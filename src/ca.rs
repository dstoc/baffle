//! Loading, validating, sharing, and exporting the daemon's certificate authority.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use time::{Duration, OffsetDateTime};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

use crate::config::CaConfig;

use rama::tls::boring::core::{pkey::PKey, pkey::Private, x509::X509};

const GENERATED_CA_VALIDITY_DAYS: i64 = 365;
const GENERATED_CA_CLOCK_SKEW_SECONDS: i64 = 5 * 60;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A validated CA owned by the daemon. Runtime use only clones native key handles.
pub struct ManagedCa {
    certificate: X509,
    private_key: PKey<Private>,
    public_certificate_pem: Arc<[u8]>,
}

impl ManagedCa {
    /// Load and validate the configured public certificate and signing key.
    pub fn load(config: &CaConfig) -> Result<Self> {
        let certificate = PublicCaCertificate::load(&config.certificate)?;
        let key_bytes = read_private_key(&config.private_key)?;
        let key_pem =
            std::str::from_utf8(&key_bytes).context("CA private key is not valid PEM text")?;
        let key_pair = KeyPair::from_pem(key_pem).context("could not parse CA private key")?;

        let (_, parsed_pem) = parse_x509_pem(&certificate.pem)
            .map_err(|_| anyhow::anyhow!("could not parse CA certificate PEM"))?;
        let (_, parsed_certificate) = parse_x509_certificate(&parsed_pem.contents)
            .map_err(|_| anyhow::anyhow!("could not parse CA certificate"))?;
        let (_, public_key_pem) = parse_x509_pem(key_pair.public_key_pem().as_bytes())
            .map_err(|_| anyhow::anyhow!("could not inspect CA public key"))?;
        if parsed_certificate.subject_pki.raw != public_key_pem.contents {
            bail!("CA certificate and private key do not match");
        }

        let certificate_pem = std::str::from_utf8(&certificate.pem)
            .context("CA certificate is not valid PEM text")?;
        let issuer = Issuer::from_ca_cert_pem(certificate_pem, key_pair)
            .context("CA certificate cannot be used as an issuer")?;

        let (runtime_certificate, runtime_private_key) = (
            X509::from_pem(&certificate.pem)
                .context("could not load CA certificate for proxy runtime")?,
            PKey::private_key_from_pem(&key_bytes)
                .context("could not load CA private key for proxy runtime")?,
        );

        // Sign a probe now so unusable issuer keys fail at daemon startup.
        CertificateParams::default()
            .signed_by(issuer.key(), &issuer)
            .context("CA private key cannot sign certificates")?;

        Ok(Self {
            certificate: runtime_certificate,
            private_key: runtime_private_key,
            public_certificate_pem: certificate.pem.into(),
        })
    }

    /// Return cloned native handles for certificate generation in the runtime.
    /// The daemon-owned CA remains the source of truth.
    pub(crate) fn runtime_signing_material(&self) -> (X509, PKey<Private>) {
        (self.certificate.clone(), self.private_key.clone())
    }

    /// Return the public certificate PEM. The private signing key is not exposed.
    pub fn public_certificate_pem(&self) -> &[u8] {
        &self.public_certificate_pem
    }
}

/// Generate and validate the configured CA pair without replacing existing files.
///
/// Both target parent directories must already exist. Temporary files are created
/// beside their targets so each final hard link is on the same filesystem.
pub fn initialize(config: &CaConfig) -> Result<()> {
    let certificate_parent = validate_target_parent(&config.certificate, "CA certificate")?;
    let private_key_parent = validate_target_parent(&config.private_key, "CA private key")?;
    let certificate_name = config
        .certificate
        .file_name()
        .context("CA certificate path must name a file")?;
    let private_key_name = config
        .private_key
        .file_name()
        .context("CA private key path must name a file")?;
    if certificate_parent.join(certificate_name) == private_key_parent.join(private_key_name) {
        bail!("CA certificate and private key must use different paths");
    }

    let mut conflicts = Vec::new();
    for (path, label) in [
        (&config.certificate, "CA certificate"),
        (&config.private_key, "CA private key"),
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => conflicts.push(format!("{label} {}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("could not inspect {label} target {}", path.display())
                });
            }
        }
    }
    if !conflicts.is_empty() {
        bail!("refusing to overwrite existing {}", conflicts.join(" and "));
    }

    let mut temporary_paths = Vec::new();
    let mut linked_targets = Vec::new();
    let result = initialize_pair(config, &mut temporary_paths, &mut linked_targets);

    match result {
        Ok(()) => {
            let temporary_cleanup = remove_paths(&temporary_paths);
            if temporary_cleanup.is_empty() {
                Ok(())
            } else {
                let rollback_errors = remove_linked_targets(&linked_targets);
                bail!(
                    "CA validation succeeded, but temporary files could not be removed: {}{}",
                    temporary_cleanup.join("; "),
                    cleanup_suffix(&rollback_errors)
                );
            }
        }
        Err(error) => {
            let rollback_errors = remove_linked_targets(&linked_targets);
            let temporary_cleanup = remove_paths(&temporary_paths);
            let cleanup_errors = rollback_errors
                .into_iter()
                .chain(temporary_cleanup)
                .collect::<Vec<_>>();
            if cleanup_errors.is_empty() {
                Err(error)
            } else {
                Err(anyhow::anyhow!(
                    "{error:#}; cleanup also failed: {}",
                    cleanup_errors.join("; ")
                ))
            }
        }
    }
}

fn initialize_pair(
    config: &CaConfig,
    temporary_paths: &mut Vec<PathBuf>,
    linked_targets: &mut Vec<LinkedTarget>,
) -> Result<()> {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("could not generate P-256 CA private key")?;
    let now = OffsetDateTime::now_utc();
    let mut parameters = CertificateParams::default();
    parameters.not_before = now - Duration::seconds(GENERATED_CA_CLOCK_SKEW_SECONDS);
    parameters.not_after = now + Duration::days(GENERATED_CA_VALIDITY_DAYS);
    parameters.distinguished_name = DistinguishedName::new();
    parameters
        .distinguished_name
        .push(DnType::CommonName, "Baffle Interception CA");
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let certificate = parameters
        .self_signed(&key_pair)
        .context("could not create self-signed Baffle CA certificate")?;
    let key_pem = key_pair.serialize_pem();
    let certificate_pem = certificate.pem();

    let temporary_key = write_temporary_file(
        &config.private_key,
        key_pem.as_bytes(),
        0o600,
        "private key",
        temporary_paths,
    )?;
    let temporary_certificate = write_temporary_file(
        &config.certificate,
        certificate_pem.as_bytes(),
        0o644,
        "certificate",
        temporary_paths,
    )?;

    let staged_config = CaConfig {
        certificate: temporary_certificate.clone(),
        private_key: temporary_key.clone(),
    };
    ManagedCa::load(&staged_config).context("generated CA pair failed Baffle validation")?;

    install_without_overwrite(
        &temporary_key,
        &config.private_key,
        "CA private key",
        linked_targets,
    )?;
    install_without_overwrite(
        &temporary_certificate,
        &config.certificate,
        "CA certificate",
        linked_targets,
    )?;
    ManagedCa::load(config).context("installed CA pair failed Baffle validation")?;
    Ok(())
}

fn validate_target_parent(path: &Path, label: &str) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::metadata(parent).with_context(|| {
        format!(
            "parent directory for {label} {} must already exist; create it first",
            path.display()
        )
    })?;
    if !metadata.is_dir() {
        bail!(
            "parent path for {label} {} is not a directory",
            path.display()
        );
    }
    fs::canonicalize(parent).with_context(|| {
        format!(
            "could not resolve parent directory for {label} {}",
            path.display()
        )
    })
}

fn write_temporary_file(
    target: &Path,
    contents: &[u8],
    mode: u32,
    label: &str,
    temporary_paths: &mut Vec<PathBuf>,
) -> Result<PathBuf> {
    let parent = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    for _ in 0..128 {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".baffle-ca-init-{}-{sequence}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        let mut file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "could not create temporary {label} beside {}",
                        target.display()
                    )
                });
            }
        };
        temporary_paths.push(temporary.clone());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(mode))
                .with_context(|| format!("could not set permissions on temporary {label}"))?;
        }
        file.write_all(contents)
            .with_context(|| format!("could not write temporary {label}"))?;
        file.sync_all()
            .with_context(|| format!("could not finish writing temporary {label}"))?;
        return Ok(temporary);
    }
    bail!(
        "could not allocate a temporary {label} beside {}",
        target.display()
    )
}

struct LinkedTarget {
    target: PathBuf,
    identity: FileIdentity,
}

fn install_without_overwrite(
    temporary: &Path,
    target: &Path,
    label: &str,
    linked_targets: &mut Vec<LinkedTarget>,
) -> Result<()> {
    let identity =
        file_identity(temporary).with_context(|| format!("could not inspect temporary {label}"))?;
    match fs::hard_link(temporary, target) {
        Ok(()) => {
            linked_targets.push(LinkedTarget {
                target: target.to_path_buf(),
                identity,
            });
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!(
                "refusing to overwrite existing {label} {}",
                target.display()
            )
        }
        Err(error) => {
            Err(error).with_context(|| format!("could not install {label} at {}", target.display()))
        }
    }
}

fn remove_paths(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|path| match fs::remove_file(path) {
            Ok(()) => None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => Some(format!("{} ({error})", path.display())),
        })
        .collect()
}

fn remove_linked_targets(linked_targets: &[LinkedTarget]) -> Vec<String> {
    linked_targets
        .iter()
        .rev()
        .filter_map(
            |linked| match file_has_identity(&linked.target, linked.identity) {
                Ok(true) => match fs::remove_file(&linked.target) {
                    Ok(()) => None,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => Some(format!("{} ({error})", linked.target.display())),
                },
                Ok(false) => None,
                Err(error) => Some(format!("{} ({error})", linked.target.display())),
            },
        )
        .collect()
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn file_identity(path: &Path) -> Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path)?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn file_has_identity(path: &Path, identity: FileIdentity) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    Ok(metadata.dev() == identity.device && metadata.ino() == identity.inode)
}

#[cfg(not(unix))]
#[derive(Clone, Copy)]
struct FileIdentity;

#[cfg(not(unix))]
fn file_identity(_path: &Path) -> Result<FileIdentity> {
    Ok(FileIdentity)
}

#[cfg(not(unix))]
fn file_has_identity(_path: &Path, _identity: FileIdentity) -> Result<bool> {
    Ok(false)
}

fn cleanup_suffix(errors: &[String]) -> String {
    if errors.is_empty() {
        String::new()
    } else {
        format!("; cleanup also failed: {}", errors.join("; "))
    }
}

/// Export the configured public CA certificate without reading the private key.
pub fn export_public_certificate(ca: &CaConfig, output: &Path) -> Result<()> {
    let certificate = PublicCaCertificate::load(&ca.certificate)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options.open(output).with_context(|| {
        format!(
            "could not create CA certificate output {}",
            output.display()
        )
    })?;
    file.write_all(&certificate.pem)
        .with_context(|| format!("could not write CA certificate output {}", output.display()))?;
    file.sync_all().with_context(|| {
        format!(
            "could not finish CA certificate output {}",
            output.display()
        )
    })?;
    Ok(())
}

struct PublicCaCertificate {
    pem: Vec<u8>,
}

impl PublicCaCertificate {
    fn load(path: &Path) -> Result<Self> {
        let metadata = fs::metadata(path).context("could not inspect CA certificate file")?;
        if !metadata.is_file() {
            bail!("CA certificate path must be a regular file");
        }
        let pem = fs::read(path).context("could not read CA certificate file")?;
        let (remainder, parsed_pem) = parse_x509_pem(&pem)
            .map_err(|_| anyhow::anyhow!("could not parse CA certificate PEM"))?;
        if parsed_pem.label != "CERTIFICATE" || !remainder.iter().all(u8::is_ascii_whitespace) {
            bail!("CA certificate file must contain one CERTIFICATE PEM block");
        }
        let (remainder, certificate) = parse_x509_certificate(&parsed_pem.contents)
            .map_err(|_| anyhow::anyhow!("could not parse CA certificate"))?;
        if !remainder.is_empty() {
            bail!("CA certificate contains trailing data");
        }

        let constraints = certificate
            .basic_constraints()
            .context("CA certificate has invalid Basic Constraints")?
            .ok_or_else(|| anyhow::anyhow!("CA certificate must have Basic Constraints"))?;
        if !constraints.value.ca {
            bail!("CA certificate is not marked as a certificate authority");
        }
        let usage = certificate
            .key_usage()
            .context("CA certificate has invalid Key Usage")?
            .ok_or_else(|| anyhow::anyhow!("CA certificate must have Key Usage"))?;
        if !usage.value.key_cert_sign() {
            bail!("CA certificate is not permitted to sign certificates");
        }
        if !certificate.validity().is_valid() {
            bail!("CA certificate is not currently valid");
        }

        Ok(Self { pem })
    }
}

fn read_private_key(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).context("could not inspect CA private key file")?;
    if !metadata.file_type().is_file() {
        bail!("CA private key path must be a regular, non-symlink file");
    }
    validate_private_key_permissions(&metadata)?;
    fs::read(path).context("could not read CA private key file")
}

#[cfg(unix)]
fn validate_private_key_permissions(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode();
    if mode & 0o7077 != 0 || mode & 0o111 != 0 || mode & 0o400 == 0 {
        bail!("CA private key permissions must allow owner read access only");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_key_permissions(_metadata: &fs::Metadata) -> Result<()> {
    bail!("CA private key permissions cannot be validated on this platform")
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    use rama::tls::boring::core::x509::X509;
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        PKCS_ECDSA_P256_SHA256,
    };
    use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

    use super::{
        ManagedCa, export_public_certificate, initialize, install_without_overwrite,
        remove_linked_targets, remove_paths, write_temporary_file,
    };
    use crate::config::CaConfig;

    fn ca_config(directory: &Path) -> CaConfig {
        CaConfig {
            certificate: directory.join("ca.pem"),
            private_key: directory.join("ca-key.pem"),
        }
    }

    fn write_ca(config: &CaConfig) {
        let key_pair = KeyPair::generate().expect("CA key should be generated");
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = parameters
            .self_signed(&key_pair)
            .expect("CA certificate should be generated");
        fs::write(&config.certificate, certificate.pem()).expect("CA certificate should be saved");
        fs::write(&config.private_key, key_pair.serialize_pem()).expect("CA key should be saved");
        set_private_key_mode(&config.private_key, 0o600);
    }

    #[cfg(unix)]
    fn set_private_key_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("CA key permissions should be set");
    }

    #[cfg(not(unix))]
    fn set_private_key_mode(_path: &Path, _mode: u32) {}

    #[test]
    fn validates_ca_material_and_keeps_public_export_separate_from_the_key() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let config = ca_config(directory.path());
        write_ca(&config);

        let ca = ManagedCa::load(&config).expect("valid CA should load");
        assert!(
            ca.public_certificate_pem()
                .starts_with(b"-----BEGIN CERTIFICATE-----")
        );
        assert!(
            !ca.public_certificate_pem()
                .windows(b"PRIVATE KEY".len())
                .any(|window| window == b"PRIVATE KEY")
        );

        let output = directory.path().join("client-ca.pem");
        export_public_certificate(&config, &output).expect("public certificate should export");
        assert_eq!(
            fs::read(output).expect("exported certificate should be readable"),
            ca.public_certificate_pem()
        );
    }

    #[test]
    fn initializes_ca_pair_that_loads_signs_and_exports() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let config = ca_config(directory.path());

        initialize(&config).expect("configured CA pair should be initialized");
        let ca = ManagedCa::load(&config).expect("generated CA should pass daemon validation");
        let certificate_pem = fs::read_to_string(&config.certificate)
            .expect("generated certificate should be readable");
        let (_, parsed_pem) = parse_x509_pem(certificate_pem.as_bytes())
            .expect("generated certificate should be PEM");
        let (_, parsed_ca) = parse_x509_certificate(&parsed_pem.contents)
            .expect("generated certificate should parse");
        let common_name = parsed_ca
            .subject()
            .iter_common_name()
            .next()
            .expect("generated CA should have a common name")
            .as_str()
            .expect("common name should be text");
        assert_eq!(common_name, "Baffle Interception CA");
        assert!(
            parsed_ca
                .basic_constraints()
                .expect("basic constraints should parse")
                .expect("CA should have basic constraints")
                .value
                .ca
        );
        let usage = parsed_ca
            .key_usage()
            .expect("key usage should parse")
            .expect("CA should have key usage");
        assert!(usage.value.key_cert_sign());
        assert!(usage.value.crl_sign());
        assert!(parsed_ca.validity().is_valid());
        let runtime_ca = X509::from_der(&parsed_pem.contents)
            .expect("generated CA should load through the runtime TLS library");
        let ca_public_key = runtime_ca
            .public_key()
            .expect("generated CA should expose a public key");
        assert!(
            runtime_ca
                .verify(&ca_public_key)
                .expect("runtime TLS library should verify the CA signature"),
            "CA certificate should be self-signed"
        );

        let validity_seconds = parsed_ca.validity().not_after.timestamp()
            - parsed_ca.validity().not_before.timestamp();
        assert!((365 * 24 * 60 * 60..=365 * 24 * 60 * 60 + 5 * 60).contains(&validity_seconds));

        let key_pem = fs::read_to_string(&config.private_key)
            .expect("generated private key should be readable");
        let key_pair = KeyPair::from_pem(&key_pem).expect("generated private key should parse");
        assert_eq!(key_pair.algorithm(), &PKCS_ECDSA_P256_SHA256);
        let issuer = Issuer::from_ca_cert_pem(&certificate_pem, key_pair)
            .expect("generated CA should create a certificate issuer");
        let leaf_key = KeyPair::generate().expect("interception key should be generated");
        let leaf = CertificateParams::new(vec!["intercept.example.test".to_owned()])
            .expect("interception certificate parameters should be valid")
            .signed_by(&leaf_key, &issuer)
            .expect("generated CA should sign an interception certificate");
        let runtime_leaf = X509::from_der(leaf.der().as_ref())
            .expect("interception certificate should load through the runtime TLS library");
        assert!(
            runtime_leaf
                .verify(&ca_public_key)
                .expect("runtime TLS library should verify the interception signature"),
            "interception certificate should verify against generated CA"
        );

        let export_path = directory.path().join("client-ca.pem");
        export_public_certificate(&config, &export_path)
            .expect("public certificate should export after CA init");
        assert_eq!(
            fs::read(export_path).expect("exported CA should be readable"),
            ca.public_certificate_pem()
        );

        assert_eq!(
            fs::metadata(&config.private_key)
                .expect("private key should have metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&config.certificate)
                .expect("certificate should have metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[test]
    fn ca_init_refuses_each_existing_target_without_changing_files() {
        for (existing_certificate, existing_key) in [(true, false), (false, true), (true, true)] {
            let directory = tempfile::tempdir().expect("temporary directory should be created");
            let config = ca_config(directory.path());
            if existing_certificate {
                fs::write(&config.certificate, b"operator certificate")
                    .expect("operator certificate should be written");
            }
            if existing_key {
                fs::write(&config.private_key, b"operator private key")
                    .expect("operator key should be written");
            }

            let error = initialize(&config).expect_err("existing targets must not be replaced");
            assert!(error.to_string().contains("refusing to overwrite"));
            assert_eq!(
                config.certificate.exists(),
                existing_certificate,
                "certificate target presence should not change"
            );
            assert_eq!(
                config.private_key.exists(),
                existing_key,
                "key target presence should not change"
            );
            if existing_certificate {
                assert_eq!(
                    fs::read(&config.certificate).expect("operator certificate should remain"),
                    b"operator certificate"
                );
            }
            if existing_key {
                assert_eq!(
                    fs::read(&config.private_key).expect("operator key should remain"),
                    b"operator private key"
                );
            }
            assert_eq!(
                fs::read_dir(directory.path())
                    .expect("CA directory should be readable")
                    .count(),
                usize::from(existing_certificate) + usize::from(existing_key),
                "failed initialization should leave no temporary files"
            );
        }
    }

    #[test]
    fn ca_init_requires_existing_parent_directories() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let missing_parent = directory.path().join("missing");
        let config = CaConfig {
            certificate: missing_parent.join("ca.pem"),
            private_key: missing_parent.join("ca-key.pem"),
        };

        let error = initialize(&config).expect_err("missing CA parent should be rejected");
        assert!(
            error
                .to_string()
                .contains("must already exist; create it first")
        );
        assert!(!missing_parent.exists());
    }

    #[test]
    fn failed_second_install_rolls_back_only_the_first_created_target() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let config = ca_config(directory.path());
        let unrelated = directory.path().join("operator-file.txt");
        fs::write(&unrelated, b"keep me").expect("unrelated file should be written");

        let mut temporary_paths = Vec::new();
        let temporary_key = write_temporary_file(
            &config.private_key,
            b"generated key",
            0o600,
            "private key",
            &mut temporary_paths,
        )
        .expect("staged key should be written");
        let temporary_certificate = write_temporary_file(
            &config.certificate,
            b"generated certificate",
            0o644,
            "certificate",
            &mut temporary_paths,
        )
        .expect("staged certificate should be written");
        fs::write(&config.certificate, b"concurrent operator file")
            .expect("concurrent certificate target should be written");

        let mut linked_targets = Vec::new();
        install_without_overwrite(
            &temporary_key,
            &config.private_key,
            "CA private key",
            &mut linked_targets,
        )
        .expect("first staged target should install");
        assert!(
            install_without_overwrite(
                &temporary_certificate,
                &config.certificate,
                "CA certificate",
                &mut linked_targets,
            )
            .is_err(),
            "concurrent target should block second install"
        );

        assert!(remove_linked_targets(&linked_targets).is_empty());
        assert!(remove_paths(&temporary_paths).is_empty());
        assert!(!config.private_key.exists());
        assert_eq!(
            fs::read(&config.certificate).expect("concurrent target should remain"),
            b"concurrent operator file"
        );
        assert_eq!(
            fs::read(&unrelated).expect("unrelated file should remain"),
            b"keep me"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_private_keys_readable_by_group_or_other_users() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let config = ca_config(directory.path());
        write_ca(&config);
        set_private_key_mode(&config.private_key, 0o640);

        assert!(ManagedCa::load(&config).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_private_key_that_does_not_match_the_certificate() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let config = ca_config(directory.path());
        write_ca(&config);
        let different_key = KeyPair::generate().expect("second key should be generated");
        fs::write(&config.private_key, different_key.serialize_pem())
            .expect("replacement key should be saved");
        set_private_key_mode(&config.private_key, 0o600);

        let error = match ManagedCa::load(&config) {
            Ok(_) => panic!("mismatched CA material must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("do not match"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_certificates_without_ca_signing_usage() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let config = ca_config(directory.path());
        let key_pair = KeyPair::generate().expect("key should be generated");
        let certificate = CertificateParams::default()
            .self_signed(&key_pair)
            .expect("non-CA certificate should be generated");
        fs::write(&config.certificate, certificate.pem()).expect("certificate should be saved");
        fs::write(&config.private_key, key_pair.serialize_pem()).expect("key should be saved");
        set_private_key_mode(&config.private_key, 0o600);

        assert!(ManagedCa::load(&config).is_err());
    }
}
