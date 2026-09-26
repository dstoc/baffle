//! Loading, validating, sharing, and exporting the daemon's certificate authority.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use rcgen::{CertificateParams, Issuer, KeyPair};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

use crate::config::CaConfig;

use rama::tls::boring::core::{pkey::PKey, pkey::Private, x509::X509};

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
    use std::{fs, path::Path};

    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    use super::{ManagedCa, export_public_certificate};
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
