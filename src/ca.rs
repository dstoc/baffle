//! Loading, validating, sharing, and exporting the daemon's certificate authority.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
#[cfg(feature = "backend-hudsucker")]
use hudsucker::{
    certificate_authority::{CertificateAuthority, RcgenAuthority},
    hyper::http::uri::Authority,
    rustls::{ServerConfig, crypto::aws_lc_rs},
};
use rcgen::{CertificateParams, Issuer, KeyPair};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

use crate::config::CaConfig;

#[cfg(feature = "backend-hudsucker")]
const CERTIFICATE_CACHE_CAPACITY: u64 = 4096;

/// A CA whose signing key is held by Hudsucker and never returned to a session.
pub struct ManagedCa {
    #[cfg(feature = "backend-hudsucker")]
    authority: Arc<RcgenAuthority>,
    public_certificate_pem: Arc<[u8]>,
}

/// A cloneable Hudsucker CA handle with shared signing state and certificate cache.
#[derive(Clone)]
#[cfg(feature = "backend-hudsucker")]
pub struct SharedCaAuthority(Arc<RcgenAuthority>);

#[cfg(feature = "backend-hudsucker")]
impl CertificateAuthority for SharedCaAuthority {
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig> {
        self.0.gen_server_config(authority).await
    }
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

        // Hudsucker generates leaves lazily. Sign a probe now so unsupported or
        // unusable signing keys fail daemon startup instead of the first request.
        CertificateParams::default()
            .signed_by(issuer.key(), &issuer)
            .context("CA private key cannot sign certificates")?;

        #[cfg(feature = "backend-hudsucker")]
        let authority = RcgenAuthority::new(
            issuer,
            CERTIFICATE_CACHE_CAPACITY,
            aws_lc_rs::default_provider(),
        );

        Ok(Self {
            #[cfg(feature = "backend-hudsucker")]
            authority: Arc::new(authority),
            public_certificate_pem: certificate.pem.into(),
        })
    }

    /// Return a Hudsucker CA handle for a proxy builder.
    #[cfg(feature = "backend-hudsucker")]
    pub fn for_proxy(&self) -> SharedCaAuthority {
        SharedCaAuthority(Arc::clone(&self.authority))
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

#[cfg(all(test, feature = "backend-hudsucker"))]
mod tests {
    use std::{fs, path::Path, sync::Arc};

    use hudsucker::{
        Proxy,
        certificate_authority::CertificateAuthority,
        hyper::http::uri::Authority,
        rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose},
        rustls::{
            ClientConfig, RootCertStore, ServerConfig,
            crypto::aws_lc_rs,
            pki_types::{CertificateDer, ServerName},
        },
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::{ManagedCa, export_public_certificate, parse_x509_pem};
    use crate::config::CaConfig;

    fn ca_config(directory: &Path) -> CaConfig {
        CaConfig {
            certificate: directory.join("ca.pem"),
            private_key: directory.join("ca-key.pem"),
        }
    }

    fn write_ca(config: &CaConfig) -> KeyPair {
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
        key_pair
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

    #[cfg(unix)]
    #[tokio::test]
    async fn proxy_handles_use_one_shared_hudsucker_certificate_cache() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let config = ca_config(directory.path());
        write_ca(&config);
        let ca = ManagedCa::load(&config).expect("valid CA should load");

        let first = ca.for_proxy();
        let second = ca.for_proxy();
        let host = Authority::from_static("shared.example");
        let first_config = first.gen_server_config(&host).await;
        let second_config = second.gen_server_config(&host).await;

        assert!(Arc::ptr_eq(&first_config, &second_config));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn separate_hudsucker_proxies_build_with_shared_ca_and_standard_rustls_connector() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let config = ca_config(directory.path());
        write_ca(&config);
        let ca = ManagedCa::load(&config).expect("valid CA should load");

        let first_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("first listener should bind");
        let second_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("second listener should bind");
        let first_proxy = Proxy::builder()
            .with_listener(first_listener)
            .with_ca(ca.for_proxy())
            .with_rustls_connector(aws_lc_rs::default_provider())
            .build()
            .expect("first proxy should use the shared CA");
        let second_proxy = Proxy::builder()
            .with_listener(second_listener)
            .with_ca(ca.for_proxy())
            .with_rustls_connector(aws_lc_rs::default_provider())
            .build()
            .expect("second proxy should use the shared CA");

        drop((first_proxy, second_proxy));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_proxy_handles_support_trusted_clients_and_reject_untrusted_names() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let config = ca_config(directory.path());
        write_ca(&config);
        let ca = ManagedCa::load(&config).expect("valid CA should load");

        let first = ca.for_proxy();
        let second = ca.for_proxy();
        let first_host = Authority::from_static("first.example");
        let second_host = Authority::from_static("second.example");
        let (first_server, second_server) = tokio::join!(
            first.gen_server_config(&first_host),
            second.gen_server_config(&second_host),
        );
        let trusted_client = client_config(Some(ca.public_certificate_pem()));

        let (first_handshake, second_handshake) = tokio::join!(
            tls_handshake(
                first_server.clone(),
                trusted_client.clone(),
                "first.example"
            ),
            tls_handshake(
                second_server.clone(),
                trusted_client.clone(),
                "second.example"
            ),
        );
        assert!(first_handshake.is_ok());
        assert!(second_handshake.is_ok());

        let untrusted_client = client_config(None);
        assert!(
            tls_handshake(first_server, untrusted_client, "first.example")
                .await
                .is_err()
        );
        assert!(
            tls_handshake(second_server, trusted_client, "wrong.example")
                .await
                .is_err()
        );
    }

    fn client_config(certificate_pem: Option<&[u8]>) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        if let Some(certificate_pem) = certificate_pem {
            let (_, certificate) =
                parse_x509_pem(certificate_pem).expect("CA public certificate should be valid PEM");
            roots
                .add(CertificateDer::from(certificate.contents))
                .expect("CA public certificate should be a valid trust anchor");
        }

        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("supported TLS protocol versions should be available")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    async fn tls_handshake(
        server_config: Arc<ServerConfig>,
        client_config: Arc<ClientConfig>,
        server_name: &str,
    ) -> std::io::Result<()> {
        let server_name =
            ServerName::try_from(server_name.to_owned()).expect("test server name should be valid");
        let (server_stream, client_stream) = tokio::io::duplex(4096);
        let server = TlsAcceptor::from(server_config).accept(server_stream);
        let client = TlsConnector::from(client_config).connect(server_name, client_stream);
        let (server, client) = tokio::join!(server, client);
        server?;
        client?;
        Ok(())
    }
}
