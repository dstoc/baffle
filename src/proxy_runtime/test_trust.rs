//! Test-only upstream trust configuration shared by unit, benchmark, and
//! integration-test runtimes.

#[cfg(any(test, baffle_integration_test))]
use std::sync::Arc;

#[derive(Clone, Default)]
pub(crate) struct TestUpstreamTrust {
    #[cfg(any(test, baffle_integration_test))]
    anchor_der: Option<Arc<[u8]>>,
}

impl TestUpstreamTrust {
    /// Load the integration-test override once when the daemon starts.
    pub(crate) fn from_environment() -> Result<Self, String> {
        #[cfg(baffle_integration_test)]
        {
            let Some(path) = std::env::var_os("BAFFLE_TEST_UPSTREAM_CA") else {
                return Ok(Self::default());
            };
            let pem = std::fs::read(path)
                .map_err(|error| format!("could not read integration upstream CA: {error}"))?;
            let (remainder, certificate) = x509_parser::pem::parse_x509_pem(&pem)
                .map_err(|_| "could not parse integration upstream CA PEM".to_owned())?;
            if certificate.label != "CERTIFICATE" || !remainder.iter().all(u8::is_ascii_whitespace)
            {
                return Err("integration upstream CA must contain one certificate".to_owned());
            }
            return Ok(Self::from_der(certificate.contents));
        }

        #[cfg(not(baffle_integration_test))]
        Ok(Self::default())
    }

    #[cfg(any(test, baffle_integration_test))]
    pub(crate) fn from_der(anchor_der: Vec<u8>) -> Self {
        Self {
            anchor_der: Some(Arc::from(anchor_der)),
        }
    }

    pub(crate) fn certificate(&self) -> Option<rama::crypto::pki_types::CertificateDer<'static>> {
        #[cfg(any(test, baffle_integration_test))]
        {
            return self
                .anchor_der
                .as_ref()
                .map(|anchor| rama::crypto::pki_types::CertificateDer::from(anchor.to_vec()));
        }

        #[cfg(not(any(test, baffle_integration_test)))]
        None
    }
}
