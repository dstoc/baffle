//! Decrypted HTTP request policy and managed credential injection.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rama::{Layer, Service};

use crate::{
    config::{HeaderInjection, InjectionFormat},
    policy::{AuthorizationError, RequestFacts, SessionPolicy},
    secrets::{ResolvedSecrets, SecretValue},
    telemetry::Metrics,
};

#[derive(Clone)]
pub(super) struct RamaPolicyLayer {
    pub(super) policy: Arc<SessionPolicy>,
    pub(super) connect_authority: String,
    pub(super) secrets: Arc<ResolvedSecrets>,
    pub(super) metrics: Arc<Metrics>,
}

impl<S> Layer<S> for RamaPolicyLayer {
    type Service = RamaPolicyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RamaPolicyService {
            inner: Arc::new(inner),
            policy: Arc::clone(&self.policy),
            connect_authority: self.connect_authority.clone(),
            secrets: Arc::clone(&self.secrets),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

pub(super) struct RamaPolicyService<S> {
    inner: Arc<S>,
    policy: Arc<SessionPolicy>,
    connect_authority: String,
    secrets: Arc<ResolvedSecrets>,
    metrics: Arc<Metrics>,
}

impl<S> Clone for RamaPolicyService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            policy: Arc::clone(&self.policy),
            connect_authority: self.connect_authority.clone(),
            secrets: Arc::clone(&self.secrets),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

impl<S> Service<rama::http::Request> for RamaPolicyService<S>
where
    S: Service<rama::http::Request, Output = rama::http::Response> + Send + Sync + 'static,
    S::Error: Into<rama::error::BoxError>,
{
    type Output = rama::http::Response;
    type Error = rama::error::BoxError;

    async fn serve(&self, mut request: rama::http::Request) -> Result<Self::Output, Self::Error> {
        let uri_authority = request.uri().authority().map(|value| value.to_string());
        let mut host_headers = Vec::new();
        for value in request.headers().get_all(rama::http::header::HOST).iter() {
            match value.to_str() {
                Ok(value) => host_headers.push(value.to_owned()),
                Err(_) => return Ok(denied_response(AuthorizationError::InvalidAuthority)),
            }
        }
        let host_headers = host_headers.iter().map(String::as_str).collect::<Vec<_>>();
        let scheme = request.uri().scheme().map(ToString::to_string);
        let path = request
            .uri()
            .path()
            .map(|path| path.to_string())
            .unwrap_or_else(|| "/".to_owned());
        let facts = RequestFacts {
            method: request.method().as_str(),
            scheme: scheme.as_deref(),
            uri_authority: uri_authority.as_deref(),
            path: &path,
            host_headers: &host_headers,
            secure_transport: true,
        };
        let (injections, canonical_path) = match self
            .policy
            .authorize_intercepted_request(&facts, &self.connect_authority)
        {
            Ok(authorized) => authorized,
            Err(error) => {
                self.metrics.denied_request();
                return Ok(denied_response(error));
            }
        };
        if let Some(path) = canonical_path {
            let mut uri = request.uri().clone();
            uri.set_path(path);
            *request.uri_mut() = uri;
        }
        if !injections.is_empty() && request_has_unsupported_upgrade(&request) {
            self.metrics.denied_request();
            return Ok(denied_response(AuthorizationError::Denied));
        }
        if apply_header_injections(&mut request, injections, &self.secrets).is_err() {
            self.metrics.denied_request();
            return Ok(denied_response(AuthorizationError::Denied));
        }
        self.inner.serve(request).await.map_err(Into::into)
    }
}

fn denied_response(error: AuthorizationError) -> rama::http::Response {
    let status = match error {
        AuthorizationError::InvalidAuthority => rama::http::StatusCode::BAD_REQUEST,
        AuthorizationError::Denied => rama::http::StatusCode::FORBIDDEN,
    };
    rama::http::Response::builder()
        .status(status)
        .body(rama::http::Body::empty())
        .expect("static proxy denial response is valid")
}

fn request_has_unsupported_upgrade(request: &rama::http::Request) -> bool {
    use rama::http::header::{CONNECTION, UPGRADE};
    if request.headers().contains_key(UPGRADE) {
        return true;
    }
    request
        .headers()
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

fn apply_header_injections(
    request: &mut rama::http::Request,
    injections: &[HeaderInjection],
    secrets: &ResolvedSecrets,
) -> Result<(), ()> {
    let values = injections
        .iter()
        .map(|injection| {
            let name =
                rama::http::HeaderName::try_from(injection.header.as_str()).map_err(|_| ())?;
            let secret = secrets.get(injection.secret.as_str()).ok_or(())?;
            let value = format_injected_secret(injection, secret)?;
            let value = rama::http::HeaderValue::try_from(value).map_err(|_| ())?;
            Ok((name, value))
        })
        .collect::<Result<Vec<_>, ()>>()?;
    for (name, value) in values {
        request.headers_mut().remove(&name);
        request.headers_mut().insert(name, value);
    }
    Ok(())
}

fn format_injected_secret(injection: &HeaderInjection, secret: &SecretValue) -> Result<String, ()> {
    Ok(match injection.format {
        InjectionFormat::Raw => secret.as_str().to_owned(),
        InjectionFormat::Bearer => format!("Bearer {}", secret.as_str()),
        InjectionFormat::BasicPassword => {
            let username = injection.username.as_deref().ok_or(())?;
            format!(
                "Basic {}",
                STANDARD.encode(format!("{username}:{}", secret.as_str()))
            )
        }
    })
}
