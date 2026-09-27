use std::{
    error::Error,
    fs, io,
    os::unix::fs::PermissionsExt,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use rama::crypto::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, UnixStream},
    sync::{mpsc, oneshot},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls};

use super::{ProxyRuntime, RuntimeId, set_test_upstream_trust_anchor};
use crate::{
    ca::ManagedCa,
    config::{ControlRequest, SessionConfig},
    proxy_runtime::ProxyRuntimeEvent,
    secrets::ResolvedSecrets,
};

mod support;
use support::*;

mod connect;
mod http;
mod ingress;
mod interception;
