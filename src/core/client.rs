use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerName};
use tokio_rustls::TlsConnector;
use std::sync::Arc;
use url::Url;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

/// Standard HTTP client for most modules
pub struct HttpClient {
    pub inner: reqwest::Client,
}

impl HttpClient {
    pub fn new() -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("recon-1337"),
        );

        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10));

        // Use global proxy if configured
        if let Ok(config) = crate::core::GLOBAL_CONFIG.lock() {
            if let Some(proxy_url) = &config.proxy_url {
                if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
                    builder = builder.proxy(proxy);
                }
            }
        }

        let client = builder.build()?;
        Ok(Self { inner: client })
    }

    #[allow(dead_code)]
    pub fn from_raw(raw: &crate::core::parser::RawRequest) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("recon-1337"),
        );
        
        for (k, v) in &raw.headers {
            if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_bytes(v.as_bytes())) {
                if name != reqwest::header::HOST {
                    headers.insert(name, val);
                }
            }
        }

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self { inner: client })
    }

    #[allow(dead_code)]
    pub fn following_redirects() -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("recon-1337"),
        );

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self { inner: client })
    }
}

/// Raw TCP/TLS client for protocol-level attacks (smuggling, desync, etc.)
pub struct RawClient;

impl RawClient {
    pub async fn send_raw(target_url: &str, raw_payload: &[u8]) -> anyhow::Result<String> {
        let url = Url::parse(target_url)?;
        let host = url.host_str().ok_or_else(|| anyhow::anyhow!("No host in URL"))?;
        let port = url.port_or_known_default().unwrap_or(80);
        let addr = format!("{}:{}", host, port);

        if url.scheme() == "https" {
            let mut root_store = RootCertStore::empty();
            root_store.add_trust_anchors(
                webpki_roots::TLS_SERVER_ROOTS
                    .iter()
                    .map(|ta| {
                        tokio_rustls::rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    })
            );
            let config = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));
            let stream = TcpStream::connect(&addr).await?;
            let domain = ServerName::try_from(host)?;
            let mut tls_stream = connector.connect(domain, stream).await?;

            tls_stream.write_all(raw_payload).await?;
            let mut response = Vec::new();
            // Wrap in timeout to avoid hanging on keep-alive connections
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                tls_stream.read_to_end(&mut response)
            ).await;
            
            Ok(String::from_utf8_lossy(&response).to_string())
        } else {
            let mut stream = TcpStream::connect(&addr).await?;
            stream.write_all(raw_payload).await?;
            let mut response = Vec::new();
            // Wrap in timeout to avoid hanging on keep-alive connections
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                stream.read_to_end(&mut response)
            ).await;
            
            Ok(String::from_utf8_lossy(&response).to_string())
        }
    }
}
