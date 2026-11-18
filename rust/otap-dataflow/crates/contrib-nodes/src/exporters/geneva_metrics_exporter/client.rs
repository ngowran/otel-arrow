// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use futures::future::LocalBoxFuture;
use otel_arrow_dfe_telemetry::otel_debug;
use reqwest::header::{AUTHORIZATION, HeaderName, HeaderValue};
use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;
use std::time::{Duration, Instant};
use thiserror::Error;

const CONTENT_TYPE: &str = "application/x-mepacket";
const ORIGINAL_CONTENT_SIZE_HEADER: &str = "OriginalContentSize";
const GIG_CONTEXT_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug)]
pub(crate) struct MetricsPublisher {
    client: Client,
    endpoint: Url,
    timeout: Duration,
    gig: Option<Rc<ManagedIdentityGigMode>>,
    #[cfg(test)]
    scripted: Option<ScriptedRequests>,
}

#[derive(Debug)]
struct ManagedIdentityGigMode {
    home_stamp: Url,
    stamp_id: String,
    monitoring_account: String,
    cached_context: RefCell<Option<GigPublicationContext>>,
}

#[derive(Clone, Debug)]
struct GigPublicationContext {
    source_auth_generation: u64,
    publication_endpoint: Url,
    auth_header_value: HeaderValue,
    refresh_at: Instant,
}

#[derive(Debug, Deserialize)]
struct GigTokenExchangeResponse {
    #[serde(rename = "gigEndpoint")]
    gig_endpoint: String,
    #[serde(rename = "gigAuthToken")]
    gig_auth_token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestStage {
    DirectPublication,
    GigTokenExchange,
    GigPublication,
}

impl fmt::Display for RequestStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DirectPublication => "publication",
            Self::GigTokenExchange => "GIG token exchange",
            Self::GigPublication => "GIG publication",
        })
    }
}

#[derive(Debug, Error)]
pub(crate) enum PublisherBuildError {
    #[error("invalid Geneva metrics endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("Geneva metrics home stamp endpoint does not contain a stamp hostname")]
    MissingStampId,
    #[error("failed to create the Geneva metrics HTTP client: {0}")]
    Client(#[source] Box<reqwest::Error>),
}

#[derive(Debug, Error)]
#[allow(variant_size_differences)]
pub(crate) enum PublishError {
    #[error("input publication deadline exhausted")]
    DeadlineExceeded,
    #[error("Geneva metrics {stage} request failed: {source}")]
    Request {
        stage: RequestStage,
        #[source]
        source: Box<reqwest::Error>,
    },
    #[error("Geneva metrics {stage} returned HTTP {status}")]
    Response {
        stage: RequestStage,
        status: StatusCode,
    },
    #[error("Geneva GIG token exchange returned invalid JSON")]
    InvalidExchangeResponse(#[source] Box<reqwest::Error>),
    #[error("Geneva GIG token exchange did not return {field}")]
    MissingExchangeField { field: &'static str },
    #[error("Geneva GIG endpoint is invalid: {0}")]
    InvalidGigEndpoint(String),
    #[error("Geneva GIG token cannot be used as an authorization header")]
    InvalidGigToken,
}

impl PublishError {
    pub(crate) fn is_unauthorized(&self) -> bool {
        // A 403 can indicate permissions; invalidation cannot force an early token refresh.
        matches!(
            self,
            Self::Response {
                stage: RequestStage::DirectPublication | RequestStage::GigTokenExchange,
                status: StatusCode::UNAUTHORIZED
            }
        )
    }

    pub(crate) fn is_retryable(&self) -> bool {
        match self {
            Self::DeadlineExceeded
            | Self::Request { .. }
            | Self::InvalidExchangeResponse(_)
            | Self::MissingExchangeField { .. }
            | Self::InvalidGigEndpoint(_)
            | Self::InvalidGigToken => true,
            Self::Response { status, .. } => {
                matches!(
                    *status,
                    StatusCode::UNAUTHORIZED
                        | StatusCode::FORBIDDEN
                        | StatusCode::REQUEST_TIMEOUT
                        | StatusCode::TOO_MANY_REQUESTS
                ) || status.is_server_error()
            }
        }
    }

    pub(crate) fn is_refusal(&self) -> bool {
        matches!(self, Self::Response { status, .. } if status.is_client_error() && *status != StatusCode::REQUEST_TIMEOUT)
    }

    fn is_gig_publication_unauthorized(&self) -> bool {
        matches!(
            self,
            Self::Response {
                stage: RequestStage::GigPublication,
                status: StatusCode::UNAUTHORIZED,
            }
        )
    }
}

impl MetricsPublisher {
    pub(crate) fn new(
        endpoint: &str,
        monitoring_account: &str,
        timeout: Duration,
    ) -> Result<Self, PublisherBuildError> {
        otel_arrow_dfe_otap::crypto::ensure_crypto_provider();
        let endpoint = endpoint.trim().replace(
            "{monitoring_account}",
            &urlencoding::encode(monitoring_account),
        );
        let endpoint = Url::parse(&endpoint)
            .map_err(|error| PublisherBuildError::InvalidEndpoint(error.to_string()))?;
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| PublisherBuildError::Client(Box::new(error)))?;
        Ok(Self {
            client,
            endpoint,
            timeout,
            gig: None,
            #[cfg(test)]
            scripted: None,
        })
    }

    pub(crate) fn new_managed_identity(
        home_stamp: &str,
        monitoring_account: &str,
        timeout: Duration,
    ) -> Result<Self, PublisherBuildError> {
        let mut publisher = Self::new(home_stamp, monitoring_account, timeout)?;
        let stamp_id = publisher
            .endpoint
            .host_str()
            .and_then(|host| host.split('.').next())
            .filter(|stamp_id| !stamp_id.is_empty())
            .ok_or(PublisherBuildError::MissingStampId)?
            .to_owned();
        publisher.gig = Some(Rc::new(ManagedIdentityGigMode {
            home_stamp: publisher.endpoint.clone(),
            stamp_id,
            monitoring_account: monitoring_account.to_owned(),
            cached_context: RefCell::new(None),
        }));
        Ok(publisher)
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(crate) fn publish_with_auth_generation(
        &self,
        packet: Vec<u8>,
        auth_header_name: HeaderName,
        auth_header_value: HeaderValue,
        auth_generation: u64,
    ) -> LocalBoxFuture<'static, Result<(), PublishError>> {
        let Some(gig) = self.gig.clone() else {
            return self.publish(packet, auth_header_name, auth_header_value);
        };
        let client = self.client.clone();
        Box::pin(async move {
            gig.publish(
                &client,
                Bytes::from(packet),
                auth_header_name,
                auth_header_value,
                auth_generation,
            )
            .await
        })
    }

    pub(crate) fn publish(
        &self,
        packet: Vec<u8>,
        auth_header_name: HeaderName,
        auth_header_value: HeaderValue,
    ) -> LocalBoxFuture<'static, Result<(), PublishError>> {
        #[cfg(test)]
        if let Some(scripted) = &self.scripted {
            return (scripted.0)();
        }
        let original_size = packet.len();
        let request = self
            .client
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE)
            .header(ORIGINAL_CONTENT_SIZE_HEADER, original_size)
            .header(auth_header_name, auth_header_value)
            .body(packet);
        Box::pin(async move {
            let response = request
                .send()
                .await
                .map_err(|error| PublishError::Request {
                    stage: RequestStage::DirectPublication,
                    source: Box::new(error),
                })?;

            if response.status() == StatusCode::OK {
                Ok(())
            } else {
                Err(PublishError::Response {
                    stage: RequestStage::DirectPublication,
                    status: response.status(),
                })
            }
        })
    }
}

impl ManagedIdentityGigMode {
    async fn context(
        &self,
        client: &Client,
        auth_header_name: &HeaderName,
        auth_header_value: &HeaderValue,
        auth_generation: u64,
    ) -> Result<GigPublicationContext, PublishError> {
        let cached = self
            .cached_context
            .borrow()
            .as_ref()
            .filter(|context| {
                context.source_auth_generation == auth_generation
                    && Instant::now() < context.refresh_at
            })
            .cloned();
        if let Some(context) = cached {
            return Ok(context);
        }
        let context = exchange_gig_context(
            client,
            &self.home_stamp,
            &self.stamp_id,
            &self.monitoring_account,
            auth_header_name,
            auth_header_value,
            auth_generation,
        )
        .await?;
        *self.cached_context.borrow_mut() = Some(context.clone());
        Ok(context)
    }

    async fn publish(
        &self,
        client: &Client,
        packet: Bytes,
        auth_header_name: HeaderName,
        auth_header_value: HeaderValue,
        auth_generation: u64,
    ) -> Result<(), PublishError> {
        let context = self
            .context(
                client,
                &auth_header_name,
                &auth_header_value,
                auth_generation,
            )
            .await?;
        let result = send_gig_packet(client, &context, packet.clone()).await;
        if !result
            .as_ref()
            .is_err_and(PublishError::is_gig_publication_unauthorized)
        {
            return result;
        }
        *self.cached_context.borrow_mut() = None;
        let refreshed = self
            .context(
                client,
                &auth_header_name,
                &auth_header_value,
                auth_generation,
            )
            .await?;
        let retry = send_gig_packet(client, &refreshed, packet).await;
        if retry
            .as_ref()
            .is_err_and(PublishError::is_gig_publication_unauthorized)
        {
            *self.cached_context.borrow_mut() = None;
        }
        retry
    }
}

async fn exchange_gig_context(
    client: &Client,
    home_stamp: &Url,
    stamp_id: &str,
    monitoring_account: &str,
    auth_header_name: &HeaderName,
    auth_header_value: &HeaderValue,
    auth_generation: u64,
) -> Result<GigPublicationContext, PublishError> {
    let mut exchange_endpoint = home_stamp.clone();
    exchange_endpoint.set_query(None);
    exchange_endpoint.set_fragment(None);
    let _ = exchange_endpoint
        .path_segments_mut()
        .map_err(|_| PublishError::InvalidGigEndpoint(home_stamp.to_string()))?
        .clear()
        .extend([
            "user-api",
            "v2",
            "authorization",
            "gig",
            "monitoringAccount",
            monitoring_account,
        ]);
    let response = client
        .get(exchange_endpoint)
        .header(auth_header_name.clone(), auth_header_value.clone())
        .send()
        .await
        .map_err(|source| PublishError::Request {
            stage: RequestStage::GigTokenExchange,
            source: Box::new(source),
        })?;
    if response.status() != StatusCode::OK {
        return Err(PublishError::Response {
            stage: RequestStage::GigTokenExchange,
            status: response.status(),
        });
    }
    let exchange: GigTokenExchangeResponse = response
        .json()
        .await
        .map_err(|source| PublishError::InvalidExchangeResponse(Box::new(source)))?;
    let gig_endpoint = exchange.gig_endpoint.trim();
    if gig_endpoint.is_empty() {
        return Err(PublishError::MissingExchangeField {
            field: "gigEndpoint",
        });
    }
    let gig_auth_token = exchange.gig_auth_token.trim();
    if gig_auth_token.is_empty() {
        return Err(PublishError::MissingExchangeField {
            field: "gigAuthToken",
        });
    }
    let publication_endpoint =
        build_gig_publication_endpoint(home_stamp, gig_endpoint, monitoring_account, stamp_id)?;
    let mut publication_auth = HeaderValue::from_str(&format!("Bearer {gig_auth_token}"))
        .map_err(|_| PublishError::InvalidGigToken)?;
    publication_auth.set_sensitive(true);
    otel_debug!(
        "geneva_metrics_exporter.gig_exchange.success",
        monitoring_account = %monitoring_account,
        stamp_id = %stamp_id,
        publication_host = publication_endpoint.host_str().unwrap_or(""),
    );
    Ok(GigPublicationContext {
        source_auth_generation: auth_generation,
        publication_endpoint,
        auth_header_value: publication_auth,
        refresh_at: Instant::now() + GIG_CONTEXT_TTL,
    })
}

fn build_gig_publication_endpoint(
    home_stamp: &Url,
    gig_endpoint: &str,
    monitoring_account: &str,
    stamp_id: &str,
) -> Result<Url, PublishError> {
    let mut endpoint = if gig_endpoint.contains("://") {
        Url::parse(gig_endpoint)
    } else {
        Url::parse(&format!("{}://{gig_endpoint}", home_stamp.scheme()))
    }
    .map_err(|error| PublishError::InvalidGigEndpoint(error.to_string()))?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || (home_stamp.scheme() == "https" && endpoint.scheme() != "https")
        || endpoint.host_str().is_none()
    {
        return Err(PublishError::InvalidGigEndpoint(endpoint.to_string()));
    }
    endpoint.set_path("/api/v1/ingestion/ingest");
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    let _ = endpoint
        .query_pairs_mut()
        .append_pair("accountId", monitoring_account)
        .append_pair("stampId", stamp_id);
    Ok(endpoint)
}

async fn send_gig_packet(
    client: &Client,
    context: &GigPublicationContext,
    packet: Bytes,
) -> Result<(), PublishError> {
    let original_size = packet.len();
    let response = client
        .post(context.publication_endpoint.clone())
        .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE)
        .header(ORIGINAL_CONTENT_SIZE_HEADER, original_size)
        .header(AUTHORIZATION, context.auth_header_value.clone())
        .body(packet)
        .send()
        .await
        .map_err(|source| PublishError::Request {
            stage: RequestStage::GigPublication,
            source: Box::new(source),
        })?;
    if response.status() == StatusCode::OK {
        Ok(())
    } else {
        Err(PublishError::Response {
            stage: RequestStage::GigPublication,
            status: response.status(),
        })
    }
}

/// Test-only request source that replaces HTTP, letting export-loop tests
/// control when publications resolve without real I/O or wall-clock timeouts.
#[cfg(test)]
struct ScriptedRequests(Box<dyn Fn() -> LocalBoxFuture<'static, Result<(), PublishError>>>);

#[cfg(test)]
impl fmt::Debug for ScriptedRequests {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScriptedRequests")
    }
}

#[cfg(test)]
impl MetricsPublisher {
    /// Creates a publisher whose requests are produced by `request` instead of HTTP.
    pub(crate) fn scripted(
        timeout: Duration,
        request: impl Fn() -> LocalBoxFuture<'static, Result<(), PublishError>> + 'static,
    ) -> Self {
        let mut publisher = Self::new("http://127.0.0.1:1", "example-account", timeout)
            .expect("static test endpoint should be valid");
        publisher.scripted = Some(ScriptedRequests(Box::new(request)));
        publisher
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{body_bytes, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn gig_response(server: &MockServer, token: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "gigEndpoint": server.uri().trim_start_matches("http://"),
            "gigAuthToken": token,
        }))
    }

    async fn publish_managed_identity(
        publisher: &MetricsPublisher,
        generation: u64,
    ) -> Result<(), PublishError> {
        publisher
            .publish_with_auth_generation(
                vec![6, 0],
                AUTHORIZATION,
                HeaderValue::from_static("Bearer mi-token"),
                generation,
            )
            .await
    }

    /// Scenario: Two packets use the same managed identity credential and monitoring account.
    /// Guarantees: The GIG exchange is cached and its token, route, headers, and packet bytes are used for both publications.
    #[tokio::test]
    async fn exchanges_managed_identity_token_for_cached_gig_publication() {
        let gig = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ingestion/ingest"))
            .and(query_param("accountId", "example-account"))
            .and(query_param("stampId", "127"))
            .and(header("authorization", "Bearer gig-token"))
            .and(header("content-type", CONTENT_TYPE))
            .and(header(ORIGINAL_CONTENT_SIZE_HEADER, "2"))
            .and(body_bytes(vec![6, 0]))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&gig)
            .await;
        let home = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/user-api/v2/authorization/gig/monitoringAccount/example-account",
            ))
            .and(header("authorization", "Bearer mi-token"))
            .respond_with(gig_response(&gig, "gig-token"))
            .expect(1)
            .mount(&home)
            .await;
        let publisher = MetricsPublisher::new_managed_identity(
            &home.uri(),
            "example-account",
            Duration::from_secs(10),
        )
        .expect("valid home stamp");
        for _ in 0..2 {
            publish_managed_identity(&publisher, 1)
                .await
                .expect("GIG publication should succeed");
        }
    }

    /// Scenario: The managed identity credential generation changes between publications.
    /// Guarantees: A cached GIG credential is exchanged again before the second publication.
    #[tokio::test]
    async fn refreshes_gig_context_after_managed_identity_rotation() {
        let gig = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("authorization", "Bearer gig-token"))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&gig)
            .await;
        let home = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(gig_response(&gig, "gig-token"))
            .expect(2)
            .mount(&home)
            .await;
        let publisher = MetricsPublisher::new_managed_identity(
            &home.uri(),
            "example-account",
            Duration::from_secs(10),
        )
        .expect("valid home stamp");
        for generation in [1, 2] {
            publish_managed_identity(&publisher, generation)
                .await
                .expect("GIG publication should succeed");
        }
    }

    /// Scenario: GIG rejects a publication once, or rejects both the cached and refreshed token.
    /// Guarantees: One refresh is attempted; a second 401 clears the cache without invalidating the managed identity credential.
    #[tokio::test]
    async fn refreshes_gig_context_after_publication_unauthorized() {
        for always_unauthorized in [false, true] {
            let gig = MockServer::start().await;
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            Mock::given(method("POST"))
                .respond_with(move |_: &wiremock::Request| {
                    let call = observed.fetch_add(1, Ordering::SeqCst);
                    ResponseTemplate::new(if always_unauthorized || call == 0 {
                        401
                    } else {
                        200
                    })
                })
                .expect(if always_unauthorized { 4 } else { 2 })
                .mount(&gig)
                .await;
            let home = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(gig_response(&gig, "gig-token"))
                .expect(if always_unauthorized { 4 } else { 2 })
                .mount(&home)
                .await;
            let publisher = MetricsPublisher::new_managed_identity(
                &home.uri(),
                "example-account",
                Duration::from_secs(10),
            )
            .expect("valid home stamp");
            let result = publish_managed_identity(&publisher, 1).await;
            if always_unauthorized {
                for error in [
                    result.expect_err("rejected refresh should fail"),
                    publish_managed_identity(&publisher, 1)
                        .await
                        .expect_err("a later input must exchange again"),
                ] {
                    assert!(!error.is_unauthorized());
                    assert!(error.is_retryable());
                }
            } else {
                result.expect("publication should succeed after refreshing");
            }
        }
    }

    /// Scenario: Two exporter instances target different accounts using the same managed identity generation.
    /// Guarantees: Each instance exchanges and publishes with its own account's GIG credential.
    #[tokio::test]
    async fn separates_gig_contexts_by_monitoring_account() {
        let gig = MockServer::start().await;
        let home = MockServer::start().await;
        for (account, token) in [("account-a", "gig-token-a"), ("account-b", "gig-token-b")] {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/user-api/v2/authorization/gig/monitoringAccount/{account}"
                )))
                .respond_with(gig_response(&gig, token))
                .expect(1)
                .mount(&home)
                .await;
            Mock::given(method("POST"))
                .and(query_param("accountId", account))
                .and(header("authorization", format!("Bearer {token}")))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&gig)
                .await;
            let publisher = MetricsPublisher::new_managed_identity(
                &home.uri(),
                account,
                Duration::from_secs(10),
            )
            .expect("valid home stamp");
            publish_managed_identity(&publisher, 1)
                .await
                .expect("account-specific GIG publication should succeed");
        }
    }

    /// Scenario: The GIG exchange returns HTTP 401 or 403 before publication.
    /// Guarantees: Only 401 invalidates source auth; both statuses retain the current runtime's retryable refusal classification.
    #[tokio::test]
    async fn classifies_gig_exchange_authorization_failures() {
        for status in [401, 403] {
            let home = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(status))
                .expect(1)
                .mount(&home)
                .await;
            let publisher = MetricsPublisher::new_managed_identity(
                &home.uri(),
                "example-account",
                Duration::from_secs(10),
            )
            .expect("valid home stamp");
            let error = publish_managed_identity(&publisher, 1)
                .await
                .expect_err("exchange should fail");
            assert_eq!(error.is_unauthorized(), status == 401);
            assert!(error.is_retryable());
            assert!(error.is_refusal());
        }
    }

    async fn publish(endpoint: &str, account: &str, packet: Vec<u8>) -> Result<(), PublishError> {
        MetricsPublisher::new(endpoint, account, Duration::from_secs(10))
            .expect("valid endpoint")
            .publish(
                packet,
                AUTHORIZATION,
                HeaderValue::from_static("test-authorization"),
            )
            .await
    }

    /// Scenario: One publisher sends two protocol v6 packets through a fixed account endpoint template.
    /// Guarantees: Both requests use the same path-encoded account, including reserved characters, and preserve content headers, authorization, and packet bytes.
    #[tokio::test]
    async fn publishes_packet_with_required_headers_and_account_routing() {
        let server = MockServer::start().await;
        let packet = vec![6, 0, 1, 2, 3];
        Mock::given(method("POST"))
            .and(path("/metrics/account%20%2F%25%3F%23"))
            .and(header("content-type", CONTENT_TYPE))
            .and(header(ORIGINAL_CONTENT_SIZE_HEADER, "5"))
            .and(header("authorization", "test-authorization"))
            .and(body_bytes(packet.clone()))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&server)
            .await;

        let endpoint = format!("{}/metrics/{{monitoring_account}}", server.uri());
        let publisher = MetricsPublisher::new(&endpoint, "account /%?#", Duration::from_secs(10))
            .expect("valid endpoint");
        for _ in 0..2 {
            publisher
                .publish(
                    packet.clone(),
                    AUTHORIZATION,
                    HeaderValue::from_static("test-authorization"),
                )
                .await
                .expect("publication should succeed");
        }
    }

    /// Scenario: The publication endpoint redirects to a page that would return HTTP 200.
    /// Guarantees: Redirects fail publication with their original status and are never followed.
    #[tokio::test]
    async fn rejects_redirects_without_following_them() {
        for status in [301, 302, 303, 307, 308] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/metrics"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("location", format!("{}/login", server.uri())),
                )
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(path("/login"))
                .respond_with(ResponseTemplate::new(200))
                .expect(0)
                .mount(&server)
                .await;

            let error = publish(
                &format!("{}/metrics", server.uri()),
                "example-account",
                vec![6, 0],
            )
            .await
            .expect_err("redirect must not count as successful publication");

            assert!(
                matches!(error, PublishError::Response { status: actual, .. } if actual.as_u16() == status),
                "expected original HTTP {status}, got {error}"
            );
            assert!(!error.is_retryable());
            assert!(!error.is_unauthorized());
        }
    }

    /// Scenario: A publication fails with HTTP 400, 401, 403, 408, 413, 429, or 5xx.
    /// Guarantees: HTTP 400 and 413 are permanent; 401, 403, 408, 429, and 5xx remain retryable independently of refusal classification.
    #[test]
    fn classifies_error_responses() {
        for status in [400, 401, 403, 408, 413, 429, 500, 503] {
            let error = PublishError::Response {
                stage: RequestStage::DirectPublication,
                status: StatusCode::from_u16(status).expect("valid HTTP status"),
            };

            assert_eq!(
                error.is_retryable(),
                !matches!(status, 400 | 413),
                "HTTP {status}"
            );
            assert_eq!(error.is_unauthorized(), status == 401);
            assert_eq!(
                error.is_refusal(),
                matches!(status, 400 | 401 | 403 | 413 | 429)
            );
        }
    }
}
