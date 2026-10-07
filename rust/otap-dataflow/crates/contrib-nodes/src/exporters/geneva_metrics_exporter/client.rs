// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use otel_arrow_dfe_telemetry::otel_debug;
use reqwest::header::{AUTHORIZATION, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use std::fmt;
use std::time::{Duration, Instant};
use thiserror::Error;

const CONTENT_TYPE: &str = "application/x-mepacket";
const ORIGINAL_CONTENT_SIZE_HEADER: &str = "OriginalContentSize";
const GIG_CONTEXT_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, Debug)]
pub(crate) struct MetricsPublisher {
    client: Client,
    mode: PublicationMode,
}

#[derive(Clone, Debug)]
enum PublicationMode {
    Direct { endpoint: String },
    ManagedIdentityGig(Box<ManagedIdentityGigMode>),
}

#[derive(Clone, Debug)]
struct ManagedIdentityGigMode {
    home_stamp: Url,
    stamp_id: String,
    cached_context: Option<GigPublicationContext>,
}

#[derive(Clone, Debug)]
struct GigPublicationContext {
    monitoring_account: String,
    source_auth_generation: u64,
    publication_endpoint: Url,
    auth_header_value: HeaderValue,
    refresh_at: Instant,
}

impl GigPublicationContext {
    fn is_usable_for(&self, monitoring_account: &str, source_auth_generation: u64) -> bool {
        self.monitoring_account == monitoring_account
            && self.source_auth_generation == source_auth_generation
            && Instant::now() < self.refresh_at
    }
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
        matches!(
            self,
            Self::Response {
                stage: RequestStage::DirectPublication | RequestStage::GigTokenExchange,
                status: StatusCode::UNAUTHORIZED,
            }
        )
    }

    pub(crate) fn is_retryable(&self) -> bool {
        match self {
            Self::Request { .. }
            | Self::InvalidExchangeResponse(_)
            | Self::MissingExchangeField { .. }
            | Self::InvalidGigEndpoint(_)
            | Self::InvalidGigToken => true,
            Self::Response { status, .. } => {
                *status == StatusCode::UNAUTHORIZED
                    || *status == StatusCode::TOO_MANY_REQUESTS
                    || status.is_server_error()
            }
        }
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
    pub(crate) fn new(endpoint: &str, timeout: Duration) -> Result<Self, PublisherBuildError> {
        let endpoint = endpoint.trim();
        let _endpoint = Url::parse(endpoint)
            .map_err(|error| PublisherBuildError::InvalidEndpoint(error.to_string()))?;
        Ok(Self {
            client: build_client(timeout)?,
            mode: PublicationMode::Direct {
                endpoint: endpoint.to_owned(),
            },
        })
    }

    pub(crate) fn new_managed_identity(
        home_stamp: &str,
        timeout: Duration,
    ) -> Result<Self, PublisherBuildError> {
        let home_stamp = Url::parse(home_stamp.trim())
            .map_err(|error| PublisherBuildError::InvalidEndpoint(error.to_string()))?;
        let stamp_id = home_stamp
            .host_str()
            .and_then(|host| host.split('.').next())
            .filter(|stamp_id| !stamp_id.is_empty())
            .ok_or(PublisherBuildError::MissingStampId)?
            .to_owned();
        Ok(Self {
            client: build_client(timeout)?,
            mode: PublicationMode::ManagedIdentityGig(Box::new(ManagedIdentityGigMode {
                home_stamp,
                stamp_id,
                cached_context: None,
            })),
        })
    }

    pub(crate) async fn publish(
        &mut self,
        monitoring_account: &str,
        packet: Vec<u8>,
        auth_header_name: HeaderName,
        auth_header_value: HeaderValue,
        auth_generation: u64,
    ) -> Result<(), PublishError> {
        let packet = Bytes::from(packet);
        match &mut self.mode {
            PublicationMode::Direct { endpoint } => {
                let endpoint = endpoint.replace(
                    "{monitoring_account}",
                    &urlencoding::encode(monitoring_account),
                );
                send_packet(
                    &self.client,
                    endpoint,
                    packet,
                    auth_header_name,
                    auth_header_value,
                    RequestStage::DirectPublication,
                )
                .await
            }
            PublicationMode::ManagedIdentityGig(mode) => {
                let ManagedIdentityGigMode {
                    home_stamp,
                    stamp_id,
                    cached_context,
                } = mode.as_mut();
                let context = match cached_context.as_ref() {
                    Some(context) if context.is_usable_for(monitoring_account, auth_generation) => {
                        context.clone()
                    }
                    _ => {
                        let context = exchange_gig_context(
                            &self.client,
                            home_stamp,
                            stamp_id,
                            monitoring_account,
                            &auth_header_name,
                            &auth_header_value,
                            auth_generation,
                        )
                        .await?;
                        *cached_context = Some(context.clone());
                        context
                    }
                };
                let result = send_gig_packet(&self.client, &context, packet.clone()).await;
                if !result
                    .as_ref()
                    .is_err_and(PublishError::is_gig_publication_unauthorized)
                {
                    return result;
                }

                *cached_context = None;
                let refreshed = exchange_gig_context(
                    &self.client,
                    home_stamp,
                    stamp_id,
                    monitoring_account,
                    &auth_header_name,
                    &auth_header_value,
                    auth_generation,
                )
                .await?;
                *cached_context = Some(refreshed.clone());
                let retry = send_gig_packet(&self.client, &refreshed, packet).await;
                if retry
                    .as_ref()
                    .is_err_and(PublishError::is_gig_publication_unauthorized)
                {
                    *cached_context = None;
                }
                retry
            }
        }
    }
}

fn build_client(timeout: Duration) -> Result<Client, PublisherBuildError> {
    otel_arrow_dfe_otap::crypto::ensure_crypto_provider();
    Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .build()
        .map_err(|error| PublisherBuildError::Client(Box::new(error)))
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
        monitoring_account: monitoring_account.to_owned(),
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
    send_packet(
        client,
        context.publication_endpoint.clone(),
        packet,
        AUTHORIZATION,
        context.auth_header_value.clone(),
        RequestStage::GigPublication,
    )
    .await
}

async fn send_packet(
    client: &Client,
    endpoint: impl reqwest::IntoUrl,
    packet: Bytes,
    auth_header_name: HeaderName,
    auth_header_value: HeaderValue,
    stage: RequestStage,
) -> Result<(), PublishError> {
    let original_size = packet.len();
    let response = client
        .post(endpoint)
        .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE)
        .header(ORIGINAL_CONTENT_SIZE_HEADER, original_size)
        .header(auth_header_name, auth_header_value)
        .body(packet)
        .send()
        .await
        .map_err(|source| PublishError::Request {
            stage,
            source: Box::new(source),
        })?;

    if response.status() == StatusCode::OK {
        Ok(())
    } else {
        Err(PublishError::Response {
            stage,
            status: response.status(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{body_bytes, header, method, path, query_param};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[derive(Clone, Default)]
    struct UnauthorizedOnce {
        calls: Arc<AtomicUsize>,
    }

    impl Respond for UnauthorizedOnce {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(401)
            } else {
                ResponseTemplate::new(200)
            }
        }
    }

    fn authorization_header() -> HeaderValue {
        HeaderValue::from_static("test-authorization")
    }

    /// Scenario: A protocol v6 packet is published to a healthy endpoint.
    /// Guarantees: The C++-compatible content headers and packet bytes are sent unchanged.
    #[tokio::test]
    async fn publishes_packet_with_required_headers() {
        let server = MockServer::start().await;
        let packet = vec![6, 0, 1, 2, 3];
        Mock::given(method("POST"))
            .and(path("/metrics"))
            .and(header("content-type", CONTENT_TYPE))
            .and(header(ORIGINAL_CONTENT_SIZE_HEADER, "5"))
            .and(header("authorization", "test-authorization"))
            .and(body_bytes(packet.clone()))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let mut publisher =
            MetricsPublisher::new(&format!("{}/metrics", server.uri()), Duration::from_secs(1))
                .expect("publisher should be created");

        publisher
            .publish(
                "example-account",
                packet,
                AUTHORIZATION,
                authorization_header(),
                1,
            )
            .await
            .expect("publication should succeed");
    }

    /// Scenario: The endpoint rejects a packet with a non-retryable client error.
    /// Guarantees: HTTP 400 and 403 responses are classified as permanent.
    #[tokio::test]
    async fn classifies_client_error_as_permanent() {
        for status in [400, 403] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            let mut publisher = MetricsPublisher::new(&server.uri(), Duration::from_secs(1))
                .expect("valid endpoint");

            let error = publisher
                .publish(
                    "example-account",
                    vec![6, 0],
                    AUTHORIZATION,
                    authorization_header(),
                    1,
                )
                .await
                .expect_err("publication should fail");

            assert!(!error.is_retryable(), "HTTP {status} should be permanent");
            assert!(!error.is_unauthorized());
        }
    }

    /// Scenario: A bearer credential is rejected, the endpoint is throttled, or the service is unavailable.
    /// Guarantees: HTTP 401, 429, and 5xx responses are classified as retryable.
    #[tokio::test]
    async fn classifies_transient_responses_as_retryable() {
        for status in [401, 429, 500, 503] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            let mut publisher = MetricsPublisher::new(&server.uri(), Duration::from_secs(1))
                .expect("valid endpoint");

            let error = publisher
                .publish(
                    "example-account",
                    vec![6, 0],
                    AUTHORIZATION,
                    authorization_header(),
                    1,
                )
                .await
                .expect_err("publication should fail");

            assert!(error.is_retryable(), "HTTP {status} should be retryable");
            assert_eq!(error.is_unauthorized(), status == 401);
        }
    }

    /// Scenario: An authenticated account publication uses an endpoint template.
    /// Guarantees: The account is path-encoded and the supplied authorization header is sent.
    #[tokio::test]
    async fn publishes_with_authorization_header_and_account_routing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/metrics/account%20name"))
            .and(header("authorization", "test-authorization"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let mut publisher = MetricsPublisher::new(
            &format!("{}/metrics/{{monitoring_account}}", server.uri()),
            Duration::from_secs(1),
        )
        .expect("valid endpoint");

        publisher
            .publish(
                "account name",
                vec![6, 0],
                AUTHORIZATION,
                authorization_header(),
                1,
            )
            .await
            .expect("authenticated publication should succeed");
    }

    /// Scenario: A direct publication endpoint redirects to another host.
    /// Guarantees: The exporter reports the 3xx response and does not follow an authenticated POST.
    #[tokio::test]
    async fn does_not_follow_publication_redirects() {
        let redirect_target = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&redirect_target)
            .await;
        let endpoint = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/login", redirect_target.uri())),
            )
            .expect(1)
            .mount(&endpoint)
            .await;
        let mut publisher =
            MetricsPublisher::new(&endpoint.uri(), Duration::from_secs(1)).expect("valid endpoint");

        let error = publisher
            .publish(
                "example-account",
                vec![6, 0],
                AUTHORIZATION,
                authorization_header(),
                1,
            )
            .await
            .expect_err("redirect should be surfaced");

        assert!(matches!(
            error,
            PublishError::Response {
                stage: RequestStage::DirectPublication,
                status: StatusCode::FOUND,
            }
        ));
        assert!(!error.is_retryable());
    }

    /// Scenario: Managed identity authentication publishes multiple packets for one account.
    /// Guarantees: The MI token is exchanged once, cached, and replaced by the returned GIG token for ingestion.
    #[tokio::test]
    async fn exchanges_managed_identity_token_for_cached_gig_publication() {
        let gig_server = MockServer::start().await;
        let packet = vec![6, 0, 1, 2, 3];
        Mock::given(method("POST"))
            .and(path("/api/v1/ingestion/ingest"))
            .and(query_param("accountId", "example-account"))
            .and(query_param("stampId", "127"))
            .and(header("authorization", "Bearer gig-token"))
            .and(header("content-type", CONTENT_TYPE))
            .and(body_bytes(packet.clone()))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&gig_server)
            .await;
        let home_stamp = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/user-api/v2/authorization/gig/monitoringAccount/example-account",
            ))
            .and(header("authorization", "Bearer mi-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "gigEndpoint": gig_server
                    .uri()
                    .trim_start_matches("http://"),
                "gigAuthToken": "gig-token",
                "forkGigTraffic": false
            })))
            .expect(1)
            .mount(&home_stamp)
            .await;
        let mut publisher =
            MetricsPublisher::new_managed_identity(&home_stamp.uri(), Duration::from_secs(1))
                .expect("managed identity publisher should be created");
        let mi_header = HeaderValue::from_static("Bearer mi-token");

        for _ in 0..2 {
            publisher
                .publish(
                    "example-account",
                    packet.clone(),
                    AUTHORIZATION,
                    mi_header.clone(),
                    7,
                )
                .await
                .expect("GIG publication should succeed");
        }
    }

    /// Scenario: The managed identity credential generation changes while a GIG context is cached.
    /// Guarantees: The exporter performs a new account-specific token exchange before publishing again.
    #[tokio::test]
    async fn refreshes_gig_context_after_managed_identity_rotation() {
        let gig_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ingestion/ingest"))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&gig_server)
            .await;
        let home_stamp = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/user-api/v2/authorization/gig/monitoringAccount/example-account",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "gigEndpoint": gig_server
                    .uri()
                    .trim_start_matches("http://"),
                "gigAuthToken": "gig-token",
                "forkGigTraffic": false
            })))
            .expect(2)
            .mount(&home_stamp)
            .await;
        let mut publisher =
            MetricsPublisher::new_managed_identity(&home_stamp.uri(), Duration::from_secs(1))
                .expect("managed identity publisher should be created");

        for generation in [1, 2] {
            publisher
                .publish(
                    "example-account",
                    vec![6, 0],
                    AUTHORIZATION,
                    authorization_header(),
                    generation,
                )
                .await
                .expect("GIG publication should succeed");
        }
    }

    /// Scenario: A cached GIG token is rejected by the ingestion endpoint.
    /// Guarantees: The exporter repeats the MI exchange and retries the packet once with a fresh GIG context.
    #[tokio::test]
    async fn refreshes_gig_context_after_publication_unauthorized() {
        let gig_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ingestion/ingest"))
            .respond_with(UnauthorizedOnce::default())
            .expect(2)
            .mount(&gig_server)
            .await;
        let home_stamp = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/user-api/v2/authorization/gig/monitoringAccount/example-account",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "gigEndpoint": gig_server
                    .uri()
                    .trim_start_matches("http://"),
                "gigAuthToken": "gig-token",
                "forkGigTraffic": false
            })))
            .expect(2)
            .mount(&home_stamp)
            .await;
        let mut publisher =
            MetricsPublisher::new_managed_identity(&home_stamp.uri(), Duration::from_secs(1))
                .expect("managed identity publisher should be created");

        publisher
            .publish(
                "example-account",
                vec![6, 0],
                AUTHORIZATION,
                authorization_header(),
                1,
            )
            .await
            .expect("the refreshed GIG publication should succeed");
    }

    /// Scenario: One exporter observes different monitoring accounts in consecutive requests.
    /// Guarantees: A GIG token exchanged for one account is never reused for another account.
    #[tokio::test]
    async fn separates_gig_contexts_by_monitoring_account() {
        let gig_server = MockServer::start().await;
        for (account, token) in [("account-a", "gig-token-a"), ("account-b", "gig-token-b")] {
            Mock::given(method("POST"))
                .and(path("/api/v1/ingestion/ingest"))
                .and(query_param("accountId", account))
                .and(header("authorization", format!("Bearer {token}")))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&gig_server)
                .await;
        }
        let home_stamp = MockServer::start().await;
        for (account, token) in [("account-a", "gig-token-a"), ("account-b", "gig-token-b")] {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/user-api/v2/authorization/gig/monitoringAccount/{account}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "gigEndpoint": gig_server
                        .uri()
                        .trim_start_matches("http://"),
                    "gigAuthToken": token,
                    "forkGigTraffic": false
                })))
                .expect(1)
                .mount(&home_stamp)
                .await;
        }
        let mut publisher =
            MetricsPublisher::new_managed_identity(&home_stamp.uri(), Duration::from_secs(1))
                .expect("managed identity publisher should be created");

        for account in ["account-a", "account-b"] {
            publisher
                .publish(
                    account,
                    vec![6, 0],
                    AUTHORIZATION,
                    authorization_header(),
                    1,
                )
                .await
                .expect("account-specific GIG publication should succeed");
        }
    }

    /// Scenario: Geneva rejects the MI token during the account-specific GIG exchange.
    /// Guarantees: HTTP 401 invalidates source auth while HTTP 403 remains a permanent account authorization failure.
    #[tokio::test]
    async fn classifies_gig_exchange_authorization_failures() {
        for (status, invalidates_source_auth, retryable) in [(401, true, true), (403, false, false)]
        {
            let home_stamp = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&home_stamp)
                .await;
            let mut publisher =
                MetricsPublisher::new_managed_identity(&home_stamp.uri(), Duration::from_secs(1))
                    .expect("managed identity publisher should be created");

            let error = publisher
                .publish(
                    "example-account",
                    vec![6, 0],
                    AUTHORIZATION,
                    authorization_header(),
                    1,
                )
                .await
                .expect_err("exchange should fail");

            assert_eq!(error.is_unauthorized(), invalidates_source_auth);
            assert_eq!(error.is_retryable(), retryable);
            assert!(matches!(
                error,
                PublishError::Response {
                    stage: RequestStage::GigTokenExchange,
                    ..
                }
            ));
        }
    }
}
