# Geneva Metrics Exporter

## Metadata

- Type: Exporter
- Feature gate: `geneva-metrics`
- Stability: WIP; metrics support is under development

## Overview

The Geneva Metrics Exporter is designed for Microsoft products to send OTLP
metrics to the Geneva monitoring backend. It maps OTLP metrics to the Geneva
metric model, encodes Geneva metrics ingestion protocol and publishes them to Geneva.

The exporter is separate from `geneva_exporter`, which publishes logs and
traces through a different Geneva protocol and client.

The current implementation contains the protocol model, encoder, compatibility
fixtures, Geneva-compatible mapping for OTLP and OTAP metrics views,
authenticated HTTP publication, exporter registration, and runtime
configuration. The registered exporter accepts OTLP metrics payloads.

The exporter requires a bound `bearer_token_provider` and supports two
authentication modes. With `auth.type: bearer`, `endpoint` is the full Geneva
publication URL and the provider credential is sent directly. With
`auth.type: managed_identity`, `endpoint` is the Geneva home stamp origin. The
exporter exchanges the managed identity credential for an account-specific GIG
endpoint and token, then publishes to GIG. The endpoint must use HTTPS.

The exporter currently supports one monitoring account per OTLP request.
Requests whose resource or data point attributes select multiple accounts are
rejected before publication.

## Testing

Run the current Geneva metrics tests with:

```bash
cargo test --manifest-path rust/otap-dataflow/Cargo.toml \
  -p otel-arrow-dfe-contrib-nodes \
  --features geneva-metrics \
  geneva_metrics_exporter
```

## License

Apache 2.0
