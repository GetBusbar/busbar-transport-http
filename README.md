<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-transport-http

First-party signed kind:transport plugin cdylib: the http transport, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `transport` | `http` | `busbar-transport-http-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-transport-http/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-transport-http/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-transport-http` frames HTTP requests and responses for the `http`, `https` and `sse`
claims. It supports HTTP/1.1 and HTTP/2 on outgoing connections and accepted listeners. An SSE
response is carried incrementally as HTTP body data. Busbar's connector owns the socket and TLS;
this plugin runs the protocol over the bytes and clock supplied by the host.

## Config

Configured under the `http` module name. The plugin reads these existing settings paths:

| Setting | Default | Effect |
|---|---|---|
| `advanced.upstream_h2_prior_knowledge` | `false` | Use HTTP/2 without protocol negotiation, including on cleartext connections. |
| `advanced.upstream_http1_only` | `false` | Restrict outgoing connections to HTTP/1.1; this takes precedence over prior knowledge. |
| `limits.upstream_request_timeout_secs` | `300` | Bound each outgoing attempt from its first emit through the end of its response body. |
| `limits.request_body_max_bytes` | `33554432` (32 MiB) | Bound an emitted request body; also derive the accepted body's existing total read deadline. |

Counts must be positive, flags must be booleans, and unknown settings are refused. Response
bodies stream without a transport-local size ceiling. Accepted requests use the host's selected
guest policy and authentication before they reach the plane; a `HeadBody` policy holds the body
under that line's body limit. The accepted side retains the existing header/body read and idle
bounds. An unanswered HTTP/1 upgrade can be handed to its upgrade framer as sent, and a completed
`101` switch hands over the subsequent bytes. HTTP/2 stays on its original framing.

## Differences from 1.5.5

Initially silent accepted connections now enter the existing 30-second idle close bound,
including before HTTP protocol detection, to bound pre-authentication resource retention.
Plugin-owned credential-bearing header, target and wire copies are wiped or streamed directly
into the host sink. Body and handover-copy limits are checked before allocating an over-limit
copy. Valid request and response wire behavior is unchanged by these hardening measures.

## Build

```bash
cargo build --release -p busbar-transport-http-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
