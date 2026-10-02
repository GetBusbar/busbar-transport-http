<!-- fleet:header:begin (rendered by `busbar-release plugin sync` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-transport-http

First-party signed kind:transport plugin cdylib: the http transport, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `transport` | `http` | `busbar-transport-http-plugin` | 1.6.0 (pinned in `.busbar-ref`) | MIT |

[![ci](https://github.com/GetBusbar/busbar-transport-http/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-transport-http/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-transport-http` is a `kind: transport` busbar plugin.

## Config

Configured under the `http` module name.

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
