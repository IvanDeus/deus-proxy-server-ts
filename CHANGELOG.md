# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-10-09

### Added

- `logger.ts` stamps every console line on its own, so `console.log`, `console.warn` and
  `console.error` all carry a timestamp without the call site building one.
- `LOG_TZ` environment variable selects the zone the timestamps are rendered in
  (default `UTC`). An unknown zone name falls back to the host's own zone and says so on
  stderr instead of refusing to start.

### Changed

- Timestamps read `[09.10.2026 09:14:38]` rather than `[09/10/2026, 09:14:38]`, and the zone is
  configurable where it used to be hard-coded to `Europe/Moscow`. Set `LOG_TZ=Europe/Moscow` to
  keep the previous behaviour.

## [1.1.0] - 2026-10-09

### Added

- Downloaded volume is logged per proxied request: every HTTP response and every HTTPS
  `CONNECT` tunnel reports the bytes it streamed (`Downloaded 12.34 MB (12910848 bytes) for ...`).
  Aborted transfers are counted too — a tunnel the client drops mid-download logs its partial
  size once and only once.

## [1.0.0] - 2026-07-22

The first packaged release, covering everything built up to this point.

### Added

- HTTP forwarding and HTTPS `CONNECT` tunneling with no traffic decryption, so end-to-end
  encryption is preserved.
- Anonymous access control: a separate auth server serves a PIN page, and a correct PIN
  whitelists the client's IP for `TIMEOUT` minutes. Unauthorized IPs get `403 Access denied`
  on the proxy port.
- Brute-force resistance: every authentication attempt is answered after a fixed 2200 ms delay.
- Authorization expiry with a background sweep every 30 s, plus lazy eviction on lookup.
- Configuration through environment variables (`PORT`, `AUTHPORT`, `PIN`, `TIMEOUT`) read from `Bun.env`.
- IPv4-first DNS with a per-request retry without the family restriction when a target fails
  with `ENOTFOUND` / `EAI_FAIL`.
- Hop-by-hop response headers stripped before responses reach the client.
- Timestamped logging in Moscow time, active-connection tracking and graceful shutdown on
  `SIGINT` / `SIGTERM`.

### Removed

- The `config.json`-based configuration used by earlier development builds, in favour of
  environment variables.
