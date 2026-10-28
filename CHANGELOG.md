# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-29

Not yet published to npm.

### Added

- `computeSignature`: HMAC-SHA256 over `` `${t}.` `` + raw body, hex output.
- `parseSignatureHeader`: strict `t=` (digits only, exactly once), multiple `v1=` values,
  unknown schemes ignored.
- `safeCompareHex`: constant-time comparison via `crypto.timingSafeEqual`; returns `false`
  instead of throwing on length mismatch or invalid hex.
- `verifyWebhook`: secrets, body, header, timestamp window (both directions), signature against
  every secret (rotation, reports `secretIndex`), then replay check by delivery ID.
- `MemoryReplayStore`: in-memory LRU with TTL (`maxEntries` default 10,000), plus the
  `ReplayStore` interface for shared stores such as Redis (`SET NX EX`).
- `expressWebhookMiddleware` (after `express.raw()`) and `fastifyRawBody` helpers.
- `signWebhook` helper for senders and tests.
- Dual ESM/CJS build with type declarations; Node.js 18+; no runtime dependencies.
