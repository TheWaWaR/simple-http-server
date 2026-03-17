# Axum Version Analysis

## Goal

The goal of this rewrite was not to mechanically translate the old `iron` code, but to replace it with an `axum` implementation while keeping the CLI and the main runtime behavior aligned as closely as practical, with a smaller direct dependency surface.

The default direct dependencies are:

- `axum 0.8.8`
- `clap 4.6.0`
- `tokio 1.50.0`
- `flate2 1.1.9`
- `mime_guess 2.0.5`
- `httpdate 1.0.3`
- `base64 0.22.1`
- `time 0.3.47`

When the `tls` feature is enabled, it additionally pulls in:

- `openssl 0.10.76`
- `tokio-openssl 0.6.5`

`clap` intentionally does not use `derive`, and TLS is intentionally behind a single `tls` feature that is disabled by default.

## Benefits

- The server now sits on a maintained async stack instead of the old `iron` ecosystem.
- The direct dependency surface is smaller and easier to reason about.
- TLS uses `axum::serve` with a custom listener instead of adding `axum-server`.
- The codebase is split into focused modules for config, server setup, handlers, and utilities.
- The default build does not carry OpenSSL or TLS glue code.

## Tradeoffs and Pitfalls

### 1. TLS is optional, but when enabled it uses system OpenSSL

To keep the default build smaller, TLS is disabled unless `tls` is enabled.

Impact:

- Default builds are smaller and compile faster.
- TLS-capable builds depend on system OpenSSL compatibility.
- `--cert` still uses PKCS#12, which keeps CLI behavior aligned but keeps TLS on the OpenSSL path.

### 2. File responses are streamed

Regular file responses and compressed file responses are streamed instead of buffering the entire file.

Impact:

- Memory usage is much lower for large files.
- Compressed responses still use a background thread per streamed file response.

### 3. Uploads are streamed to temporary files

Uploads are written to temporary files first, then moved into place after CSRF validation succeeds.

Impact:

- Large uploads do not need to sit fully in memory.
- Failed CSRF validation cleans up temporary files.

### 4. `base-url` is normalized

`--base-url` is normalized to start with `/`, and to end with `/` when it is not root.

Impact:

- Inputs like `prefix`, `/prefix`, and `/prefix/` all normalize to `/prefix/`.

### 5. `--try-file` semantics are explicit

- Relative paths are resolved against the server root.
- Absolute paths are used as-is.

This is more explicit than the old behavior and matches the current help text.

### 6. HEAD + compression is cleaner, not identical

The old middleware-based compression path had some inconsistent historical behavior for `HEAD`.

The current implementation does not preserve those quirks:

- `HEAD` does not read and compress the whole file just to compute a compressed length.
- The result is cleaner HTTP behavior, but not byte-for-byte historical parity in that edge case.

## Compatibility Summary

### Kept aligned

- CLI flags and short options
- Directory listing
- `--index`
- `--upload` / `--csrf`
- `--auth`
- `--redirect`
- `--nocache`
- `--norange`
- `--cors`
- `--coop` / `--coep`
- `--compress`
- `--try-file`
- `--base-url`
- `--cert` / `--certpass` with PKCS#12

### Intentional fixes

- `--open` uses `https://` when TLS is enabled
- Error pages escape injected text
- `--cors` responds to `OPTIONS` preflight requests
- `--upload-size-limit` supports human-readable values such as `30K`, `50M`, and `1G`, interpreted with powers of 1024

## Verification

The current replacement is covered by black-box HTTP tests for:

- directory listing
- `try-file`
- basic auth
- range requests
- cache revalidation
- CORS preflight
- upload with CSRF
- gzip compression

Both default and `tls` builds pass `cargo test` and `cargo clippy`.
