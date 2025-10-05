# Token Tool (Rust) — Bearer/Refresh token helper for Hamrah API

A tiny Rust CLI that helps you:
- Mint a new access/refresh token pair for a user via the Worker API
- Validate the current access token
- Refresh tokens using the refresh token
- Persist tokens locally and export them to your shell for use with curl

It talks to the following API endpoints exposed by the Worker:
- POST `/api/auth/native`
- POST `/api/auth/tokens/refresh`
- GET  `/api/auth/tokens/validate`

Note: Only `/v1/*` endpoints are protected by iOS App Attestation. The auth endpoints above are public (no attestation required). If you use the minted token with `/v1/*`, ensure the Worker has `APP_ATTEST_DEV_BYPASS` set to a truthy value in your environment (or send the proper iOS App Attestation headers).


## Requirements

- curl (required)
- Rust toolchain (for building a single-file binary with `rustc`)
- jq (optional, for pretty-printing JSON in your shell)


## Location

- Script source: `hamrah-api/scripts/token_tool.rs`
- Default token store file: `~/.hamrah/token_tool.json` (override with `HAMRAH_TOKEN_STORE`)


## Build

Build the standalone binary with `rustc` (no external crates are required):

~~~bash
rustc -O -o token_tool hamrah-api/scripts/token_tool.rs
~~~

Optional: move it somewhere on your PATH:

~~~bash
mv ./token_tool /usr/local/bin/
# or ~/.local/bin if you prefer
~~~


## Quick Start

1) Point the tool at your Worker (replace with your domain):

~~~bash
export HAMRAH_BASE_URL="https://your-worker.example.workers.dev"
~~~

2) Login (creates user if needed) and store tokens:

~~~bash
token_tool login --email you@example.com --name "Your Name"
~~~

3) Validate the access token:

~~~bash
token_tool validate
~~~

4) Refresh when it expires:

~~~bash
token_tool refresh
~~~

5) Export to your shell:

~~~bash
eval "$(token_tool export)"
# Now you have:
#   $HAMRAH_BASE_URL
#   $HAMRAH_ACCESS_TOKEN
#   $HAMRAH_REFRESH_TOKEN
~~~

6) Use with your protected endpoints:

~~~bash
curl -sS "$HAMRAH_BASE_URL/v1/links" \
  -H "Authorization: Bearer $HAMRAH_ACCESS_TOKEN" | jq .
~~~

If your Worker enforces App Attestation on `/v1/*`, make sure `APP_ATTEST_DEV_BYPASS` is set to a truthy value during development or include the required iOS headers.


## Commands

- `login` — Mint a new access/refresh token pair (creates the user if needed)
  - Flags:
    - `--email <email>` (required)
    - `--name <name>` (optional)
    - `--provider <provider>` (default: `dev`)
    - `--credential <cred>` (default: `dummy`)
    - `--base-url <url>` (override `HAMRAH_BASE_URL`)
  - Example:
    ~~~bash
    token_tool login --email you@example.com --name "You"
    ~~~

- `refresh` — Use the stored or provided refresh token to get a new pair
  - Flags:
    - `--refresh-token <token>` (optional; falls back to store)
    - `--base-url <url>` (override `HAMRAH_BASE_URL`)
  - Example:
    ~~~bash
    token_tool refresh
    ~~~

- `validate` — Validate the current access token
  - Flags:
    - `--access-token <token>` (optional; falls back to store)
    - `--base-url <url>` (override `HAMRAH_BASE_URL`)
  - Example:
    ~~~bash
    token_tool validate
    ~~~

- `print` — Show what’s currently stored (base URL, email, tokens)
  - Example:
    ~~~bash
    token_tool print
    ~~~

- `export` — Emit shell exports for the stored base URL and tokens
  - Example:
    ~~~bash
    eval "$(token_tool export)"
    ~~~


## Environment Variables

- `HAMRAH_BASE_URL` — Base URL for the API, e.g.:
  ~~~bash
  export HAMRAH_BASE_URL="https://your-worker.example.workers.dev"
  ~~~
- `HAMRAH_TOKEN_STORE` — Override the token store path (defaults to `~/.hamrah/token_tool.json`)


## Token Storage

- Tokens are stored as JSON at `~/.hamrah/token_tool.json` by default.
- Keep this file secure as it contains your refresh token.
- To clear tokens:
  ~~~bash
  rm -f ~/.hamrah/token_tool.json
  ~~~


## Troubleshooting

- Getting `401 unauthorized` on `/v1/*`:
  - Ensure the Worker has `APP_ATTEST_DEV_BYPASS` set to a truthy value when developing without iOS attestation headers.
  - Confirm `Authorization: Bearer <access_token>` header is present.

- Refresh fails:
  - The refresh token may be expired or revoked (refresh tokens last 30 days by default).
  - Run `token_tool login` again to mint a fresh pair.

- Validate fails:
  - The access token may be expired (access tokens last 1 hour by default); use `token_tool refresh`.

- Wrong base URL:
  - Execute `token_tool print` to see the stored base URL.
  - Set `HAMRAH_BASE_URL` or pass `--base-url` on each command.


## Security Notes

- Never commit tokens to source control.
- Treat the refresh token like a password—anyone with it can mint new access tokens.
- Rotate or revoke tokens if you suspect leakage.
