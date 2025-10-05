/*
Token Tool - Rust CLI to mint and refresh Bearer tokens using the Worker API

Usage examples:

  # Set the base URL once (or pass --base-url each time)
  export HAMRAH_BASE_URL="https://your-worker.example.workers.dev"

  # 1) Login (creates user if needed) and store tokens
  token_tool login --email you@example.com --name "Your Name"

  # 2) Print current tokens (from store)
  token_tool print

  # 3) Validate current access token
  token_tool validate

  # 4) Refresh tokens (use stored refresh token)
  token_tool refresh

  # 5) Export to shell environment
  eval "$(token_tool export)"

Notes:
- This tool uses `curl` under the hood to avoid external Rust dependencies.
- Tokens are stored at: ~/.hamrah/token_tool.json (override with HAMRAH_TOKEN_STORE).
- Endpoints used:
  - POST /api/auth/native
  - POST /api/auth/tokens/refresh
  - GET  /api/auth/tokens/validate

Build:
  rustc -O -o token_tool hamrah-api/scripts/token_tool.rs
*/

use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DEFAULT_BASE_URL: &str = "http://localhost:8787"; // override with HAMRAH_BASE_URL or --base-url
const DEFAULT_STORE_PATH: &str = ".hamrah/token_tool.json";

#[derive(Debug, Clone)]
struct Config {
    base_url: String,
    store_path: PathBuf,
}

#[derive(Debug, Clone, Default)]
struct Tokens {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    email: Option<String>,
    base_url: Option<String>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() <= 1 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        return;
    }

    let config = load_config_from_env();
    let sub = args[1].as_str();
    match sub {
        "login" => cmd_login(&args[2..], config),
        "refresh" => cmd_refresh(&args[2..], config),
        "validate" => cmd_validate(&args[2..], config),
        "print" => cmd_print(&args[2..], config),
        "export" => cmd_export(&args[2..], config),
        _ => {
            eprintln!("Unknown command: {}", sub);
            print_help();
        }
    }
}

fn print_help() {
    let help = r#"
token_tool - Mint and refresh Bearer tokens using the Worker API

Usage:
  token_tool login [--email <email>] [--name <name>] [--provider <provider>] [--credential <cred>] [--base-url <url>]
  token_tool refresh [--refresh-token <token>] [--base-url <url>]
  token_tool validate [--access-token <token>] [--base-url <url>]
  token_tool print
  token_tool export

Environment:
  HAMRAH_BASE_URL      Base URL for the API (e.g., https://your-worker.workers.dev)
  HAMRAH_TOKEN_STORE   Path to token store file (default: ~/.hamrah/token_tool.json)

Examples:
  export HAMRAH_BASE_URL="https://your-worker.workers.dev"
  token_tool login --email you@example.com --name "You"
  token_tool validate
  token_tool refresh
  eval "$(token_tool export)"
"#;
    println!("{}", help);
}

fn load_config_from_env() -> Config {
    let base_url = env::var("HAMRAH_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
    let store_path = env::var("HAMRAH_TOKEN_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let mut home = dirs_home();
            home.push(DEFAULT_STORE_PATH);
            home
        });

    Config {
        base_url,
        store_path,
    }
}

fn cmd_login(args: &[String], mut config: Config) {
    let mut email: Option<String> = None;
    let mut name: Option<String> = None;
    let mut provider: String = "dev".to_string();
    let mut credential: String = "dummy".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--email" => {
                i += 1;
                email = args.get(i).cloned();
            }
            "--name" => {
                i += 1;
                name = args.get(i).cloned();
            }
            "--provider" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    provider = val.clone();
                }
            }
            "--credential" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    credential = val.clone();
                }
            }
            "--base-url" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    config.base_url = val.clone();
                }
            }
            x => {
                eprintln!("Unknown option: {}", x);
                return;
            }
        }
        i += 1;
    }

    let email = match email {
        Some(e) => e,
        None => {
            eprintln!("--email is required for login");
            return;
        }
    };

    let payload = format!(
        r#"{{"provider":"{}","credential":"{}","email":"{}","name":{}}}"#,
        provider,
        credential,
        email,
        match name {
            Some(n) => format!("\"{}\"", escape_json_string(&n)),
            None => "null".to_string(),
        }
    );

    let url = format!("{}/api/auth/native", trim_trailing_slash(&config.base_url));
    let resp = curl_json("POST", &url, Some(&payload), &[]);

    match resp {
        Ok(body) => {
            if let Some(err) = detect_error(&body) {
                eprintln!("Login failed: {}", err);
                eprintln!("Response: {}", body);
                std::process::exit(1);
            }

            let tokens = parse_tokens_from_auth_response(&body);
            if tokens.access_token.is_none() || tokens.refresh_token.is_none() {
                eprintln!("Failed to parse tokens from response.");
                eprintln!("Response: {}", body);
                std::process::exit(1);
            }

            let mut to_store = load_store(&config.store_path);
            to_store.access_token = tokens.access_token.clone();
            to_store.refresh_token = tokens.refresh_token.clone();
            to_store.expires_in = tokens.expires_in;
            to_store.email = Some(email.clone());
            to_store.base_url = Some(config.base_url.clone());
            if let Err(e) = save_store(&config.store_path, &to_store) {
                eprintln!("Warning: failed to save token store: {}", e);
            }

            println!("Login successful.");
            println!("Access Token:  {}", tokens.access_token.unwrap());
            println!("Refresh Token: {}", tokens.refresh_token.unwrap());
            if let Some(exp) = tokens.expires_in {
                println!("Expires In:    {}s", exp);
            }
            println!("Stored at: {}", config.store_path.display());
        }
        Err(e) => {
            eprintln!("HTTP error: {}", e);
        }
    }
}

fn cmd_refresh(args: &[String], mut config: Config) {
    let mut refresh_token: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--refresh-token" => {
                i += 1;
                refresh_token = args.get(i).cloned();
            }
            "--base-url" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    config.base_url = val.clone();
                }
            }
            x => {
                eprintln!("Unknown option: {}", x);
                return;
            }
        }
        i += 1;
    }

    // Load from store if not provided
    if refresh_token.is_none() {
        let st = load_store(&config.store_path);
        refresh_token = st.refresh_token;
        if config.base_url == DEFAULT_BASE_URL {
            if let Some(b) = st.base_url {
                config.base_url = b;
            }
        }
    }

    let refresh_token = match refresh_token {
        Some(rt) => rt,
        None => {
            eprintln!("No refresh token provided and none found in store.");
            return;
        }
    };

    let payload = format!(
        r#"{{"refresh_token":"{}"}}"#,
        escape_json_string(&refresh_token)
    );
    let url = format!(
        "{}/api/auth/tokens/refresh",
        trim_trailing_slash(&config.base_url)
    );
    let resp = curl_json("POST", &url, Some(&payload), &[]);

    match resp {
        Ok(body) => {
            if let Some(err) = detect_error(&body) {
                eprintln!("Refresh failed: {}", err);
                eprintln!("Response: {}", body);
                std::process::exit(1);
            }

            let tokens = parse_tokens_from_auth_response(&body);
            if tokens.access_token.is_none() || tokens.refresh_token.is_none() {
                eprintln!("Failed to parse tokens from response.");
                eprintln!("Response: {}", body);
                std::process::exit(1);
            }

            let mut to_store = load_store(&config.store_path);
            to_store.access_token = tokens.access_token.clone();
            to_store.refresh_token = tokens.refresh_token.clone();
            to_store.expires_in = tokens.expires_in;
            if to_store.base_url.is_none() {
                to_store.base_url = Some(config.base_url.clone());
            }
            if let Err(e) = save_store(&config.store_path, &to_store) {
                eprintln!("Warning: failed to save token store: {}", e);
            }

            println!("Refresh successful.");
            println!("New Access Token:  {}", tokens.access_token.unwrap());
            println!("New Refresh Token: {}", tokens.refresh_token.unwrap());
            if let Some(exp) = tokens.expires_in {
                println!("Expires In:        {}s", exp);
            }
            println!("Stored at: {}", config.store_path.display());
        }
        Err(e) => {
            eprintln!("HTTP error: {}", e);
        }
    }
}

fn cmd_validate(args: &[String], mut config: Config) {
    let mut access_token: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--access-token" => {
                i += 1;
                access_token = args.get(i).cloned();
            }
            "--base-url" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    config.base_url = val.clone();
                }
            }
            x => {
                eprintln!("Unknown option: {}", x);
                return;
            }
        }
        i += 1;
    }

    if access_token.is_none() {
        let st = load_store(&config.store_path);
        access_token = st.access_token;
        if config.base_url == DEFAULT_BASE_URL {
            if let Some(b) = st.base_url {
                config.base_url = b;
            }
        }
    }

    let access_token = match access_token {
        Some(t) => t,
        None => {
            eprintln!("No access token provided and none found in store.");
            return;
        }
    };

    let url = format!(
        "{}/api/auth/tokens/validate",
        trim_trailing_slash(&config.base_url)
    );
    let headers = vec![("Authorization", &format!("Bearer {}", access_token))];
    let resp = curl_json("GET", &url, None, &headers);

    match resp {
        Ok(body) => {
            if let Some(err) = detect_error(&body) {
                eprintln!("Validation error: {}", err);
                eprintln!("Response: {}", body);
                std::process::exit(1);
            }
            println!("Validation successful.");
            println!("{}", body);
        }
        Err(e) => {
            eprintln!("HTTP error: {}", e);
        }
    }
}

fn cmd_print(_args: &[String], config: Config) {
    let st = load_store(&config.store_path);
    println!("Token store: {}", config.store_path.display());
    println!(
        "Base URL:     {}",
        st.base_url.clone().unwrap_or_else(|| "<unset>".to_string())
    );
    println!(
        "Email:        {}",
        st.email.unwrap_or_else(|| "<unknown>".to_string())
    );
    println!(
        "Access Token: {}",
        st.access_token.unwrap_or_else(|| "<none>".to_string())
    );
    println!(
        "Refresh Token: {}",
        st.refresh_token.unwrap_or_else(|| "<none>".to_string())
    );
    if let Some(exp) = st.expires_in {
        println!("Expires In:   {}s", exp);
    }
}

fn cmd_export(_args: &[String], config: Config) {
    let st = load_store(&config.store_path);
    if let Some(url) = st.base_url {
        println!("export HAMRAH_BASE_URL='{}'", shell_escape(&url));
    }
    if let Some(at) = st.access_token {
        println!("export HAMRAH_ACCESS_TOKEN='{}'", shell_escape(&at));
    }
    if let Some(rt) = st.refresh_token {
        println!("export HAMRAH_REFRESH_TOKEN='{}'", shell_escape(&rt));
    }
}

/* ------------------------------ Utilities ------------------------------ */

fn trim_trailing_slash(s: &str) -> String {
    if s.ends_with('/') {
        s.trim_end_matches('/').to_string()
    } else {
        s.to_string()
    }
}

fn dirs_home() -> PathBuf {
    if let Some(home) = dirs_home_inner() {
        home
    } else {
        PathBuf::from(".")
    }
}

#[cfg(target_os = "windows")]
fn dirs_home_inner() -> Option<PathBuf> {
    dirs_next::home_dir()
}

#[cfg(not(target_os = "windows"))]
fn dirs_home_inner() -> Option<PathBuf> {
    env::var("HOME").ok().map(PathBuf::from)
}

fn ensure_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn load_store(path: &Path) -> Tokens {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Tokens::default(),
    };
    let mut s = String::new();
    if f.read_to_string(&mut s).is_err() {
        return Tokens::default();
    }
    parse_tokens_from_store(&s)
}

fn save_store(path: &Path, tokens: &Tokens) -> std::io::Result<()> {
    ensure_parent_dir(path)?;
    let mut f = File::create(path)?;
    let json = format!(
        r#"{{"base_url":{},"email":{},"access_token":{},"refresh_token":{},"expires_in":{}}}"#,
        match &tokens.base_url {
            Some(v) => format!("\"{}\"", escape_json_string(v)),
            None => "null".to_string(),
        },
        match &tokens.email {
            Some(v) => format!("\"{}\"", escape_json_string(v)),
            None => "null".to_string(),
        },
        match &tokens.access_token {
            Some(v) => format!("\"{}\"", escape_json_string(v)),
            None => "null".to_string(),
        },
        match &tokens.refresh_token {
            Some(v) => format!("\"{}\"", escape_json_string(v)),
            None => "null".to_string(),
        },
        match tokens.expires_in {
            Some(v) => v.to_string(),
            None => "null".to_string(),
        }
    );
    f.write_all(json.as_bytes())
}

/* ------------------------------ HTTP via curl ------------------------------ */

fn curl_json(
    method: &str,
    url: &str,
    body_json: Option<&str>,
    headers: &[(&str, &str)],
) -> Result<String, String> {
    let mut cmd = Command::new("curl");
    cmd.arg("-sS");
    cmd.arg("-i"); // include HTTP status headers to get non-200 details
    cmd.arg("-X").arg(method);
    cmd.arg(url);

    for (k, v) in headers {
        cmd.arg("-H").arg(format!("{}: {}", k, v));
    }

    if body_json.is_some() {
        cmd.arg("-H").arg("Content-Type: application/json");
        cmd.arg("-d").arg(body_json.unwrap());
    }

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run curl: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Extract body (after the last blank line separating headers and body)
    let body = extract_http_body(&stdout);

    // Non-zero exit code also returns here, but we rely on API error JSON if possible
    if !output.status.success() {
        return Err(format!(
            "curl exited with status {}. Body: {}",
            output.status, body
        ));
    }

    Ok(body)
}

fn extract_http_body(http_output: &str) -> String {
    // Handle possible multiple HTTP response blocks (redirects). Body is after final header block.
    // Split on \r\n\r\n or \n\n
    let parts: Vec<&str> = http_output.split("\r\n\r\n").collect();
    let last = parts.last().unwrap_or(&http_output);
    // Some systems only use \n\n
    if last.contains("\n") && !last.contains("{") && !last.contains("[") {
        // Might be headers; try a different split
        let parts_n: Vec<&str> = http_output.split("\n\n").collect();
        parts_n.last().unwrap_or(&http_output).to_string()
    } else {
        last.to_string()
    }
}

/* ------------------------------ JSON helpers (naive) ------------------------------ */

fn detect_error(body: &str) -> Option<String> {
    // If body contains {"error":{...}}, try to extract message
    if !body.contains("\"error\"") {
        return None;
    }
    if let Some(msg) = extract_string_field(body, &["error", "message"]) {
        return Some(msg);
    }
    Some("Unknown error".to_string())
}

fn parse_tokens_from_auth_response(body: &str) -> Tokens {
    Tokens {
        access_token: extract_string_field(body, &["access_token"]),
        refresh_token: extract_string_field(body, &["refresh_token"]),
        expires_in: extract_number_field(body, &["expires_in"]),
        email: None,
        base_url: None,
    }
}

fn parse_tokens_from_store(body: &str) -> Tokens {
    Tokens {
        base_url: extract_string_field(body, &["base_url"]),
        email: extract_string_field(body, &["email"]),
        access_token: extract_string_field(body, &["access_token"]),
        refresh_token: extract_string_field(body, &["refresh_token"]),
        expires_in: extract_number_field(body, &["expires_in"]),
    }
}

// Supports nested keys like ["error","message"]
fn extract_string_field(json: &str, keys: &[&str]) -> Option<String> {
    let mut search_area = json;
    for (idx, key) in keys.iter().enumerate() {
        let pattern = format!("\"{}\":", key);
        if let Some(pos) = search_area.find(&pattern) {
            let rest = &search_area[pos + pattern.len()..];
            if idx == keys.len() - 1 {
                // Expecting "value"
                let rest_trim = rest.trim_start();
                if rest_trim.starts_with('"') {
                    return extract_quoted_string(rest_trim);
                } else if rest_trim.starts_with("null") {
                    return None;
                } else {
                    // Not a string
                    return None;
                }
            } else {
                // Move into nested object by finding the next '{' after the key and using until its matching '}'
                if let Some(obj_start) = rest.find('{') {
                    // Use from start of child object
                    search_area = &rest[obj_start..];
                } else {
                    return None;
                }
            }
        } else {
            return None;
        }
    }
    None
}

fn extract_number_field(json: &str, keys: &[&str]) -> Option<i64> {
    let mut search_area = json;
    for (idx, key) in keys.iter().enumerate() {
        let pattern = format!("\"{}\":", key);
        if let Some(pos) = search_area.find(&pattern) {
            let rest = &search_area[pos + pattern.len()..];
            if idx == keys.len() - 1 {
                let rest_trim = rest.trim_start();
                // capture until comma or closing brace
                let mut end = rest_trim.len();
                for (i, ch) in rest_trim.char_indices() {
                    if ch == ',' || ch == '}' || ch == '\n' {
                        end = i;
                        break;
                    }
                }
                let num_str = rest_trim[..end].trim();
                if num_str.starts_with('"') {
                    // number in string
                    if let Some(s) = extract_quoted_string(num_str) {
                        return s.parse::<i64>().ok();
                    } else {
                        return None;
                    }
                } else if num_str.starts_with("null") {
                    return None;
                } else {
                    return num_str.parse::<i64>().ok();
                }
            } else {
                if let Some(obj_start) = rest.find('{') {
                    search_area = &rest[obj_start..];
                } else {
                    return None;
                }
            }
        } else {
            return None;
        }
    }
    None
}

fn extract_quoted_string(s: &str) -> Option<String> {
    // s should start with '"'
    let mut chars = s.chars();
    if chars.next()? != '"' {
        return None;
    }
    let mut result = String::new();
    let mut escape = false;
    for ch in chars {
        if escape {
            // Only handle simple escapes we expect to appear
            result.push(match ch {
                '"' => '"',
                '\\' => '\\',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'b' => '\u{0008}',
                'f' => '\u{000C}',
                other => other, // pass through
            });
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else if ch == '"' {
            return Some(result);
        } else {
            result.push(ch);
        }
    }
    None
}

fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push(' '), // sanitize control chars
            c => out.push(c),
        }
    }
    out
}

fn shell_escape(s: &str) -> String {
    // Single-quote style shell escaping
    let mut out = String::new();
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out
}
