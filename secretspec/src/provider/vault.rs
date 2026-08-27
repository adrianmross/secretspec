//! HashiCorp Vault / OpenBao provider
//!
//! This provider integrates with HashiCorp Vault and OpenBao to store and retrieve
//! secrets using the KV (Key-Value) secrets engine (v1 and v2).
//!
//! # Authentication
//!
//! Supports three authentication methods, selected via the `auth` query parameter:
//!
//! - Token (default) -- uses `VAULT_TOKEN` environment variable or `~/.vault-token` file
//! - AppRole (`?auth=approle`) -- uses `VAULT_ROLE_ID` and `VAULT_SECRET_ID` environment
//!   variables to perform an AppRole login
//! - JWT/OIDC (`?auth=jwt`) -- exchanges a workload-identity token for a Vault
//!   token, so CI authenticates as itself instead of holding a long-lived
//!   credential. The JWT comes from `VAULT_JWT`, from the file named by
//!   `VAULT_JWT_PATH` (a Kubernetes projected service account token), or is
//!   minted from the GitHub Actions OIDC endpoint with `?jwt=github-actions`.
//!
//! # URI Format
//!
//! `vault://[namespace@]host[:port][/mount][?key=value&...]`
//! `openbao://[namespace@]host[:port][/mount][?key=value&...]`
//!
//! Query parameters:
//! - `auth` -- authentication method: `token` (default), `approle` or `jwt`
//! - `auth_mount` -- auth backend mount path (default: the method's own name)
//! - `role` -- Vault role for `auth=jwt` (also read from `VAULT_ROLE`)
//! - `jwt` -- where the JWT comes from: `env` (default) or `github-actions`
//! - `audience` -- audience to request when minting a workload-identity token
//! - `kv` -- KV engine version: `1` or `2` (default)
//! - `layout` -- storage layout: `secretspec` (default) or `flat`
//! - `tls` -- enable TLS: `true` (default) or `false`
//!
//! # Examples
//!
//! - `vault://vault.example.com:8200/secret` -- KV v2, token auth
//! - `vault://vault.example.com:8200/secret?auth=approle` -- AppRole auth
//! - `vault://vault.example.com:8200/secret?auth=jwt&role=ci` -- JWT from `VAULT_JWT`
//! - `openbao://bao.internal:8200/kv?auth=jwt&auth_mount=github-actions&role=ci&jwt=github-actions`
//!   -- GitHub Actions OIDC into a JWT backend mounted at `github-actions`
//! - `vault://ns1@vault.example.com:8200/secret` -- with Vault namespace
//! - `openbao://bao.internal:8200/secret` -- OpenBao server
//! - `vault://127.0.0.1:8200/secret?kv=1` -- KV v1 engine
//! - `vault://vault.example.com:8200/secret?tls=false` -- disable TLS (dev mode)
//!
//! When no host is provided, falls back to the `VAULT_ADDR` environment variable.
//!
//! # Secret Naming
//!
//! Secrets are stored at the path: `secretspec/{project}/{profile}/{key}`
//! Each secret is stored as a KV entry with a `value` field.
//!
//! With `layout=flat`, the provider reads and writes a single KV document whose
//! fields are secret names. If the URI path includes segments after the mount,
//! those segments are the document path:
//!
//! `openbao://vault.example.com:8200/kv/team/app/dev?layout=flat`
//!
//! In this example, secret `DATABASE_URL` is read from the `DATABASE_URL` field
//! in KV v2 document `kv/data/team/app/dev`.
//!
//! # Example
//!
//! ```bash
//! # Set a secret
//! secretspec set DATABASE_URL --provider vault://vault.example.com:8200/secret
//!
//! # Use with a namespace
//! secretspec check --provider vault://team-a@vault.example.com:8200/secret
//! ```

use super::{Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use reqwest::header::{HeaderMap, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// KV secrets engine version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KvVersion {
    /// KV version 1 (no versioning).
    V1,
    /// KV version 2 (versioned, default).
    V2,
}

impl Default for KvVersion {
    fn default() -> Self {
        KvVersion::V2
    }
}

/// Authentication method for the Vault / OpenBao provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuthMethod {
    /// Token-based authentication via `VAULT_TOKEN` or `~/.vault-token`.
    #[default]
    Token,
    /// AppRole authentication via `VAULT_ROLE_ID` and `VAULT_SECRET_ID`.
    AppRole,
    /// JWT/OIDC authentication -- exchanges a workload-identity token for a
    /// Vault token. This is what lets CI authenticate as itself rather than
    /// holding a long-lived credential: GitHub Actions, GitLab CI and
    /// Kubernetes service accounts all present a signed JWT that Vault can bind
    /// to a role by its claims.
    Jwt,
}

/// Storage layout for Vault / OpenBao secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum VaultLayout {
    /// Store one KV entry per SecretSpec key at `secretspec/{project}/{profile}/{key}`.
    #[default]
    SecretSpec,
    /// Store all keys as fields in one KV document.
    Flat,
}

/// Configuration for the Vault / OpenBao provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// The Vault server endpoint URL (e.g., `https://vault.example.com:8200`).
    pub endpoint: String,
    /// The KV secrets engine mount path (default: `secret`).
    pub mount: String,
    /// Optional path prefix or flat document path under the KV mount.
    pub path: Option<String>,
    /// The KV engine version (default: V2).
    pub kv_version: KvVersion,
    /// Optional Vault namespace.
    pub namespace: Option<String>,
    /// Authentication method (default: Token).
    pub auth: AuthMethod,
    /// Auth backend mount path. Defaults to the method's own name, but a Vault
    /// admin can mount the same backend anywhere -- an estate that mounts JWT
    /// auth at `github-actions` logs in at `/v1/auth/github-actions/login`, and
    /// without this the provider could only ever talk to a default mount.
    pub auth_mount: Option<String>,
    /// Vault role to authenticate against, for methods that take one.
    pub role: Option<String>,
    /// Audience to request when minting a workload-identity token.
    pub audience: Option<String>,
    /// Where to obtain the JWT from, when `auth = Jwt`.
    pub jwt_source: JwtSource,
    /// Storage layout (default: one KV entry per SecretSpec key).
    pub layout: VaultLayout,
}

/// Where the JWT for `auth=jwt` comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum JwtSource {
    /// `VAULT_JWT`, or the file named by `VAULT_JWT_PATH` -- which is how a
    /// Kubernetes workload reaches its projected service account token.
    #[default]
    Environment,
    /// Mint one from the GitHub Actions OIDC endpoint. Opt-in via
    /// `?jwt=github-actions` rather than sniffed from the environment, so the
    /// provider never silently reaches for a token the caller did not ask for.
    GithubActions,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://127.0.0.1:8200".to_string(),
            mount: "secret".to_string(),
            path: None,
            kv_version: KvVersion::default(),
            namespace: None,
            auth: AuthMethod::default(),
            auth_mount: None,
            role: None,
            audience: None,
            jwt_source: JwtSource::default(),
            layout: VaultLayout::default(),
        }
    }
}

impl TryFrom<&ProviderUrl> for VaultConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        let scheme = url.scheme();
        if scheme != "vault" && scheme != "openbao" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for vault provider. Expected 'vault' or 'openbao'.",
                scheme
            )));
        }

        // Determine TLS setting from query parameter (default: true)
        let use_tls = url
            .query_pairs()
            .find(|(k, _)| k == "tls")
            .map(|(_, v)| v != "false" && v != "0")
            .unwrap_or(true);

        let http_scheme = if use_tls { "https" } else { "http" };

        // Resolve endpoint: from URI host or VAULT_ADDR env var
        let endpoint = match url.host().filter(|s| !s.is_empty()) {
            Some(host) => {
                if let Some(port) = url.port() {
                    format!("{}://{}:{}", http_scheme, host, port)
                } else {
                    format!("{}://{}", http_scheme, host)
                }
            }
            None => std::env::var("VAULT_ADDR")
                .ok()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    SecretSpecError::ProviderOperationFailed(
                        "No Vault address provided. Either specify a host in the URI \
                         (e.g., vault://vault.example.com:8200) or set the VAULT_ADDR \
                         environment variable."
                            .to_string(),
                    )
                })?,
        };

        // Mount path from URL path (strip leading slash, default to "secret").
        // Additional path segments are used by `layout=flat` as the KV document
        // path, allowing one existing KV document to expose many SecretSpec keys.
        let path = url.path();
        let mut path_segments = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty());
        let mount = path_segments.next().unwrap_or("secret").to_string();
        let path = {
            let remaining = path_segments.collect::<Vec<_>>().join("/");
            if remaining.is_empty() {
                None
            } else {
                Some(remaining)
            }
        };

        // KV version from query parameter (default: V2)
        let kv_version = url
            .query_pairs()
            .find(|(k, _)| k == "kv")
            .map(|(_, v)| match v.as_ref() {
                "1" | "v1" => KvVersion::V1,
                _ => KvVersion::V2,
            })
            .unwrap_or_default();

        // Namespace from URI username or VAULT_NAMESPACE env var
        let namespace = {
            let username = url.username();
            if !username.is_empty() {
                Some(username)
            } else {
                std::env::var("VAULT_NAMESPACE")
                    .ok()
                    .filter(|s| !s.is_empty())
            }
        };

        let auth = url
            .query_pairs()
            .find(|(k, _)| k == "auth")
            .map(|(_, v)| match v.as_ref() {
                "approle" => Ok(AuthMethod::AppRole),
                "token" => Ok(AuthMethod::Token),
                "jwt" | "oidc" => Ok(AuthMethod::Jwt),
                other => Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Unknown auth method '{}'. Expected 'token', 'approle' or 'jwt'.",
                    other
                ))),
            })
            .transpose()?
            .unwrap_or_default();

        let query_value = |key: &str| {
            url.query_pairs()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.into_owned())
                .filter(|s| !s.is_empty())
        };

        let auth_mount = query_value("auth_mount");
        // Env fallbacks so the same provider URI works unchanged across
        // environments that bind different roles.
        let role = query_value("role")
            .or_else(|| std::env::var("VAULT_ROLE").ok().filter(|s| !s.is_empty()));
        let audience = query_value("audience");

        let jwt_source = url
            .query_pairs()
            .find(|(k, _)| k == "jwt")
            .map(|(_, v)| match v.as_ref() {
                "env" | "environment" => Ok(JwtSource::Environment),
                "github-actions" | "github" => Ok(JwtSource::GithubActions),
                other => Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Unknown jwt source '{}'. Expected 'env' or 'github-actions'.",
                    other
                ))),
            })
            .transpose()?
            .unwrap_or_default();

        let layout = url
            .query_pairs()
            .find(|(k, _)| k == "layout")
            .map(|(_, v)| match v.as_ref() {
                "secretspec" | "default" => Ok(VaultLayout::SecretSpec),
                "flat" => Ok(VaultLayout::Flat),
                other => Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Unknown Vault layout '{}'. Expected 'secretspec' or 'flat'.",
                    other
                ))),
            })
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            endpoint,
            mount,
            path,
            kv_version,
            namespace,
            auth,
            auth_mount,
            role,
            audience,
            jwt_source,
            layout,
        })
    }
}

/// HashiCorp Vault / OpenBao provider.
///
/// Stores and retrieves secrets from a Vault or OpenBao server using the
/// KV secrets engine (v1 or v2) with token-based authentication.
pub struct VaultProvider {
    config: VaultConfig,
}

crate::register_provider! {
    struct: VaultProvider,
    config: VaultConfig,
    name: "vault",
    description: "HashiCorp Vault / OpenBao secret management",
    schemes: ["vault", "openbao"],
    examples: ["vault://vault.example.com:8200/secret", "openbao://bao.internal:8200/secret"],
}

impl VaultProvider {
    /// Creates a new VaultProvider with the given configuration.
    pub fn new(config: VaultConfig) -> Self {
        Self { config }
    }

    /// Formats the SecretSpec one-entry-per-key path within the KV engine.
    fn format_secretspec_path(project: &str, profile: &str, key: &str) -> Result<String> {
        if project.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "project cannot be empty".to_string(),
            ));
        }
        if profile.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "profile cannot be empty".to_string(),
            ));
        }
        if key.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "key cannot be empty".to_string(),
            ));
        }

        Ok(format!("secretspec/{}/{}/{}", project, profile, key))
    }

    /// Formats the flat-layout KV document path.
    fn format_flat_path(&self, project: &str, profile: &str) -> Result<String> {
        if let Some(path) = &self.config.path {
            return Ok(path.clone());
        }
        if project.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "project cannot be empty".to_string(),
            ));
        }
        if profile.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "profile cannot be empty".to_string(),
            ));
        }

        Ok(format!("secretspec/{}/{}", project, profile))
    }

    /// Resolves the Vault token using the configured authentication method.
    ///
    /// Async, and awaited rather than blocked on, because the callers are
    /// already inside a runtime: `get`/`set` block on their async bodies, and
    /// blocking a second time from in there calls `block_in_place`, which
    /// panics on the current-thread runtime the outer `block_on` builds. That
    /// made every non-token auth method unusable — AppRole included, before
    /// JWT existed.
    async fn resolve_token(&self) -> Result<SecretString> {
        match self.config.auth {
            AuthMethod::Token => Self::resolve_token_auth(),
            AuthMethod::AppRole => self.resolve_approle_auth().await,
            AuthMethod::Jwt => self.resolve_jwt_auth().await,
        }
    }

    /// Login endpoint for the configured auth method, honouring a custom mount.
    fn auth_login_url(&self, default_mount: &str) -> String {
        let mount = self
            .config
            .auth_mount
            .as_deref()
            .unwrap_or(default_mount)
            .trim_matches('/');
        format!("{}/v1/auth/{}/login", self.config.endpoint, mount)
    }

    /// Posts a login payload and extracts `auth.client_token`.
    ///
    /// Shared by AppRole and JWT: both are "POST credentials, get a token", and
    /// the error paths are the part worth having in one place -- a claim
    /// mismatch comes back as an HTTP error whose body is the only thing that
    /// says which claim, so it must reach the caller rather than be flattened
    /// into "login failed".
    async fn login(
        &self,
        url: &str,
        method: &str,
        body: serde_json::Value,
    ) -> Result<SecretString> {
        let client = reqwest::Client::new();
        let mut request = client.post(url).json(&body);
        if let Some(namespace) = &self.config.namespace {
            request = request.header("X-Vault-Namespace", namespace);
        }

        let response = request.send().await.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!("{} login failed: {}", method, e))
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} login to {} returned HTTP {}: {}",
                method, url, status, body
            )));
        }

        let resp: serde_json::Value = response.json().await.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to parse {} login response: {}",
                method, e
            ))
        })?;

        let token = resp["auth"]["client_token"].as_str().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "{} login response missing auth.client_token",
                method
            ))
        })?;

        Ok(SecretString::new(token.to_string().into()))
    }

    /// Authenticates via JWT/OIDC and returns a client token.
    async fn resolve_jwt_auth(&self) -> Result<SecretString> {
        let role = self.config.role.clone().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "JWT authentication needs a Vault role. Add `?role=<name>` to the \
                 provider URI or set VAULT_ROLE."
                    .to_string(),
            )
        })?;

        let jwt = match self.config.jwt_source {
            JwtSource::Environment => Self::jwt_from_environment()?,
            JwtSource::GithubActions => self.jwt_from_github_actions().await?,
        };

        let body = serde_json::json!({ "role": role, "jwt": jwt.expose_secret() });
        self.login(&self.auth_login_url("jwt"), "JWT", body).await
    }

    /// Reads the JWT from `VAULT_JWT`, or the file at `VAULT_JWT_PATH`.
    ///
    /// The file form is how a Kubernetes workload presents its projected
    /// service account token, which is a path rather than a value.
    fn jwt_from_environment() -> Result<SecretString> {
        if let Some(jwt) = std::env::var("VAULT_JWT").ok().filter(|s| !s.is_empty()) {
            return Ok(SecretString::new(jwt.into()));
        }

        if let Some(path) = std::env::var("VAULT_JWT_PATH")
            .ok()
            .filter(|s| !s.is_empty())
        {
            let jwt = std::fs::read_to_string(&path).map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to read VAULT_JWT_PATH ({}): {}",
                    path, e
                ))
            })?;
            let jwt = jwt.trim();
            if !jwt.is_empty() {
                return Ok(SecretString::new(jwt.to_string().into()));
            }
        }

        Err(SecretSpecError::ProviderOperationFailed(
            "No JWT found for Vault authentication. Set VAULT_JWT, or VAULT_JWT_PATH \
             to a file containing one (a Kubernetes projected service account token, \
             for example), or use `?jwt=github-actions` to mint one."
                .to_string(),
        ))
    }

    /// Mints a workload-identity token from the GitHub Actions OIDC endpoint.
    ///
    /// Requires `permissions: id-token: write` on the job; without it GitHub
    /// sets neither variable and the token simply is not available, so say that
    /// rather than failing on an empty URL.
    async fn jwt_from_github_actions(&self) -> Result<SecretString> {
        let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "ACTIONS_ID_TOKEN_REQUEST_URL is not set. `?jwt=github-actions` \
                     needs a job with `permissions: id-token: write`."
                        .to_string(),
                )
            })?;
        let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN is not set. `?jwt=github-actions` \
                     needs a job with `permissions: id-token: write`."
                        .to_string(),
                )
            })?;

        let client = reqwest::Client::new();
        // `.query` appends to the api-version already on the request URL, and
        // encodes the audience -- which is a URL itself, so hand-concatenating
        // it is how you get a silently truncated claim.
        let mut request = client
            .get(&request_url)
            .header("Authorization", format!("bearer {}", request_token));
        if let Some(audience) = &self.config.audience {
            request = request.query(&[("audience", audience)]);
        }

        let response = request.send().await.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to request a GitHub Actions OIDC token: {}",
                e
            ))
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "GitHub Actions OIDC request returned HTTP {}: {}",
                status, body
            )));
        }

        let resp: serde_json::Value = response.json().await.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to parse the GitHub Actions OIDC response: {}",
                e
            ))
        })?;

        let jwt = resp["value"].as_str().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "GitHub Actions OIDC response missing `value`".to_string(),
            )
        })?;

        Ok(SecretString::new(jwt.to_string().into()))
    }

    /// Resolves a token via static token sources.
    fn resolve_token_auth() -> Result<SecretString> {
        if let Ok(token) = std::env::var("VAULT_TOKEN") {
            if !token.is_empty() {
                return Ok(SecretString::new(token.into()));
            }
        }

        let token_path = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(|home| std::path::PathBuf::from(home).join(".vault-token"));

        if let Some(path) = token_path {
            if let Ok(token) = std::fs::read_to_string(&path) {
                let token = token.trim();
                if !token.is_empty() {
                    return Ok(SecretString::new(token.to_string().into()));
                }
            }
        }

        Err(SecretSpecError::ProviderOperationFailed(
            "No Vault token found. Set the VAULT_TOKEN environment variable \
             or create a ~/.vault-token file."
                .to_string(),
        ))
    }

    /// Authenticates via AppRole and returns a client token.
    async fn resolve_approle_auth(&self) -> Result<SecretString> {
        let role_id = std::env::var("VAULT_ROLE_ID").map_err(|_| {
            SecretSpecError::ProviderOperationFailed(
                "VAULT_ROLE_ID environment variable is required for AppRole authentication."
                    .to_string(),
            )
        })?;

        let secret_id = std::env::var("VAULT_SECRET_ID").map_err(|_| {
            SecretSpecError::ProviderOperationFailed(
                "VAULT_SECRET_ID environment variable is required for AppRole authentication."
                    .to_string(),
            )
        })?;

        let body = serde_json::json!({
            "role_id": role_id,
            "secret_id": secret_id,
        });

        self.login(&self.auth_login_url("approle"), "AppRole", body)
            .await
    }

    /// Builds the common HTTP headers for Vault API requests.
    fn build_headers(token: &SecretString, namespace: &Option<String>) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Vault-Token",
            HeaderValue::from_str(token.expose_secret()).map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!("Invalid token value: {}", e))
            })?,
        );
        if let Some(ns) = namespace {
            headers.insert(
                "X-Vault-Namespace",
                HeaderValue::from_str(ns).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Invalid namespace value: {}",
                        e
                    ))
                })?,
            );
        }
        Ok(headers)
    }

    /// Builds the full Vault API URL for a secret path.
    fn build_url(&self, secret_path: &str) -> String {
        match self.config.kv_version {
            KvVersion::V2 => format!(
                "{}/v1/{}/data/{}",
                self.config.endpoint, self.config.mount, secret_path
            ),
            KvVersion::V1 => format!(
                "{}/v1/{}/{}",
                self.config.endpoint, self.config.mount, secret_path
            ),
        }
    }

    fn extract_kv_data<'a>(
        &self,
        body: &'a serde_json::Value,
    ) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
        match self.config.kv_version {
            KvVersion::V2 => body
                .get("data")
                .and_then(|d| d.get("data"))
                .and_then(|d| d.as_object()),
            KvVersion::V1 => body.get("data").and_then(|d| d.as_object()),
        }
    }

    /// Retrieves a secret from Vault asynchronously.
    async fn get_secret_async(
        &self,
        project: &str,
        key: &str,
        profile: &str,
    ) -> Result<Option<SecretString>> {
        let secret_path = match self.config.layout {
            VaultLayout::SecretSpec => Self::format_secretspec_path(project, profile, key)?,
            VaultLayout::Flat => self.format_flat_path(project, profile)?,
        };
        let url = self.build_url(&secret_path);
        let token = self.resolve_token().await?;
        let headers = Self::build_headers(&token, &self.config.namespace)?;

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to connect to Vault at {}: {}",
                    self.config.endpoint, e
                ))
            })?;

        match response.status().as_u16() {
            200 => {
                let body: serde_json::Value = response.json().await.map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse Vault response: {}",
                        e
                    ))
                })?;

                let value = match self.config.layout {
                    VaultLayout::SecretSpec => self
                        .extract_kv_data(&body)
                        .and_then(|d| d.get("value"))
                        .and_then(|v| v.as_str()),
                    VaultLayout::Flat => self
                        .extract_kv_data(&body)
                        .and_then(|d| d.get(key))
                        .and_then(|v| v.as_str()),
                };

                Ok(value.map(|v| SecretString::new(v.to_string().into())))
            }
            404 => Ok(None),
            403 => Err(SecretSpecError::ProviderOperationFailed(
                "Vault authentication failed (403 Forbidden). \
                 Check your VAULT_TOKEN and ensure it has the required permissions."
                    .to_string(),
            )),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Vault returned HTTP {}: {}",
                    status, body
                )))
            }
        }
    }

    /// Writes a secret to Vault asynchronously.
    async fn set_secret_async(
        &self,
        project: &str,
        key: &str,
        value: &SecretString,
        profile: &str,
    ) -> Result<()> {
        let secret_path = match self.config.layout {
            VaultLayout::SecretSpec => Self::format_secretspec_path(project, profile, key)?,
            VaultLayout::Flat => self.format_flat_path(project, profile)?,
        };
        let url = self.build_url(&secret_path);
        let token = self.resolve_token().await?;
        let headers = Self::build_headers(&token, &self.config.namespace)?;

        let body = match self.config.layout {
            VaultLayout::SecretSpec => match self.config.kv_version {
                KvVersion::V2 => {
                    serde_json::json!({ "data": { "value": value.expose_secret() } })
                }
                KvVersion::V1 => {
                    serde_json::json!({ "value": value.expose_secret() })
                }
            },
            VaultLayout::Flat => {
                let mut data = self.read_flat_document(&url, &headers).await?;
                data.insert(
                    key.to_string(),
                    serde_json::Value::String(value.expose_secret().to_string()),
                );
                match self.config.kv_version {
                    KvVersion::V2 => serde_json::json!({ "data": data }),
                    KvVersion::V1 => serde_json::Value::Object(data),
                }
            }
        };

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to connect to Vault at {}: {}",
                    self.config.endpoint, e
                ))
            })?;

        match response.status().as_u16() {
            200 | 204 => Ok(()),
            403 => Err(SecretSpecError::ProviderOperationFailed(
                "Vault authentication failed (403 Forbidden). \
                 Check your VAULT_TOKEN and ensure it has write permissions."
                    .to_string(),
            )),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Vault returned HTTP {} while writing secret: {}",
                    status, body
                )))
            }
        }
    }

    async fn read_flat_document(
        &self,
        url: &str,
        headers: &HeaderMap,
    ) -> Result<serde_json::Map<String, serde_json::Value>> {
        let client = reqwest::Client::new();
        let response = client
            .get(url)
            .headers(headers.clone())
            .send()
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to connect to Vault at {}: {}",
                    self.config.endpoint, e
                ))
            })?;

        match response.status().as_u16() {
            200 => {
                let body: serde_json::Value = response.json().await.map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse Vault response: {}",
                        e
                    ))
                })?;
                Ok(self.extract_kv_data(&body).cloned().unwrap_or_default())
            }
            404 => Ok(serde_json::Map::new()),
            403 => Err(SecretSpecError::ProviderOperationFailed(
                "Vault authentication failed (403 Forbidden). \
                 Check your VAULT_TOKEN and ensure it has the required permissions."
                    .to_string(),
            )),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Vault returned HTTP {} while reading existing flat secret document: {}",
                    status, body
                )))
            }
        }
    }
}

impl Provider for VaultProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut uri = format!(
            "vault://{}",
            self.config
                .endpoint
                .trim_start_matches("https://")
                .trim_start_matches("http://")
        );
        if self.config.mount != "secret" || self.config.path.is_some() {
            uri.push('/');
            uri.push_str(&self.config.mount);
            if let Some(path) = &self.config.path {
                uri.push('/');
                uri.push_str(path);
            }
        }
        let mut query = Vec::new();
        if self.config.layout == VaultLayout::Flat {
            query.push("layout=flat");
        }
        if self.config.kv_version == KvVersion::V1 {
            query.push("kv=1");
        }
        if self.config.auth == AuthMethod::AppRole {
            query.push("auth=approle");
        }
        if !query.is_empty() {
            uri.push('?');
            uri.push_str(&query.join("&"));
        }
        uri
    }

    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        super::block_on(self.get_secret_async(project, key, profile))
    }

    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        super::block_on(self.set_secret_async(project, key, value, profile))
    }

    fn allows_set(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn provider_url(s: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(s).unwrap())
    }

    fn provider(s: &str) -> VaultProvider {
        VaultProvider {
            config: VaultConfig::try_from(&provider_url(s)).unwrap(),
        }
    }

    #[test]
    fn test_vault_auth_jwt_is_parsed() {
        let config = VaultConfig::try_from(&provider_url(
            "vault://vault.example.com:8200/secret?auth=jwt&role=ci",
        ))
        .unwrap();
        assert_eq!(config.auth, AuthMethod::Jwt);
        assert_eq!(config.role.as_deref(), Some("ci"));
        assert_eq!(config.jwt_source, JwtSource::Environment);
    }

    #[test]
    fn test_vault_auth_oidc_is_an_alias_for_jwt() {
        let config =
            VaultConfig::try_from(&provider_url("vault://vault.example.com:8200?auth=oidc"))
                .unwrap();
        assert_eq!(config.auth, AuthMethod::Jwt);
    }

    #[test]
    fn test_vault_unknown_auth_method_is_rejected() {
        let result = VaultConfig::try_from(&provider_url(
            "vault://vault.example.com:8200/secret?auth=kerberos",
        ));
        let err = result.unwrap_err().to_string();
        assert!(err.contains("kerberos"), "{}", err);
        assert!(err.contains("jwt"), "{}", err);
    }

    // An estate that mounts JWT auth somewhere other than `jwt` -- as red-wiz
    // does at `github-actions` -- is unreachable without this.
    #[test]
    fn test_vault_auth_mount_overrides_the_login_path() {
        let provider = provider(
            "vault://vault.example.com:8200/secret?auth=jwt&role=ci&auth_mount=github-actions",
        );
        assert_eq!(
            provider.auth_login_url("jwt"),
            "https://vault.example.com:8200/v1/auth/github-actions/login"
        );
    }

    #[test]
    fn test_vault_auth_mount_defaults_to_the_method_name() {
        let provider = provider("vault://vault.example.com:8200/secret?auth=jwt&role=ci");
        assert_eq!(
            provider.auth_login_url("jwt"),
            "https://vault.example.com:8200/v1/auth/jwt/login"
        );
        assert_eq!(
            provider.auth_login_url("approle"),
            "https://vault.example.com:8200/v1/auth/approle/login"
        );
    }

    #[test]
    fn test_vault_jwt_source_github_actions_is_opt_in() {
        let config = VaultConfig::try_from(&provider_url(
            "vault://vault.example.com:8200/secret?auth=jwt&role=ci&jwt=github-actions&audience=https%3A%2F%2Fgithub.com%2Fred-wiz",
        ))
        .unwrap();
        assert_eq!(config.jwt_source, JwtSource::GithubActions);
        assert_eq!(
            config.audience.as_deref(),
            Some("https://github.com/red-wiz")
        );
    }

    #[test]
    fn test_vault_unknown_jwt_source_is_rejected() {
        let result = VaultConfig::try_from(&provider_url(
            "vault://vault.example.com:8200/secret?auth=jwt&jwt=carrier-pigeon",
        ));
        assert!(result.is_err());
    }

    // Without a role the login body is malformed and Vault answers a generic
    // 400, so catch it here where the message can name the fix.
    #[test]
    fn test_vault_jwt_without_a_role_is_rejected() {
        let provider = provider("vault://vault.example.com:8200/secret?auth=jwt");
        let err = super::super::block_on(provider.resolve_jwt_auth())
            .unwrap_err()
            .to_string();
        assert!(err.contains("role"), "{}", err);
        assert!(err.contains("VAULT_ROLE"), "{}", err);
    }
}
