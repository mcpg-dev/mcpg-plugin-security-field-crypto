//! Field-level crypto ToolGate plugin (`dev.mcpg.tool-gate.field-crypto`).
//!
//! Encrypts named **argument** fields pre-dispatch and decrypts named **result**
//! fields post-dispatch with XChaCha20-Poly1305 (the same AEAD the gateway's
//! credential-cache / cluster-state encryption uses). Each field is sealed into
//! a self-describing string envelope `mcpgfc1:<base64url(nonce ‖ ciphertext)>`,
//! bound to its JSON Pointer path as AAD so a ciphertext can't be moved between
//! fields. The 32-byte key comes from operator config (populate via
//! `${env.X}`). Pure compute, no network. Fails closed on bad config; a result
//! field that fails to decrypt is denied (configurable).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use mcpg_glob::glob_match;
use mcpg_plugin_protocol::{GateDecision, PluginContext, PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::ffi::SyncToolGate;
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::Value;

const PLUGIN_ID: &str = "dev.mcpg.tool-gate.field-crypto";
/// Envelope marker for a sealed field value.
const ENVELOPE_PREFIX: &str = "mcpgfc1:";
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const DEFAULT_DENY_CODE: i32 = -32051;
const DEFAULT_DENY_HTTP_STATUS: u16 = 403;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldCryptoConfig {
    /// 32-byte AEAD key, hex-encoded (64 hex chars). Populate via `${env.X}`.
    key_hex: String,
    /// JSON Pointers (RFC 6901) to argument fields to encrypt pre-dispatch.
    #[serde(default)]
    encrypt_fields: Vec<String>,
    /// JSON Pointers to result fields to decrypt post-dispatch.
    #[serde(default)]
    decrypt_fields: Vec<String>,
    /// When a configured result field is present + sealed but fails to open
    /// (wrong key / tamper / AAD mismatch), deny the call (default) vs. leaving
    /// the field untouched.
    #[serde(default = "default_true")]
    fail_closed: bool,
    #[serde(default = "default_deny_code")]
    deny_code: i32,
    #[serde(default = "default_deny_http_status")]
    deny_http_status: u16,
    #[serde(default)]
    tools: Vec<String>,
    #[serde(default)]
    exclude_tools: Vec<String>,
    #[serde(default)]
    apply_to_non_tool_surfaces: bool,
}

fn default_true() -> bool {
    true
}
fn default_deny_code() -> i32 {
    DEFAULT_DENY_CODE
}
fn default_deny_http_status() -> u16 {
    DEFAULT_DENY_HTTP_STATUS
}

pub struct FieldCryptoPlugin {
    manifest: PluginManifest,
    cipher: XChaCha20Poly1305,
    encrypt_fields: Vec<String>,
    decrypt_fields: Vec<String>,
    fail_closed: bool,
    deny_code: i32,
    deny_http_status: u16,
    tools: Vec<String>,
    exclude_tools: Vec<String>,
    apply_to_non_tool_surfaces: bool,
}

impl FieldCryptoPlugin {
    /// SDK factory. Fails closed: a bad config or an invalid key panics
    /// (→ null handle → boot Err), the uniform tool-gate convention.
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg: FieldCryptoConfig = serde_json::from_str(config_json).unwrap_or_else(|err| {
            panic!("tool-gate-field-crypto: config JSON failed to parse: {err}")
        });

        let key_bytes = hex::decode(cfg.key_hex.trim()).unwrap_or_else(|err| {
            panic!("tool-gate-field-crypto: key_hex is not valid hex: {err}")
        });
        if key_bytes.len() != KEY_BYTES {
            panic!(
                "tool-gate-field-crypto: key must decode to {KEY_BYTES} bytes, got {}",
                key_bytes.len()
            );
        }
        if cfg.encrypt_fields.is_empty() && cfg.decrypt_fields.is_empty() {
            panic!(
                "tool-gate-field-crypto: at least one of encrypt_fields / decrypt_fields is required"
            );
        }
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));

        Self {
            manifest: firstparty_manifest! {
                id: PLUGIN_ID,
                name: "Field-Level Crypto Gate",
                class: ToolGate,
            },
            cipher,
            encrypt_fields: cfg.encrypt_fields,
            decrypt_fields: cfg.decrypt_fields,
            fail_closed: cfg.fail_closed,
            deny_code: cfg.deny_code,
            deny_http_status: cfg.deny_http_status,
            tools: cfg.tools,
            exclude_tools: cfg.exclude_tools,
            apply_to_non_tool_surfaces: cfg.apply_to_non_tool_surfaces,
        }
    }

    fn matches_tool(&self, tool_name: &str) -> bool {
        if self.exclude_tools.iter().any(|p| glob_match(p, tool_name)) {
            return false;
        }
        self.tools.is_empty() || self.tools.iter().any(|p| glob_match(p, tool_name))
    }

    fn in_scope(&self, ctx: &PluginContext) -> bool {
        (ctx.surface == "tool" || self.apply_to_non_tool_surfaces)
            && self.matches_tool(&ctx.tool_name)
    }

    /// Seal `plaintext` into the `mcpgfc1:` string envelope, binding `aad`
    /// (the field path) so the ciphertext can't be relocated to another field.
    fn seal(&self, plaintext: &str, aad: &[u8]) -> Result<String, String> {
        let mut nonce_bytes = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ct = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad,
                },
            )
            .map_err(|_| "encrypt failed".to_owned())?;
        let mut buf = Vec::with_capacity(NONCE_BYTES + ct.len());
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&ct);
        Ok(format!("{ENVELOPE_PREFIX}{}", B64URL.encode(&buf)))
    }

    /// Open a `mcpgfc1:` envelope produced by [`Self::seal`] with the same AAD.
    fn open(&self, envelope: &str, aad: &[u8]) -> Result<String, String> {
        let b64 = envelope
            .strip_prefix(ENVELOPE_PREFIX)
            .ok_or("not an envelope")?;
        let raw = B64URL
            .decode(b64.as_bytes())
            .map_err(|_| "invalid base64".to_owned())?;
        if raw.len() < NONCE_BYTES {
            return Err("envelope too short".to_owned());
        }
        let (nonce_bytes, ct) = raw.split_at(NONCE_BYTES);
        let nonce = XNonce::from_slice(nonce_bytes);
        let pt = self
            .cipher
            .decrypt(nonce, Payload { msg: ct, aad })
            .map_err(|_| "authentication failed".to_owned())?;
        String::from_utf8(pt).map_err(|_| "decrypted value is not UTF-8".to_owned())
    }

    fn deny(&self, message: String) -> GateDecision {
        GateDecision::Deny {
            http_status: self.deny_http_status,
            code: self.deny_code,
            message,
            error_data: None,
        }
    }
}

impl SyncToolGate for FieldCryptoPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        _meta: Option<&Value>,
        _config: &Value,
    ) -> GateDecision {
        if self.encrypt_fields.is_empty() || !self.in_scope(ctx) {
            return GateDecision::allow();
        }
        let mut out = arguments.clone();
        let mut modified = false;
        for ptr in &self.encrypt_fields {
            let Some(slot) = out.pointer_mut(ptr) else {
                continue;
            };
            // A non-string configured for encryption matched no arm and was
            // silently forwarded in the clear. The caller controls the JSON
            // type, so that is a client-selectable opt-out of the gate.
            let Value::String(s) = slot else {
                return self.deny(format!(
                    "field-crypto: {ptr} is configured for encryption but is not a string; \
                     refusing to forward it unsealed"
                ));
            };
            {
                // Idempotent: never double-seal an already-sealed value — but
                // the prefix is client-visible, so it is not proof of sealing.
                // Only a value that actually authenticates under this field's
                // AAD may be passed through; anything else wearing the prefix
                // is the caller opting out of encryption.
                if s.starts_with(ENVELOPE_PREFIX) {
                    if self.open(s, ptr.as_bytes()).is_ok() {
                        continue;
                    }
                    return self.deny(format!(
                        "field-crypto: {ptr} carries the envelope prefix but does not \
                         authenticate under this field; refusing it"
                    ));
                }
                match self.seal(s, ptr.as_bytes()) {
                    Ok(env) => {
                        *slot = Value::String(env);
                        modified = true;
                    }
                    Err(e) => {
                        return self.deny(format!("field-crypto: encrypt of {ptr} failed: {e}"));
                    }
                }
            }
        }
        if modified {
            GateDecision::Allow {
                modified_arguments: Some(out),
                modified_result: None,
                metadata: None,
            }
        } else {
            GateDecision::allow()
        }
    }

    fn evaluate_post(
        &self,
        ctx: &PluginContext,
        _arguments: &Value,
        result: &Value,
        _duration_ms: u64,
        _config: &Value,
    ) -> GateDecision {
        if self.decrypt_fields.is_empty() || !self.in_scope(ctx) {
            return GateDecision::allow();
        }
        let mut out = result.clone();
        let mut modified = false;
        for ptr in &self.decrypt_fields {
            if let Some(slot) = out.pointer_mut(ptr)
                && let Value::String(s) = slot
            {
                if !s.starts_with(ENVELOPE_PREFIX) {
                    continue; // not sealed — leave plaintext as-is
                }
                match self.open(s, ptr.as_bytes()) {
                    Ok(pt) => {
                        *slot = Value::String(pt);
                        modified = true;
                    }
                    Err(e) if self.fail_closed => {
                        return self.deny(format!("field-crypto: decrypt of {ptr} failed: {e}"));
                    }
                    Err(_) => { /* tolerate: leave the sealed value untouched */ }
                }
            }
        }
        if modified {
            GateDecision::Allow {
                modified_arguments: None,
                modified_result: Some(out),
                metadata: None,
            }
        } else {
            GateDecision::allow()
        }
    }
}

mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.tool-gate.field-crypto",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: FieldCryptoPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| FieldCryptoPlugin::from_config_json(cfg),
        },
    ],
}

#[cfg(test)]
mod tests;
