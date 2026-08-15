use mcpg_plugin_protocol::{GateDecision, PluginContext, PluginIdentity};
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde_json::{Value, json};

use super::{FieldCryptoPlugin, PLUGIN_ID};

const KEY_A: &str = "abababababababababababababababababababababababababababababababab"; // 32 bytes
const KEY_B: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

fn ctx(tool: &str, surface: &str) -> PluginContext {
    PluginContext {
        request_id: "t".into(),
        session_id: None,
        tool_name: tool.into(),
        surface: surface.into(),
        identity: PluginIdentity {
            kind: "anonymous".into(),
            trust_level: "unauthenticated".into(),
            subject_id: None,
            auth_provider: None,
            issuer: None,
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: Default::default(),
        },
        transport: "http".into(),
    }
}

fn build(cfg: Value) -> FieldCryptoPlugin {
    FieldCryptoPlugin::from_config_json(&cfg.to_string())
}

fn pre(p: &FieldCryptoPlugin, args: Value) -> GateDecision {
    p.evaluate_pre(&ctx("t", "tool"), &args, None, &json!({}))
}
fn post(p: &FieldCryptoPlugin, result: Value) -> GateDecision {
    p.evaluate_post(&ctx("t", "tool"), &json!({}), &result, 1, &json!({}))
}

fn modified_args(d: GateDecision) -> Value {
    match d {
        GateDecision::Allow {
            modified_arguments: Some(v),
            ..
        } => v,
        other => panic!("expected Allow w/ modified_arguments, got {other:?}"),
    }
}
fn modified_result(d: GateDecision) -> Value {
    match d {
        GateDecision::Allow {
            modified_result: Some(v),
            ..
        } => v,
        other => panic!("expected Allow w/ modified_result, got {other:?}"),
    }
}

#[test]
fn manifest_is_correct() {
    use mcpg_plugin_protocol::PluginClass;
    let p = build(json!({ "key_hex": KEY_A, "encrypt_fields": ["/s"] }));
    let m = SyncToolGate::manifest(&p);
    assert_eq!(m.id, PLUGIN_ID);
    assert_eq!(m.plugin_class, PluginClass::ToolGate);
    assert!(m.required_capabilities.is_empty());
}

#[test]
fn encrypt_then_decrypt_round_trip() {
    let p = build(
        json!({ "key_hex": KEY_A, "encrypt_fields": ["/secret"], "decrypt_fields": ["/secret"] }),
    );
    let enc_args = modified_args(pre(&p, json!({ "secret": "hunter2", "keep": 1 })));
    let enc = enc_args["secret"].as_str().unwrap().to_owned();
    assert!(enc.starts_with("mcpgfc1:"), "{enc}");
    assert_eq!(enc_args["keep"], json!(1));
    let dec = modified_result(post(&p, json!({ "secret": enc })));
    assert_eq!(dec["secret"], json!("hunter2"));
}

#[test]
fn ciphertext_differs_each_call() {
    let p = build(json!({ "key_hex": KEY_A, "encrypt_fields": ["/s"] }));
    let a = modified_args(pre(&p, json!({ "s": "x" })))["s"]
        .as_str()
        .unwrap()
        .to_owned();
    let b = modified_args(pre(&p, json!({ "s": "x" })))["s"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(a, b, "random nonce should make ciphertexts differ");
}

#[test]
fn tamper_fails_closed() {
    let p = build(json!({ "key_hex": KEY_A, "encrypt_fields": ["/s"], "decrypt_fields": ["/s"] }));
    let enc = modified_args(pre(&p, json!({ "s": "secret" })))["s"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut bad = enc.clone();
    // Flip the last base64 char to a guaranteed-different one (avoid a no-op
    // tamper when the original char already equals the replacement).
    let last = bad.pop().unwrap();
    bad.push(if last == 'A' { 'B' } else { 'A' });
    assert!(matches!(
        post(&p, json!({ "s": bad })),
        GateDecision::Deny { .. }
    ));
}

#[test]
fn wrong_key_fails() {
    let enc = {
        let pa = build(json!({ "key_hex": KEY_A, "encrypt_fields": ["/s"] }));
        modified_args(pre(&pa, json!({ "s": "secret" })))["s"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let pb = build(json!({ "key_hex": KEY_B, "decrypt_fields": ["/s"] }));
    assert!(matches!(
        post(&pb, json!({ "s": enc })),
        GateDecision::Deny { .. }
    ));
}

#[test]
fn aad_binding_prevents_field_move() {
    let pa = build(json!({ "key_hex": KEY_A, "encrypt_fields": ["/a"] }));
    let enc = modified_args(pre(&pa, json!({ "a": "secret" })))["a"]
        .as_str()
        .unwrap()
        .to_owned();
    // Same key, but the ciphertext was sealed for path "/a"; opening at "/b" must fail.
    let pb = build(json!({ "key_hex": KEY_A, "decrypt_fields": ["/b"] }));
    assert!(matches!(
        post(&pb, json!({ "b": enc })),
        GateDecision::Deny { .. }
    ));
}

/// A field the operator configured for encryption must never travel in the
/// clear. The JSON type is the caller's choice, so silently skipping a
/// non-string was a client-selectable opt-out of the gate.
#[test]
fn non_string_field_is_denied_rather_than_forwarded_in_the_clear() {
    let p = build(json!({ "key_hex": KEY_A, "encrypt_fields": ["/n"] }));
    for value in [json!(5), json!(true), json!([1, 2]), json!({"k": "v"})] {
        assert!(
            matches!(pre(&p, json!({ "n": value })), GateDecision::Deny { .. }),
            "non-string must be denied, got a pass-through"
        );
    }
}

/// The `mcpgfc1:` prefix is visible to the caller, so it is not proof of
/// sealing — only a value that authenticates under this field's AAD may skip
/// re-encryption.
#[test]
fn forged_envelope_prefix_is_denied() {
    let p = build(json!({ "key_hex": KEY_A, "encrypt_fields": ["/a"] }));
    assert!(matches!(
        pre(&p, json!({ "a": "mcpgfc1:not-a-real-envelope" })),
        GateDecision::Deny { .. }
    ));
}

#[test]
fn genuinely_sealed_field_passes_through_unchanged() {
    let p = build(json!({ "key_hex": KEY_A, "encrypt_fields": ["/a"] }));
    // Seal once, then re-run: the second pass must recognise it and skip.
    let GateDecision::Allow {
        modified_arguments: Some(sealed),
        ..
    } = pre(&p, json!({ "a": "secret" }))
    else {
        panic!("first pass must seal");
    };
    assert!(matches!(
        pre(&p, sealed),
        GateDecision::Allow {
            modified_arguments: None,
            ..
        }
    ));
}

#[test]
fn absent_field_is_noop() {
    let p = build(json!({ "key_hex": KEY_A, "encrypt_fields": ["/missing"] }));
    assert!(matches!(
        pre(&p, json!({ "other": "x" })),
        GateDecision::Allow {
            modified_arguments: None,
            ..
        }
    ));
}

#[test]
fn already_encrypted_is_not_resealed() {
    let p = build(json!({ "key_hex": KEY_A, "encrypt_fields": ["/s"] }));
    let enc = modified_args(pre(&p, json!({ "s": "x" })))["s"]
        .as_str()
        .unwrap()
        .to_owned();
    // Re-running pre over the already-sealed value makes no change.
    assert!(matches!(
        pre(&p, json!({ "s": enc })),
        GateDecision::Allow {
            modified_arguments: None,
            ..
        }
    ));
}

#[test]
fn fail_open_leaves_undecryptable_field() {
    let p = build(json!({ "key_hex": KEY_A, "decrypt_fields": ["/s"], "fail_closed": false }));
    // Sealed-looking but garbage → tolerated, no modification, allowed.
    assert!(matches!(
        post(&p, json!({ "s": "mcpgfc1:not-real" })),
        GateDecision::Allow {
            modified_result: None,
            ..
        }
    ));
}

#[test]
fn plaintext_result_field_passes_through() {
    let p = build(json!({ "key_hex": KEY_A, "decrypt_fields": ["/s"] }));
    // Not sealed (no prefix) → left as-is, allowed.
    assert!(matches!(
        post(&p, json!({ "s": "plain value" })),
        GateDecision::Allow {
            modified_result: None,
            ..
        }
    ));
}

#[test]
fn tool_filtering_scopes_encryption() {
    let p = build(json!({ "key_hex": KEY_A, "encrypt_fields": ["/s"], "tools": ["allowed.*"] }));
    assert!(matches!(
        p.evaluate_pre(
            &ctx("other.x", "tool"),
            &json!({ "s": "x" }),
            None,
            &json!({})
        ),
        GateDecision::Allow {
            modified_arguments: None,
            ..
        }
    ));
    assert!(matches!(
        p.evaluate_pre(
            &ctx("allowed.y", "tool"),
            &json!({ "s": "x" }),
            None,
            &json!({})
        ),
        GateDecision::Allow {
            modified_arguments: Some(_),
            ..
        }
    ));
}

#[test]
fn non_tool_surface_skipped_unless_opted_in() {
    let p = build(json!({ "key_hex": KEY_A, "encrypt_fields": ["/s"] }));
    assert!(matches!(
        p.evaluate_pre(
            &ctx("t", "resource"),
            &json!({ "s": "x" }),
            None,
            &json!({})
        ),
        GateDecision::Allow {
            modified_arguments: None,
            ..
        }
    ));
}

#[test]
#[should_panic(expected = "config JSON failed to parse")]
fn malformed_config_panics() {
    FieldCryptoPlugin::from_config_json("{ not json");
}

#[test]
#[should_panic(expected = "config JSON failed to parse")]
fn unknown_field_panics() {
    FieldCryptoPlugin::from_config_json(
        &json!({ "key_hex": KEY_A, "encrypt_fields": ["/s"], "bogus": 1 }).to_string(),
    );
}

#[test]
#[should_panic(expected = "key must decode to 32 bytes")]
fn bad_key_length_panics() {
    FieldCryptoPlugin::from_config_json(
        &json!({ "key_hex": "abcd", "encrypt_fields": ["/s"] }).to_string(),
    );
}

#[test]
#[should_panic(expected = "not valid hex")]
fn non_hex_key_panics() {
    FieldCryptoPlugin::from_config_json(
        &json!({ "key_hex": "z".repeat(64), "encrypt_fields": ["/s"] }).to_string(),
    );
}

#[test]
#[should_panic(expected = "at least one of encrypt_fields")]
fn no_fields_panics() {
    FieldCryptoPlugin::from_config_json(&json!({ "key_hex": KEY_A }).to_string());
}
