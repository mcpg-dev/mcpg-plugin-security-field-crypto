# Field-Level Crypto Gate — `dev.mcpg.tool-gate.field-crypto`

> class `tool_gate` · `native` · package `mcpg-plugin-security-field-crypto` · artifact `libmcpg_plugin_security_field_crypto.so` · BUSL-1.1

A tool gate that seals named argument fields with XChaCha20-Poly1305 before a
call reaches its backend, and opens named result fields on the way back. Each
protected value becomes a self-describing string envelope bound to its own JSON
Pointer path, so a downstream system stores ciphertext it cannot read and cannot
usefully move between fields. Reach for it when a backend must accept and return
a sensitive field — a national ID, a card number, a clinical note — without ever
holding the plaintext.

## What it does
- Encrypts each JSON Pointer listed in `encrypt_fields` on the argument payload
  before dispatch, and decrypts each pointer listed in `decrypt_fields` on the
  result payload after dispatch.
- Uses XChaCha20-Poly1305 with a fresh 24-byte random nonce per seal, emitting
  `mcpgfc1:<base64url(nonce ‖ ciphertext ‖ tag)>` as the field's new string
  value. Two seals of the same plaintext never produce the same envelope.
- Binds the field's JSON Pointer as additional authenticated data, so an
  envelope lifted from `/ssn` fails to open at `/other` — relocation is detected
  as a tampering failure, not silently accepted.
- Denies rather than leaking when a field configured for encryption is present
  but is not a string, and when a value merely wears the `mcpgfc1:` prefix
  without authenticating under that field's pointer.
- Passes an already-sealed argument field through untouched, so re-entering the
  gate is idempotent, and leaves an absent field alone.
- Treats a result field that fails to open as a denial by default; set
  `fail_closed: false` to leave the sealed value in place instead.
- Scopes itself with `tools` / `exclude_tools` glob patterns (`*` for any
  sequence, `?` for one character; an exclude wins) and skips non-`tool`
  surfaces unless `apply_to_non_tool_surfaces` is on.
- Runs entirely in-process. It declares no capabilities, opens no sockets, and
  calls no host services.

## Configuration
Loaded from the flat top-level `plugins:` list. Every `tool_gate` entry joins
one chain evaluated in list order: the first deny short-circuits the call, and
argument rewrites made by one gate are visible to the gates after it and to the
backend.

```yaml
plugins:
  - id: dev.mcpg.tool-gate.field-crypto
    class: tool_gate
    source: { path: ./plugins/libmcpg_plugin_security_field_crypto.so }
    config:
      key_hex: ${env.MCPG_FIELD_CRYPTO_KEY_HEX}   # 64 hex chars = 32 bytes
      encrypt_fields: ["/ssn", "/card/number"]
      decrypt_fields: ["/ssn"]
      fail_closed: true
      tools: ["records.*"]
```

To pull the published artifact instead of building it, write
`source: { oci: ghcr.io/mcpg-dev/source-code/plugins/tool-gate-field-crypto:protocol-1 }`.
The reference is platform-agnostic; the gateway resolves the variant for its own
OS, architecture and libc.

| Field | Type | Default | Description |
|---|---|---|---|
| `key_hex` | string | — (required) | AEAD key, hex-encoded; must decode to exactly 32 bytes. |
| `encrypt_fields` | array of JSON Pointer | `[]` | Argument fields sealed before dispatch. |
| `decrypt_fields` | array of JSON Pointer | `[]` | Result fields opened after dispatch. |
| `fail_closed` | bool | `true` | A sealed result field that fails to open denies the call; `false` leaves it sealed. |
| `deny_code` | int | `-32051` | JSON-RPC error code used for this gate's denials. |
| `deny_http_status` | int | `403` | HTTP status used for this gate's denials. |
| `tools` | array of glob | `[]` | Tool names this gate applies to; empty means every tool. |
| `exclude_tools` | array of glob | `[]` | Tool names to skip; an exclude beats an include. |
| `apply_to_non_tool_surfaces` | bool | `false` | Also act on prompt, resource and completion surfaces. |

At least one of `encrypt_fields` / `decrypt_fields` must be non-empty. Unknown
fields are rejected, and a config that fails to parse — or a `key_hex` that is
not valid hex or not 32 bytes — refuses to register.

With the example above, an argument `{"ssn": "123-45-6789"}` reaches the backend
as `{"ssn": "mcpgfc1:…"}`, and a result that carries an envelope back at `/ssn`
is handed to the caller as plaintext. The two lists are matched by pointer, not
by position: because the pointer is the AAD, a value sealed at `/ssn` opens only
at `/ssn`.

## Security
- The key lives only in the entry's config. Populate it from the environment or
  another bound secret scheme; a hex literal in a checked-in config file defeats
  the point of the gate.
- Pointer-bound AAD is what stops envelope shuffling. If you rename a protected
  field, values sealed under the old pointer no longer open — re-seal them.
- The plugin holds exactly one key, so rotation means re-sealing stored values
  under the new key. The `mcpgfc1:` prefix identifies the envelope format for
  that kind of migration.
- The envelope prefix is caller-visible and therefore not proof of encryption:
  an argument arriving with the prefix is accepted only when it authenticates
  under that field's pointer, and rejected otherwise.
- Only string leaves are sealed. A field configured for encryption that arrives
  as a number or object is denied rather than forwarded in the clear.

## Build
The `cdylib-export` feature is on by default, so a standalone build already
produces a loadable artifact; a binary that links several plugins together turns
it off so they do not all export `mcpg_plugin_register`:

```bash
cargo build -p mcpg-plugin-security-field-crypto --features cdylib-export --release   # → target/release/libmcpg_plugin_security_field_crypto.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes, the ABI, and how entries load:
  <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema, including `plugins[]`:
  <https://mcpg.dev/docs/reference/configuration>
- Detect and block or redact secrets rather than encrypting named fields:
  `libs/plugins/security/dlp`
