//! KeePassKeyWin's CTAP2 `authenticatorGetInfo` blob + AAGUID constant.
//!
//! Cross-platform on purpose: the CBOR encoder (ciborium) and the byte
//! layout are OS-agnostic, so Linux CI can exercise this directly. The
//! Windows registration path (`com::exe_server::cmd_register`) consumes
//! the output of `authenticator_get_info_cbor()` as the
//! `pbAuthenticatorInfo` buffer passed to
//! `EXPERIMENTAL_WebAuthNPluginAddAuthenticator`.
//!
//! Any change to this blob that passes the unit tests below still has to
//! clear two additional runtime checks on a live Win11 target:
//!   1. `keepasskeywin-provider.exe register` returning S_OK.
//!   2. `KeePassKeyWin` appearing in Settings → Accounts → Passkeys → Advanced.

/// KeePassKeyWin's plugin AAGUID. Randomly generated once, baked in — stable
/// across installs so credentials sync-attested by AAGUID keep working.
/// If a different AAGUID is ever needed (e.g. v2 of the provider),
/// generate a new RFC-4122 v4 UUID, update this constant, and update
/// the `KEEPASSKEYWIN_AAGUID` documentation.
///
/// Bytes of `a97d1e2b-4c8f-4a3e-9bd6-5f82c1476e3d` — verified v4 per
/// RFC 4122 (version nibble = 4, variant bits = 10xx).
///
/// An all-zeros AAGUID is the WebAuthn spec's reserved "no attestation"
/// value. The `EXPERIMENTAL_` WebAuthN plugin API rejects it with
/// NTE_INVALID_PARAMETER (0x80090027) — confirmed empirically against
/// SDK 10.0.26100.0 + build 26200.8037. Don't revert to zero.
pub const KEEPASSKEYWIN_AAGUID: [u8; 16] = [
    0xa9, 0x7d, 0x1e, 0x2b, 0x4c, 0x8f, 0x4a, 0x3e,
    0x9b, 0xd6, 0x5f, 0x82, 0xc1, 0x47, 0x6e, 0x3d,
];

/// Build the CTAP2 `authenticatorGetInfo` CBOR response required by the
/// WebAuthN plugin-provider registration API.
///
/// Advertises:
///   1 (versions):    ["FIDO_2_0", "FIDO_2_1"]
///   3 (aaguid):      KEEPASSKEYWIN_AAGUID (non-zero, v4 UUID bytes)
///   4 (options):     {"rk": true, "up": true, "uv": true}
///   9 (transports):  ["internal"]
///   10 (algorithms): [{"alg": -7, "type": "public-key"}]   — ES256 / COSE P-256
///
/// Matches Microsoft's PasskeyManager reference sample minus key 2
/// (extensions) — `prf` and `hmac-secret` are v1 non-goals per PLAN.md,
/// so we deliberately don't advertise them. The CBOR is re-read by
/// Windows on each `register`, so extending later does not break
/// existing registrations.
///
/// History: an earlier minimal-subset blob (versions + aaguid + options.rk
/// only, zero AAGUID) was rejected with NTE_INVALID_PARAMETER. The API
/// enforces stricter capability advertisement than CTAP2.1 §6.4 strictly
/// requires.
pub fn authenticator_get_info_cbor() -> Vec<u8> {
    use ciborium::Value;

    let versions = Value::Array(vec![
        Value::Text("FIDO_2_0".into()),
        Value::Text("FIDO_2_1".into()),
    ]);
    let aaguid   = Value::Bytes(KEEPASSKEYWIN_AAGUID.to_vec());
    let options  = Value::Map(vec![
        (Value::Text("rk".into()), Value::Bool(true)),
        (Value::Text("up".into()), Value::Bool(true)),
        (Value::Text("uv".into()), Value::Bool(true)),
    ]);
    let transports = Value::Array(vec![Value::Text("internal".into())]);
    let algorithms = Value::Array(vec![
        Value::Map(vec![
            (Value::Text("alg".into()),  Value::Integer((-7i64).into())),
            (Value::Text("type".into()), Value::Text("public-key".into())),
        ]),
    ]);

    let info = Value::Map(vec![
        (Value::Integer(1.into()),  versions),
        (Value::Integer(3.into()),  aaguid),
        (Value::Integer(4.into()),  options),
        (Value::Integer(9.into()),  transports),
        (Value::Integer(10.into()), algorithms),
    ]);

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&info, &mut bytes)
        .expect("authenticatorGetInfo CBOR encode");
    bytes
}

// ── Regression tests ──────────────────────────────────────────────────────────
//
// Catches: ciborium version bumps changing integer-key encoding, accidental
// field drops, typos in option-key spelling. The empirical cost of a bad blob
// is an opaque NTE_INVALID_PARAMETER at register time with no per-field
// diagnostic.

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    fn decode() -> Vec<(Value, Value)> {
        let bytes = authenticator_get_info_cbor();
        match ciborium::de::from_reader::<Value, _>(&bytes[..])
            .expect("re-parse our own CBOR")
        {
            Value::Map(m) => m,
            other => panic!("expected top-level CBOR map, got {:?}", other),
        }
    }

    fn get(map: &[(Value, Value)], k: i64) -> &Value {
        map.iter()
            .find(|(key, _)| matches!(key, Value::Integer(i) if i64::try_from(*i) == Ok(k)))
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("key {k} missing from authenticatorGetInfo CBOR"))
    }

    #[test]
    fn aaguid_is_not_all_zeros() {
        // Zero AAGUID → NTE_INVALID_PARAMETER from the EXPERIMENTAL_ API.
        assert!(
            KEEPASSKEYWIN_AAGUID.iter().any(|&b| b != 0),
            "AAGUID must not be all zeros — API rejects with 0x80090027",
        );
        assert_eq!(KEEPASSKEYWIN_AAGUID.len(), 16);
    }

    #[test]
    fn versions_include_fido_2_1() {
        let map = decode();
        let versions = match get(&map, 1) {
            Value::Array(a) => a,
            other => panic!("key 1 (versions) should be array, got {other:?}"),
        };
        assert!(
            versions.iter().any(|v| matches!(v, Value::Text(t) if t == "FIDO_2_1")),
            "versions must include FIDO_2_1 on Win11 24H2+",
        );
        assert!(
            versions.iter().any(|v| matches!(v, Value::Text(t) if t == "FIDO_2_0")),
            "versions should include FIDO_2_0 for broader compat",
        );
    }

    #[test]
    fn aaguid_key_roundtrips() {
        let map = decode();
        let aaguid = match get(&map, 3) {
            Value::Bytes(b) => b,
            other => panic!("key 3 (aaguid) should be bytes, got {other:?}"),
        };
        assert_eq!(aaguid.as_slice(), &KEEPASSKEYWIN_AAGUID);
    }

    #[test]
    fn options_flags_present() {
        let map = decode();
        let options = match get(&map, 4) {
            Value::Map(m) => m,
            other => panic!("key 4 (options) should be map, got {other:?}"),
        };
        for required in ["rk", "up", "uv"] {
            let found = options.iter().any(|(k, v)| {
                matches!((k, v), (Value::Text(t), Value::Bool(true)) if t == required)
            });
            assert!(found, "options.{required} must be present and true");
        }
    }

    #[test]
    fn transports_and_algorithms_present() {
        let map = decode();
        // Just assert presence + shape — the exact contents can shift later.
        let _transports = match get(&map, 9) {
            Value::Array(a) => a,
            other => panic!("key 9 (transports) should be array, got {other:?}"),
        };
        let algorithms = match get(&map, 10) {
            Value::Array(a) => a,
            other => panic!("key 10 (algorithms) should be array, got {other:?}"),
        };
        // ES256 (alg = -7) must be advertised.
        let has_es256 = algorithms.iter().any(|entry| {
            let Value::Map(fields) = entry else { return false };
            fields.iter().any(|(k, v)| {
                matches!((k, v), (Value::Text(n), Value::Integer(i))
                    if n == "alg" && i64::try_from(*i) == Ok(-7))
            })
        });
        assert!(has_es256, "algorithms must include ES256 (alg = -7)");
    }
}
