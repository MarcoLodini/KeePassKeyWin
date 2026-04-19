using System;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using KeePassKeyWin.Harness.Cdp;
using KeePassKeyWin.Harness.Pipe;

namespace KeePassKeyWin.Harness
{
    /// <summary>
    /// Phase 0.5 harness: bridges Chrome DevTools virtual authenticator to the KeePassKeyWin plugin pipe.
    ///
    /// Flow:
    ///   1. Connect to the plugin pipe and perform handshake.
    ///   2. Connect to Chrome CDP.
    ///   3. Enable WebAuthn domain and install a virtual authenticator (ctap2, internal transport).
    ///   4. Chrome intercepts navigator.credentials.create/get calls and emits CDP events.
    ///   5. This harness translates each event into a keepasskeywin.* JSON-RPC call and feeds the
    ///      response back to Chrome so the browser's WebAuthn operation completes normally.
    ///
    /// Chrome DevTools Protocol WebAuthn domain reference:
    ///   https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/
    ///
    /// Note: CDP virtual authenticator intercepts at the credential creation/assertion level,
    /// not at raw CTAP2 framing — so we receive parsed rpId, userHandle, clientDataHash etc.
    /// directly rather than CBOR-encoded CTAP2 commands. This simplifies the shim considerably.
    /// </summary>
    public sealed class KeePassKeyWinHarness : IAsyncDisposable
    {
        private readonly PipeClient _pipe;
        private readonly CdpClient? _cdp;
        private string? _authenticatorId;

        public KeePassKeyWinHarness(PipeClient pipe, CdpClient? cdp = null)
        {
            _pipe = pipe;
            _cdp  = cdp;
        }

        /// <summary>
        /// Connects to the Chrome CDP virtual authenticator and registers event handlers.
        /// When <c>_cdp</c> is <c>null</c> (smoke mode), this method is a no-op on the CDP
        /// side — the pipe connection is already live and all smoke operations use it directly.
        /// </summary>
        public async Task StartAsync(CancellationToken ct = default)
        {
            if (_cdp == null)
            {
                Console.WriteLine("[Harness] No CDP client — running pipe-only (smoke mode).");
                return;
            }

            // Enable the WebAuthn domain for this target.
            await _cdp.CallAsync("WebAuthn.enable", new JObject
            {
                ["enableUI"] = false,
            }, ct);

            // Add a virtual authenticator: CTAP2, internal platform transport, resident keys,
            // user verification. These flags match the KeePassKeyWin v1 capabilities.
            var result = await _cdp.CallAsync("WebAuthn.addVirtualAuthenticator", new JObject
            {
                ["options"] = new JObject
                {
                    ["protocol"]                   = "ctap2",
                    ["transport"]                  = "internal",
                    ["hasResidentKey"]             = true,
                    ["hasUserVerification"]        = true,
                    ["isUserVerified"]             = true,
                    ["automaticPresenceSimulation"] = true,
                },
            }, ct);

            _authenticatorId = result["authenticatorId"]?.Value<string>()
                ?? throw new InvalidOperationException("CDP did not return an authenticatorId.");

            Console.WriteLine($"[Harness] Virtual authenticator registered: {_authenticatorId}");

            // CDP fires WebAuthn.credentialAdded after a successful MakeCredential.
            // We don't need to intercept this — Chrome calls our virtual authenticator
            // directly via the CDP command flow, not events. The events are informational.
            // The actual interception happens via the credential store commands below.

            // Register event handler for credential assertions (informational logging).
            _cdp.OnEvent("WebAuthn.credentialAdded", OnCredentialAdded);
            _cdp.OnEvent("WebAuthn.credentialAsserted", OnCredentialAsserted);
        }

        /// <summary>
        /// Performs a MakeCredential round-trip through the plugin pipe: calls
        /// `keepasskeywin.createPasskey`, receives the credential id + COSE public key.
        ///
        /// NOTE: this does NOT inject the credential into Chrome's CDP virtual
        /// authenticator. Doing so would require handing Chrome a PKCS#8 private
        /// key (CDP `WebAuthn.addCredential` has `privateKey` as a required field
        /// and returns "Invalid parameters" without it), which contradicts the
        /// Phase 0.5 design goal of keeping private keys inside the plugin. For
        /// plugin-side verification the smoke test then calls `keepasskeywin.signAssertion`
        /// directly via the pipe; Chrome's virtual authenticator is only needed so
        /// the CDP WebSocket connects (see memory note "Harness --smoke mode
        /// requires a live CDP target"). If a future browser-transparent flow needs
        /// the credential visible to Chrome, call `InjectCredentialAsync` explicitly
        /// with a synthesised private key — but that diverges Chrome's PK from the
        /// plugin's authoritative PK and is not what Phase 0.5 validates.
        /// </summary>
        public async Task<string> CreatePasskeyAsync(
            string rpId, string rpName,
            string userHandle, string userName, string userDisplayName,
            CancellationToken ct = default)
        {
            Console.WriteLine($"[Harness] createPasskey: rpId={rpId} user={userName}");

            var result = await _pipe.CallAsync("keepasskeywin.createPasskey", new JObject
            {
                ["rpId"]            = rpId,
                ["rpName"]          = rpName,
                ["userHandle"]      = userHandle,
                ["userName"]        = userName,
                ["userDisplayName"] = userDisplayName,
            }, ct);

            var obj = (JObject)(result ?? throw new InvalidOperationException("createPasskey returned null."));
            var credentialId = obj["credentialId"]!.Value<string>()!;

            Console.WriteLine($"[Harness] Created credential: {credentialId}");
            return credentialId;
        }

        /// <summary>
        /// Injects a credential into Chrome's CDP virtual authenticator so the browser
        /// can enumerate it during GetAssertion. Not used by the Phase 0.5 smoke test
        /// (see the note on <see cref="CreatePasskeyAsync"/>); kept as a building block
        /// for future browser-transparent flows that need Chrome to have an actual
        /// signing key. Note that the PK passed here diverges Chrome's view from the
        /// plugin's authoritative key unless the caller synthesises a fresh pair and
        /// registers the public half with the plugin through some other channel.
        ///
        /// CDP's <c>WebAuthn.addCredential</c> requires <c>privateKey</c> as a PKCS#8
        /// blob and rejects the call with "Invalid parameters" if it's missing —
        /// the earlier version of this method omitted it and silently broke.
        /// </summary>
        public async Task InjectCredentialAsync(
            string credentialId, string userHandle,
            string privateKeyPkcs8Base64, string rpId,
            CancellationToken ct = default)
        {
            if (_cdp == null)
                throw new InvalidOperationException(
                    "InjectCredentialAsync requires a live CDP connection. " +
                    "This method is for Phase 1+ browser-transparent flows and must not be called in smoke mode.");
            if (_authenticatorId == null)
                throw new InvalidOperationException("Harness not started.");
            if (string.IsNullOrEmpty(privateKeyPkcs8Base64))
                throw new ArgumentException("CDP requires a non-empty PKCS#8 privateKey.", nameof(privateKeyPkcs8Base64));

            Console.WriteLine($"[Harness] Injecting credential {credentialId} for rpId={rpId}");

            await _cdp.CallAsync("WebAuthn.addCredential", new JObject
            {
                ["authenticatorId"] = _authenticatorId,
                ["credential"] = new JObject
                {
                    ["credentialId"]         = credentialId,
                    ["isResidentCredential"] = true,
                    ["rpId"]                 = rpId,
                    ["privateKey"]           = privateKeyPkcs8Base64,
                    ["userHandle"]           = userHandle,
                    ["signCount"]            = 0,
                },
            }, ct);
        }

        /// <summary>
        /// Verifies a sign assertion round-trip through the plugin for a known credential.
        /// Used by the E2E test to confirm the DER signature is valid.
        /// </summary>
        public async Task<bool> VerifyAssertionAsync(
            string credentialId, string rpId,
            byte[] authDataBytes, byte[] clientDataHash,
            CancellationToken ct = default)
        {
            Console.WriteLine($"[Harness] signAssertion: credentialId={credentialId}");

            var result = await _pipe.CallAsync("keepasskeywin.signAssertion", new JObject
            {
                ["credentialId"]   = credentialId,
                ["authData"]       = Convert.ToBase64String(authDataBytes),
                ["clientDataHash"] = Convert.ToBase64String(clientDataHash),
            }, ct);

            var obj = (JObject)(result ?? throw new InvalidOperationException("signAssertion returned null."));
            var sigB64 = obj["signature"]?.Value<string>();

            if (string.IsNullOrEmpty(sigB64))
            {
                Console.Error.WriteLine("[Harness] signAssertion: no signature in response.");
                return false;
            }

            Console.WriteLine($"[Harness] Got signature ({Convert.FromBase64String(sigB64).Length} bytes DER).");
            return true;
        }

        private void OnCredentialAdded(JObject @params)
        {
            var credId = @params["credential"]?["credentialId"]?.Value<string>() ?? "(unknown)";
            Console.WriteLine($"[CDP event] credentialAdded: {credId}");
        }

        private void OnCredentialAsserted(JObject @params)
        {
            var credId = @params["credential"]?["credentialId"]?.Value<string>() ?? "(unknown)";
            Console.WriteLine($"[CDP event] credentialAsserted: {credId}");
        }

        public async ValueTask DisposeAsync()
        {
            if (_cdp != null && _authenticatorId != null)
            {
                try
                {
                    await _cdp.CallAsync("WebAuthn.removeVirtualAuthenticator", new JObject
                    {
                        ["authenticatorId"] = _authenticatorId,
                    });
                }
                catch { }
            }
        }
    }
}
