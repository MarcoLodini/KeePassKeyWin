using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using PassKee.Harness.Cdp;
using PassKee.Harness.Pipe;

/// <summary>
/// PassKee Phase 0.5 harness.
///
/// Prerequisites:
///   1. KeePass is running with a .kdbx open and the PassKee plugin loaded.
///   2. Chrome (or Edge) is running with:
///        --remote-debugging-port=9222
///   3. The HKCU handshake nonce has been written by the plugin to
///        HKEY_CURRENT_USER\Software\PassKee\HandshakeNonce
///      (the plugin writes this on Initialize(); read it from the registry or
///       pass it via --nonce on the command line).
///
/// Usage:
///   PassKee.Harness [--port 9222] [--pipe PassKee.1] [--nonce &lt;hex&gt;] [--rp example.com]
///
/// Modes:
///   (default) Interactive: connects, handshakes, then prints a menu.
///   --smoke   Smoke test: createPasskey then listCredentials then signAssertion, print PASS/FAIL.
/// </summary>

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// --- Parse args ---
int cdpPort  = 9222;
string? nonce = null;
string rpId   = "webauthn.io";
string rpName = "WebAuthn.io";
bool smokeTest = false;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--port"  when i + 1 < args.Length: cdpPort  = int.Parse(args[++i]); break;
        case "--nonce" when i + 1 < args.Length: nonce    = args[++i]; break;
        case "--rp"    when i + 1 < args.Length: rpId     = args[++i]; break;
        case "--smoke": smokeTest = true; break;
    }
}

// --- Derive pipe name ---
// The plugin names the pipe PassKee.<sessionId>. On Windows the session ID matches
// the current process. For testing we default to session 1 (typical interactive session).
var sessionId = System.Diagnostics.Process.GetCurrentProcess().SessionId;
var pipeName  = $"PassKee.{sessionId}";

Console.WriteLine($"[Harness] Pipe: {pipeName}");
Console.WriteLine($"[Harness] CDP: localhost:{cdpPort}");

// --- Resolve nonce ---
if (string.IsNullOrEmpty(nonce))
{
    // Try to read from HKCU (Windows only).
    nonce = TryReadNonceFromRegistry();
    if (string.IsNullOrEmpty(nonce))
    {
        Console.Error.WriteLine("[Harness] ERROR: no handshake nonce. " +
            "Pass --nonce <value> or ensure the plugin has written it to " +
            @"HKEY_CURRENT_USER\Software\PassKee\HandshakeNonce");
        return 1;
    }
}

Console.WriteLine($"[Harness] Nonce: {nonce[..Math.Min(8, nonce.Length)]}...");

// --- Connect to plugin pipe ---
await using var pipe = new PipeClient(pipeName);
try
{
    Console.Write("[Harness] Connecting to plugin pipe... ");
    await pipe.ConnectAsync(timeoutMs: 5000, cts.Token);
    Console.WriteLine("OK");
    await pipe.HandshakeAsync(nonce, cts.Token);
    Console.WriteLine("[Harness] Handshake complete.");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"\n[Harness] ERROR connecting to plugin: {ex.Message}");
    Console.Error.WriteLine("Is KeePass running with a .kdbx open and the PassKee plugin loaded?");
    return 1;
}

// --- Connect to Chrome CDP ---
await using var cdp = new CdpClient();
try
{
    Console.Write($"[Harness] Discovering Chrome target at port {cdpPort}... ");
    var wsUrl = await ChromeTarget.GetFirstPageWebSocketUrlAsync(cdpPort);
    Console.WriteLine($"OK ({wsUrl[..Math.Min(60, wsUrl.Length)]}...)");

    await cdp.ConnectAsync(wsUrl, cts.Token);
    Console.WriteLine("[Harness] CDP connected.");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"\n[Harness] ERROR connecting to Chrome: {ex.Message}");
    Console.Error.WriteLine($"Launch Chrome with: --remote-debugging-port={cdpPort}");
    return 1;
}

// --- Start harness ---
await using var harness = new PasskeeHarness(pipe, cdp);
await harness.StartAsync(cts.Token);
Console.WriteLine("[Harness] Virtual authenticator installed. Ready.");

if (smokeTest)
    return await RunSmokeTestAsync(harness, pipe, rpId, rpName, cts.Token);

// --- Interactive mode ---
Console.WriteLine();
Console.WriteLine("Commands: create | list <rpId> | sign <credId> | quit");
while (!cts.Token.IsCancellationRequested)
{
    Console.Write("> ");
    var line = Console.ReadLine();
    if (line == null || line is "quit" or "q") break;

    var parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
    if (parts.Length == 0) continue;

    try
    {
        switch (parts[0])
        {
            case "create":
            {
                var credId = await harness.CreatePasskeyAsync(
                    rpId, rpName,
                    userHandle: Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                    userName: "test@example.com",
                    userDisplayName: "Test User",
                    cts.Token);
                Console.WriteLine($"Created: {credId}");
                break;
            }
            case "list":
            {
                var rp = parts.Length > 1 ? parts[1] : rpId;
                var result = await pipe.CallAsync("passkee.listCredentials",
                    new Newtonsoft.Json.Linq.JObject { ["rpId"] = rp }, cts.Token);
                Console.WriteLine(result?.ToString(Newtonsoft.Json.Formatting.Indented));
                break;
            }
            case "sign":
            {
                var credId = parts.Length > 1 ? parts[1] : string.Empty;
                if (string.IsNullOrEmpty(credId)) { Console.WriteLine("Usage: sign <credentialId>"); break; }
                var ok = await harness.VerifyAssertionAsync(
                    credId, rpId,
                    authDataBytes: new byte[37],
                    clientDataHash: System.Security.Cryptography.SHA256.HashData(
                        System.Text.Encoding.UTF8.GetBytes("{}")),
                    cts.Token);
                Console.WriteLine(ok ? "Signature OK" : "Signature FAILED");
                break;
            }
            default:
                Console.WriteLine("Unknown command. Commands: create | list [rpId] | sign <credId> | quit");
                break;
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Error: {ex.Message}");
    }
}

Console.WriteLine("[Harness] Exiting.");
return 0;

// --- Smoke test ---
static async Task<int> RunSmokeTestAsync(
    PasskeeHarness harness, PipeClient pipe,
    string rpId, string rpName,
    CancellationToken ct)
{
    Console.WriteLine("[Smoke] Starting smoke test...");
    bool pass = true;

    try
    {
        // 1. createPasskey
        Console.Write("[Smoke] createPasskey... ");
        var credId = await harness.CreatePasskeyAsync(
            rpId, rpName,
            userHandle: Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }),
            userName: "smoke@test.com",
            userDisplayName: "Smoke User",
            ct);
        Console.WriteLine($"OK ({credId[..Math.Min(16, credId.Length)]}...)");

        // 2. listCredentials
        Console.Write("[Smoke] listCredentials... ");
        var listResult = await pipe.CallAsync("passkee.listCredentials",
            new Newtonsoft.Json.Linq.JObject { ["rpId"] = rpId }, ct);
        var creds = (Newtonsoft.Json.Linq.JArray?)listResult;
        if (creds == null || creds.Count == 0) throw new Exception("No credentials returned.");
        Console.WriteLine($"OK ({creds.Count} credential(s))");

        // 3. signAssertion
        Console.Write("[Smoke] signAssertion... ");
        var authData   = PassKee.Core.WebAuthn.AuthDataBuilder.BuildAssertion(rpId, userVerified: true);
        var clientData = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes("{\"type\":\"webauthn.get\",\"challenge\":\"dGVzdA\"}"));
        var ok = await harness.VerifyAssertionAsync(credId, rpId, authData, clientData, ct);
        if (!ok) throw new Exception("Signature verification failed.");
        Console.WriteLine("OK");

        // 4. deleteCredential
        Console.Write("[Smoke] deleteCredential... ");
        var delResult = await pipe.CallAsync("passkee.deleteCredential",
            new Newtonsoft.Json.Linq.JObject { ["credentialId"] = credId }, ct);
        var deleted = delResult?["deleted"]?.Value<bool>() ?? false;
        if (!deleted) throw new Exception("deleteCredential returned false.");
        Console.WriteLine("OK");

        Console.WriteLine("[Smoke] All checks PASSED.");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[Smoke] FAILED: {ex.Message}");
        pass = false;
    }

    return pass ? 0 : 1;
}

static string? TryReadNonceFromRegistry()
{
    if (!OperatingSystem.IsWindows()) return null;
    try
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\PassKee");
        return key?.GetValue("HandshakeNonce") as string;
    }
    catch
    {
        return null;
    }
}
