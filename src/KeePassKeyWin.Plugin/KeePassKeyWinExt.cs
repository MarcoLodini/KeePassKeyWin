using System;
using System.Diagnostics;
using KeePass.Plugins;
using Microsoft.Win32;
using KeePassKeyWin.Core.Ipc;
using KeePassKeyWin.Core.Platform;
using KeePassKeyWin.Plugin.Ipc;
using KeePassKeyWin.Plugin.Storage;
#if NET48
using KeePassKeyWin.Plugin.UI;
#endif

namespace KeePassKeyWin;

// Class name must be <Namespace>Ext per KeePass plugin loader convention.
public sealed class KeePassKeyWinExt : KeePass.Plugins.Plugin
{
    // Diag breadcrumbs live flat under HKCU\Software\KeePassKeyWin alongside the nonce
    // so the validator's existing `Get-ItemProperty HKCU:\Software\KeePassKeyWin` dump
    // picks them up without needing to recurse into subkeys.
    private const string DiagRegPath   = @"Software\KeePassKeyWin";
    private const string DiagKeyPrefix = "Diag_";

    private IPluginHost? _host;
    private PipeServer? _pipeServer;
    private RegistryNonceStore? _nonceStore;
#if NET48
    private MenuEntry? _menuEntry;
    private PasskeyEntryDecorator? _decorator;
#endif

    /// <summary>
    /// Writes a single HKCU diagnostic breadcrumb. Used so a silent Initialize()
    /// failure on a user's box can be diagnosed after the fact by reading
    /// HKCU\Software\KeePassKeyWin\Diag\* — the nonce-never-appears symptom otherwise
    /// gives us nothing to go on.
    /// </summary>
    private static void Diag(string key, string value)
    {
        try
        {
            using var k = Registry.CurrentUser.CreateSubKey(DiagRegPath, writable: true);
            k?.SetValue(DiagKeyPrefix + key, value ?? string.Empty, RegistryValueKind.String);
        }
        catch { /* diag is best-effort; never let telemetry break Initialize */ }
    }

    public override bool Initialize(IPluginHost host)
    {
        // Write a breadcrumb BEFORE any logic that could throw or early-return.
        // If HKCU\Software\KeePassKeyWin\Diag is missing after a failed run, we know
        // Initialize() didn't run at all (assembly load failure, binding issue).
        Diag("LastStep", "Initialize:entered");
        Diag("LastStepTime", DateTime.UtcNow.ToString("o"));

        try
        {
            return InitializeCore(host);
        }
        catch (Exception ex)
        {
            Diag("InitException", ex.ToString());
            throw; // let KeePass surface it through its normal plugin-load error path
        }
    }

    private bool InitializeCore(IPluginHost host)
    {
        _host = host;

        var (osOk, osReason) = OsVersionCheck.IsSupportedWindows();
        Diag("OsCheckOk",     osOk ? "true" : "false");
        Diag("OsCheckReason", osReason ?? string.Empty);

        if (!osOk)
        {
            Diag("LastStep", "Initialize:os-check-failed-early-return");
            // Log but still return true — don't prevent KeePass from loading.
            // Just skip pipe server and UI wiring.
            host.MainWindow.SetStatusEx($"KeePassKeyWin disabled: {osReason}");
            return true;
        }

#if NET48
        Diag("LastStep", "Initialize:installing-menu");
        _menuEntry = new MenuEntry(host);
        _menuEntry.Install();

        Diag("LastStep", "Initialize:installing-decorator");
        _decorator = new PasskeyEntryDecorator(host);
        _decorator.Install();

        Diag("LastStep", "Initialize:nonce-store-init");
        _nonceStore = new RegistryNonceStore();
        _nonceStore.Initialize();
#endif

        Diag("LastStep", "Initialize:building-dispatcher");
        var dispatcher = new RpcDispatcher(_nonceStore!);
        var vaultStore = new KeePassPasskeyStore(host);
        var vaultHandler = new VaultHandler(vaultStore);
        dispatcher.VaultHandler = vaultHandler.Handle;

        var sessionId = Process.GetCurrentProcess().SessionId;
        var pipeName = $"KeePassKeyWin.{sessionId}";

        Diag("LastStep", "Initialize:pipe-start");
        _pipeServer = new PipeServer(pipeName, dispatcher.Dispatch);
        if (!_pipeServer.TryStart())
        {
            host.MainWindow.SetStatusEx("KeePassKeyWin: another instance is active. This instance will stay passive.");
            _pipeServer.Dispose();
            _pipeServer = null;
            Diag("LastStep", "Initialize:pipe-busy-passive");
        }
        else
        {
            Diag("LastStep", "Initialize:complete");
        }

        return true;
    }

    public override void Terminate()
    {
#if NET48
        _menuEntry?.Uninstall();
        _menuEntry = null;
        _decorator?.Dispose();
        _decorator = null;
#endif

        _pipeServer?.Stop();
        _pipeServer = null;
        _nonceStore?.Clear();
        _nonceStore = null;
        _host = null;
    }
}
