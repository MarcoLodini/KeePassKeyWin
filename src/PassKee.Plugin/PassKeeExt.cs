using System;
using System.Diagnostics;
using KeePass.Plugins;
using PassKee.Core.Ipc;
using PassKee.Plugin.Ipc;
using PassKee.Plugin.Storage;

namespace PassKee;

// Class name must be <Namespace>Ext per KeePass plugin loader convention.
public sealed class PassKeeExt : Plugin
{
    private IPluginHost? _host;
    private PipeServer? _pipeServer;
    private RegistryNonceStore? _nonceStore;

    public override bool Initialize(IPluginHost host)
    {
        _host = host;

        if (!IsWin1124H2OrLater())
        {
            host.MainWindow.SetStatusEx("PassKee: requires Windows 11 24H2 (build 26100.6725+). Plugin disabled.");
            return false;
        }

        _nonceStore = new RegistryNonceStore();
        _nonceStore.Initialize();

        var dispatcher = new RpcDispatcher(_nonceStore);
        var vaultStore = new KeePassPasskeyStore(host);
        var vaultHandler = new VaultHandler(vaultStore);
        dispatcher.VaultHandler = vaultHandler.Handle;

        var sessionId = Process.GetCurrentProcess().SessionId;
        var pipeName = $"PassKee.{sessionId}";

        _pipeServer = new PipeServer(pipeName, dispatcher.Dispatch);
        if (!_pipeServer.TryStart())
        {
            host.MainWindow.SetStatusEx("PassKee: another instance is active. This instance will stay passive.");
            _pipeServer.Dispose();
            _pipeServer = null;
        }

        return true;
    }

    public override void Terminate()
    {
        _pipeServer?.Stop();
        _pipeServer = null;
        _nonceStore?.Clear();
        _nonceStore = null;
        _host = null;
    }

    // Windows 11 24H2 build 26100.6725 or later is required for IPluginAuthenticator.
    private static bool IsWin1124H2OrLater()
    {
#if WINDOWS
        var v = Environment.OSVersion.Version;
        // Build 26100 corresponds to 24H2; KB5068861 pushes revision to ≥6725.
        return v.Major >= 10 && v.Build >= 26100;
#else
        return false;
#endif
    }
}
