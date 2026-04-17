using System;
using System.Diagnostics;
using KeePass.Plugins;
using PassKee.Core.Ipc;
using PassKee.Core.Platform;
using PassKee.Plugin.Ipc;
using PassKee.Plugin.Storage;
#if NET48
using PassKee.Plugin.UI;
#endif

namespace PassKee;

// Class name must be <Namespace>Ext per KeePass plugin loader convention.
public sealed class PassKeeExt : KeePass.Plugins.Plugin
{
    private IPluginHost? _host;
    private PipeServer? _pipeServer;
    private RegistryNonceStore? _nonceStore;
#if NET48
    private MenuEntry? _menuEntry;
    private PasskeyEntryDecorator? _decorator;
#endif

    public override bool Initialize(IPluginHost host)
    {
        _host = host;

        var (osOk, osReason) = OsVersionCheck.IsSupportedWindows();
        if (!osOk)
        {
            // Log but still return true — don't prevent KeePass from loading.
            // Just skip pipe server and UI wiring.
            host.MainWindow.SetStatusEx($"PassKee disabled: {osReason}");
            return true;
        }

#if NET48
        _menuEntry = new MenuEntry(host);
        _menuEntry.Install();

        _decorator = new PasskeyEntryDecorator(host);
        _decorator.Install();

        _nonceStore = new RegistryNonceStore();
        _nonceStore.Initialize();
#endif

        var dispatcher = new RpcDispatcher(_nonceStore!);
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
