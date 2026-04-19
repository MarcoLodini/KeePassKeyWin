#if NET48
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassKeyWin.Core.Platform;

namespace KeePassKeyWin.Plugin.UI
{
    /// <summary>
    /// Adds a "KeePassKeyWin" item to the KeePass Tools menu with sub-items for About,
    /// Show Passkeys folder, and OS compatibility info. Removes itself on Terminate.
    /// </summary>
    internal sealed class MenuEntry
    {
        private readonly IPluginHost      _host;
        private ToolStripMenuItem?        _rootItem;

        internal MenuEntry(IPluginHost host) => _host = host;

        internal void Install()
        {
            _rootItem = new ToolStripMenuItem("KeePassKeyWin");

            var about = new ToolStripMenuItem("About KeePassKeyWin...");
            about.Click += (_, _) =>
            {
                using var dlg = new AboutDialog();
                dlg.ShowDialog(_host.MainWindow);
            };

            var showPasskeys = new ToolStripMenuItem("Show Passkeys folder");
            showPasskeys.Click += (_, _) => ShowPasskeysGroup();

            var osCompat = new ToolStripMenuItem("OS compatibility...");
            osCompat.Click += (_, _) =>
            {
                var (ok, reason) = OsVersionCheck.IsSupportedWindows();
                string msg = ok
                    ? "Your OS meets KeePassKeyWin requirements."
                    : reason;
                MessageBox.Show(msg, "KeePassKeyWin — OS Compatibility",
                    MessageBoxButtons.OK,
                    ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            };

            _rootItem.DropDownItems.Add(about);
            _rootItem.DropDownItems.Add(showPasskeys);
            _rootItem.DropDownItems.Add(new ToolStripSeparator());
            _rootItem.DropDownItems.Add(osCompat);

            _host.MainWindow.ToolsMenu.DropDownItems.Add(_rootItem);
        }

        internal void Uninstall()
        {
            if (_rootItem != null)
            {
                _host.MainWindow.ToolsMenu.DropDownItems.Remove(_rootItem);
                _rootItem.Dispose();
                _rootItem = null;
            }
        }

        private void ShowPasskeysGroup()
        {
            var db = _host.Database;
            if (db == null || !db.IsOpen) return;

            var root = db.RootGroup;
            for (uint i = 0; i < root.Groups.UCount; i++)
            {
                var g = root.Groups.GetAt(i);
                if (g.Name == "Passkeys")
                {
                    _host.MainWindow.UpdateUI(false, null, true, g, false, null, false);
                    return;
                }
            }

            MessageBox.Show("No Passkeys folder found in the current database.",
                "KeePassKeyWin", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
#endif
