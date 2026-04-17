#if NET48
using System;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassLib;
using PassKee.Core.Storage;

namespace PassKee.Plugin.UI
{
    /// <summary>
    /// Decorates the KeePass entry editor with a read-only Passkey tab when the entry
    /// being edited has a PassKee.credentialId string field. Deletion is handled by
    /// the standard KeePass delete flow (no special write path in v1).
    /// </summary>
    internal sealed class PasskeyEntryDecorator : IDisposable
    {
        private const string KeyCredId = "PassKee.credentialId";

        private readonly IPluginHost _host;
        private bool _disposed;

        internal PasskeyEntryDecorator(IPluginHost host) => _host = host;

        internal void Install()
        {
            // KeePass raises EcasGlobalEvent "EntryViewEntry" when an entry editor
            // is opened. Since the entry-form hook requires access to the EcasPool
            // (event-condition-action system), we use the simpler approach of
            // subscribing to the main window's entry-context-menu or listening to
            // GlobalWindowManager events. For v1 we use GlobalWindowManager.
            KeePass.UI.GlobalWindowManager.WindowAdded += OnWindowAdded;
        }

        internal void Uninstall()
        {
            KeePass.UI.GlobalWindowManager.WindowAdded -= OnWindowAdded;
        }

        private void OnWindowAdded(object? sender, KeePass.UI.GwmWindowEventArgs e)
        {
            if (e.Form is KeePass.Forms.PwEntryForm entryForm)
                entryForm.Shown += (_, _) => DecorateEntryForm(entryForm);
        }

        private void DecorateEntryForm(KeePass.Forms.PwEntryForm form)
        {
            var entry = form.EntryRef;
            if (entry == null) return;

            var credId = entry.Strings.Get(KeyCredId)?.ReadString();
            if (string.IsNullOrEmpty(credId)) return;

            // Build read-only metadata tab.
            var tab = new TabPage("Passkey");
            var grid = BuildMetadataPanel(entry);
            tab.Controls.Add(grid);

            // Find the TabControl in the entry form and append our tab.
            foreach (Control c in form.Controls)
            {
                if (c is TabControl tc)
                {
                    tc.TabPages.Add(tab);
                    break;
                }
            }
        }

        private static Panel BuildMetadataPanel(PwEntry entry)
        {
            string Get(string key) => entry.Strings.Get(key)?.ReadString() ?? string.Empty;
            string GetCustom(string key) => entry.CustomData.Get(key) ?? string.Empty;

            var fields = new[]
            {
                ("Credential ID",  Get("PassKee.credentialId")),
                ("Relying Party",  Get("PassKee.rpId")),
                ("User name",      Get("PassKee.userName")),
                ("Display name",   Get("PassKee.userDisplayName")),
                ("Algorithm",      GetCustom("PassKee.algId") == "-7" ? "ES256 (-7)" : GetCustom("PassKee.algId")),
                ("Transports",     GetCustom("PassKee.transports")),
                ("Created",        GetCustom("PassKee.creationTime")),
                ("Last used",      GetCustom("PassKee.lastUsedTime")),
            };

            var panel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8), AutoScroll = true };
            int y = 8;
            foreach (var (label, value) in fields)
            {
                panel.Controls.Add(new Label
                {
                    Text     = label + ":",
                    Location = new System.Drawing.Point(8, y),
                    Width    = 120,
                    AutoSize = false,
                });
                panel.Controls.Add(new TextBox
                {
                    Text      = value,
                    ReadOnly  = true,
                    Location  = new System.Drawing.Point(132, y),
                    Width     = 340,
                    BorderStyle = BorderStyle.None,
                    BackColor = System.Drawing.SystemColors.Control,
                });
                y += 26;
            }
            return panel;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Uninstall();
                _disposed = true;
            }
        }
    }
}
#endif
