#if NET48
using System.Diagnostics;
using System.Windows.Forms;

namespace PassKee.Plugin.UI
{
    internal sealed class AboutDialog : Form
    {
        internal AboutDialog()
        {
            Text        = "About PassKee";
            Width       = 400;
            Height      = 220;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;

            var body = new Label
            {
                Text = "PassKee — FIDO2 / WebAuthn passkey storage for KeePass 2.x\r\n\r\n" +
                       "Version 0.0.1\r\n\r\n" +
                       "Licensed under GNU General Public License v3.0 or later.\r\n\r\n" +
                       "https://github.com/mlodini/PassKee",
                AutoSize  = false,
                Dock      = DockStyle.Fill,
                Padding   = new Padding(16),
            };

            body.Click += (_, _) =>
            {
                try { Process.Start(new ProcessStartInfo("https://github.com/mlodini/PassKee") { UseShellExecute = true }); }
                catch { /* best-effort */ }
            };

            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Dock = DockStyle.Bottom };
            Controls.Add(body);
            Controls.Add(ok);
            AcceptButton = ok;
        }
    }
}
#endif
