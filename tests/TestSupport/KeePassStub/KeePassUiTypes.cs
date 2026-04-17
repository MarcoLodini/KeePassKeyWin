#if NET48
// Minimal stubs for KeePass WinForms UI types needed to compile PassKee.Plugin
// on Linux/CI where KeePass.exe is not present. net48-only: WinForms unavailable on net8.0.

using System;
using System.Windows.Forms;

#pragma warning disable CA1050, CS8618

namespace KeePass.UI
{
    public sealed class GwmWindowEventArgs : EventArgs
    {
        public Form Form { get; }
        public GwmWindowEventArgs(Form form) { Form = form; }
    }

    public static class GlobalWindowManager
    {
        public static event EventHandler<GwmWindowEventArgs>? WindowAdded;

        // Allow tests / production code to raise the event.
        public static void RaiseWindowAdded(Form form)
            => WindowAdded?.Invoke(null, new GwmWindowEventArgs(form));
    }
}

namespace KeePass.Forms
{
    public class PwEntryForm : Form
    {
        public KeePassLib.PwEntry? EntryRef { get; set; }
    }
}

namespace KeePass
{
    // net48 partial extends MainForm to inherit Form so it satisfies IWin32Window (ShowDialog).
    public partial class MainForm : Form
    {
        // ToolsMenu stub: returns a ToolStripMenuItem whose DropDownItems can be mutated.
        private readonly ToolStripMenuItem _toolsMenu = new ToolStripMenuItem("Tools");
        public ToolStripMenuItem ToolsMenu => _toolsMenu;

        public void UpdateUI(bool bSetModified, object? pgSelect,
            bool bUpdateGroupList, object? pgList,
            bool bUpdateEntryList, object? peList,
            bool bSetModifiedList) { }
    }
}
#endif
