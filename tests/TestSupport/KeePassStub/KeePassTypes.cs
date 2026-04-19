// Minimal surface of KeePass.exe types needed to compile PassKee.Plugin when
// the real KeePass.exe is not present (Linux/CI builds).
// This assembly must produce the same public API shape as KeePass.exe — no logic.
//
// Keep types + namespaces faithful to real KeePass. We learned the hard way
// (WSL2 → Win11 2026-04-18) that stub drift (PwEntry parameterless ctor,
// ProtectedString in KeePassLib instead of KeePassLib.Security) compiles on
// Linux but fails on Windows. If you add or rename a member here, verify
// against the real KeePassLib signatures before committing.

using System;
using System.Collections.Generic;
using KeePassLib.Interfaces;
using KeePassLib.Security;

#pragma warning disable CA1050, CS8618

namespace KeePass.Plugins
{
    public abstract class Plugin
    {
        public virtual bool Initialize(IPluginHost host) => true;
        public virtual void Terminate() { }
        public virtual string UpdateUrl => string.Empty;
    }

    public interface IPluginHost
    {
        MainForm MainWindow { get; }
        KeePass.Program.PwDatabase? Database { get; }
    }
}

namespace KeePass.Program
{
    public sealed class PwDatabase
    {
        public bool IsOpen { get; set; }
        public KeePassLib.PwGroup RootGroup { get; set; } = new KeePassLib.PwGroup();

        /// <summary>
        /// Real KeePassLib signature: <c>bool Save(IStatusLogger sLogger)</c>.
        /// The plugin passes <c>null</c> for non-interactive saves. The stub
        /// flips a test-visible flag so tests can assert synchronous persistence.
        /// </summary>
        public int SaveCallCount { get; private set; }
        public bool Save(IStatusLogger? sLogger)
        {
            SaveCallCount++;
            return true;
        }
    }
}

namespace KeePassLib
{
    public sealed class PwGroup
    {
        public string Name { get; set; } = string.Empty;
        public PwObjectList<PwGroup> Groups { get; } = new PwObjectList<PwGroup>();
        public PwObjectList<PwEntry> Entries { get; } = new PwObjectList<PwEntry>();

        public void AddEntry(PwEntry entry, bool bTakeOwnership) => Entries.Add(entry);
        public void AddGroup(PwGroup group, bool bTakeOwnership) => Groups.Add(group);
    }

    public sealed class PwEntry
    {
        // Real KeePass PwEntry has no parameterless ctor. Mirror the (bool, bool)
        // signature exactly so production code using `new PwEntry(true, true)`
        // compiles against both stub and real.
        public PwEntry(bool bCreateNewUuid, bool bSetTimes) { }

        public PwStringDictionary Strings { get; } = new PwStringDictionary();
        public PwBinaryDictionary Binaries { get; } = new PwBinaryDictionary();
        public StringDictionaryEx CustomData { get; } = new StringDictionaryEx();

        /// <summary>
        /// Real KeePassLib signature: <c>void Touch(bool bModified, bool bTouchParents)</c>.
        /// Bumps LastModificationTime on the entry (and parents when requested).
        /// No-op in the stub; tests assert via the Save counter instead.
        /// </summary>
        public void Touch(bool bModified, bool bTouchParents) { }
    }

    public sealed class PwObjectList<T>
    {
        private readonly List<T> _list = new List<T>();
        public int UCount => _list.Count;
        public T GetAt(uint idx) => _list[(int)idx];
        public void Add(T item) => _list.Add(item);
        public void Remove(T item) => _list.Remove(item);
    }

    public sealed class PwStringDictionary
    {
        private readonly Dictionary<string, ProtectedString> _d = new Dictionary<string, ProtectedString>();
        public ProtectedString? Get(string key) => _d.TryGetValue(key, out var v) ? v : null;
        public void Set(string key, ProtectedString value) => _d[key] = value;
        public bool Exists(string key) => _d.ContainsKey(key);
        public void Remove(string key) => _d.Remove(key);
    }

    public sealed class PwBinaryDictionary
    {
        private readonly Dictionary<string, ProtectedBinary> _d = new Dictionary<string, ProtectedBinary>();
        public ProtectedBinary? Get(string key) => _d.TryGetValue(key, out var v) ? v : null;
        public void Set(string key, ProtectedBinary value) => _d[key] = value;
        public bool Exists(string key) => _d.ContainsKey(key);
    }

    public sealed class StringDictionaryEx
    {
        private readonly Dictionary<string, string> _d = new Dictionary<string, string>();
        public string? Get(string key) => _d.TryGetValue(key, out var v) ? v : null;
        public void Set(string key, string value) => _d[key] = value;
        public bool Exists(string key) => _d.ContainsKey(key);
        public void Remove(string key) => _d.Remove(key);
    }
}

namespace KeePassLib.Interfaces
{
    /// <summary>
    /// Minimal stub of <c>KeePassLib.Interfaces.IStatusLogger</c> — the parameter
    /// type of <c>PwDatabase.Save</c>. Plugin passes <c>null</c> for non-interactive
    /// saves so no members are required; the type exists only to satisfy the
    /// signature against real KeePassLib.
    /// </summary>
    public interface IStatusLogger { }
}

namespace KeePassLib.Security
{
    public sealed class ProtectedString
    {
        public bool IsProtected { get; }
        private readonly string _value;
        public ProtectedString(bool bProtect, string str) { IsProtected = bProtect; _value = str; }
        public string ReadString() => _value;
    }

    public sealed class ProtectedBinary
    {
        private readonly byte[] _data;
        public bool IsProtected { get; }
        public int Length => _data.Length;
        public ProtectedBinary(bool bProtect, byte[] data) { IsProtected = bProtect; _data = (byte[])data.Clone(); }
        public byte[] ReadData() => (byte[])_data.Clone();
    }
}

// Stub MainForm — cross-platform members. WinForms members are in KeePassUiTypes.cs (net48 only).
namespace KeePass
{
    public partial class MainForm
    {
        public void SetStatusEx(string str) { }

#if !NET48
        // net8.0 / CI: no WinForms — IsHandleCreated = false so the store skips BeginInvoke.
        public bool IsHandleCreated => false;
        public System.IAsyncResult BeginInvoke(Delegate method) => default!;
        public void UpdateUI(bool bSetModified, object? pgSelect,
            bool bUpdateGroupList, object? pgList,
            bool bUpdateEntryList, object? peList,
            bool bSetModifiedList) { }
#endif
    }
}
