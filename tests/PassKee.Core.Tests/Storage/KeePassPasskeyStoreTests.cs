using System;
using System.Linq;
using KeePass.Plugins;
using KeePass.Program;
using KeePassLib;
using PassKee.Core.Storage;
using PassKee.Plugin.Storage;
using Xunit;

namespace PassKee.Core.Tests.Storage
{
    public class KeePassPasskeyStoreTests
    {
        private sealed class FakePluginHost : IPluginHost
        {
            public KeePass.MainForm MainWindow { get; } = new KeePass.MainForm();
            public PwDatabase? Database { get; }

            public FakePluginHost(bool dbOpen)
            {
                if (dbOpen) Database = new PwDatabase { IsOpen = true };
            }
        }

        private static PasskeyRecord MakeRecord(string credId = "cred1", string rpId = "example.com") =>
            new PasskeyRecord
            {
                CredentialId    = credId,
                RpId            = rpId,
                RpName          = "Example",
                UserHandle      = "dXNlcjE",
                UserName        = "alice@example.com",
                UserDisplayName = "Alice",
                AlgId           = -7,
                PrivateKeyPkcs8 = "privatekeydata",
                PublicKeyCose   = new byte[] { 0x01, 0x02, 0x03 },
                Transports      = "internal",
                Flags           = "",
                CreationTime    = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                LastUsedTime    = new DateTime(2026, 4, 1, 12, 0, 0, DateTimeKind.Utc),
            };

        // --- IsVaultOpen ---

        [Fact]
        public void IsVaultOpen_DatabaseNull_ReturnsFalse()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: false));
            Assert.False(store.IsVaultOpen);
        }

        [Fact]
        public void IsVaultOpen_DatabaseOpen_ReturnsTrue()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            Assert.True(store.IsVaultOpen);
        }

        // --- Add + FindById round-trip ---

        [Fact]
        public void Add_ThenFindById_ReturnsRecord()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            var record = MakeRecord();

            store.Add(record);
            var found = store.FindById(record.CredentialId);

            Assert.NotNull(found);
            Assert.Equal(record.CredentialId, found!.CredentialId);
        }

        [Fact]
        public void Add_PreservesAllStringFields()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            var record = MakeRecord();

            store.Add(record);
            var found = store.FindById(record.CredentialId)!;

            Assert.Equal(record.RpId,            found.RpId);
            Assert.Equal(record.RpName,           found.RpName);
            Assert.Equal(record.UserHandle,       found.UserHandle);
            Assert.Equal(record.UserName,         found.UserName);
            Assert.Equal(record.UserDisplayName,  found.UserDisplayName);
            Assert.Equal(record.PrivateKeyPkcs8,  found.PrivateKeyPkcs8);
        }

        [Fact]
        public void Add_PreservesAlgId()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            var record = MakeRecord();

            store.Add(record);
            var found = store.FindById(record.CredentialId)!;

            Assert.Equal(-7, found.AlgId);
        }

        [Fact]
        public void Add_PreservesPublicKeyCose()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            var record = MakeRecord();

            store.Add(record);
            var found = store.FindById(record.CredentialId)!;

            Assert.Equal(record.PublicKeyCose, found.PublicKeyCose);
        }

        [Fact]
        public void Add_PreservesTransportsAndFlags()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            var record = MakeRecord();
            record.Transports = "internal,usb";
            record.Flags      = "uv";

            store.Add(record);
            var found = store.FindById(record.CredentialId)!;

            Assert.Equal("internal,usb", found.Transports);
            Assert.Equal("uv",           found.Flags);
        }

        [Fact]
        public void Add_PreservesDateTimes()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            var record = MakeRecord();

            store.Add(record);
            var found = store.FindById(record.CredentialId)!;

            Assert.Equal(record.CreationTime, found.CreationTime);
            Assert.Equal(record.LastUsedTime, found.LastUsedTime);
        }

        [Fact]
        public void Add_PrivateKeyIsProtectedString()
        {
            var host = new FakePluginHost(dbOpen: true);
            var store = new KeePassPasskeyStore(host);
            var record = MakeRecord();

            store.Add(record);

            var group = host.Database!.RootGroup.Groups.GetAt(0);
            var entry = group.Entries.GetAt(0);
            var ps    = entry.Strings.Get("PassKee.privateKey");

            Assert.NotNull(ps);
            Assert.True(ps!.IsProtected);
        }

        [Fact]
        public void Add_SetsReadableTitleOnEntry()
        {
            var host = new FakePluginHost(dbOpen: true);
            var store = new KeePassPasskeyStore(host);
            var record = MakeRecord();

            store.Add(record);

            var group = host.Database!.RootGroup.Groups.GetAt(0);
            var entry = group.Entries.GetAt(0);
            var title = entry.Strings.Get("Title")?.ReadString();

            Assert.Equal("Example / Alice", title);
        }

        // --- Group management ---

        [Fact]
        public void Add_CreatesPasskeysGroupWhenAbsent()
        {
            var host = new FakePluginHost(dbOpen: true);
            var store = new KeePassPasskeyStore(host);

            Assert.Equal(0, (int)host.Database!.RootGroup.Groups.UCount);

            store.Add(MakeRecord());

            Assert.Equal(1, (int)host.Database!.RootGroup.Groups.UCount);
            Assert.Equal("Passkeys", host.Database!.RootGroup.Groups.GetAt(0).Name);
        }

        [Fact]
        public void Add_ReusesExistingPasskeysGroup()
        {
            var host = new FakePluginHost(dbOpen: true);
            var store = new KeePassPasskeyStore(host);

            store.Add(MakeRecord("cred1"));
            store.Add(MakeRecord("cred2"));

            Assert.Equal(1, (int)host.Database!.RootGroup.Groups.UCount);
        }

        // --- FindByRpId ---

        [Fact]
        public void FindByRpId_ReturnsMatchingRecords()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            store.Add(MakeRecord("c1", "example.com"));
            store.Add(MakeRecord("c2", "example.com"));
            store.Add(MakeRecord("c3", "other.com"));

            var results = store.FindByRpId("example.com");

            Assert.Equal(2, results.Count);
            Assert.All(results, r => Assert.Equal("example.com", r.RpId));
        }

        [Fact]
        public void FindByRpId_NoMatch_ReturnsEmpty()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            store.Add(MakeRecord("c1", "example.com"));

            var results = store.FindByRpId("nope.com");

            Assert.Empty(results);
        }

        [Fact]
        public void FindByRpId_VaultClosed_ReturnsEmpty()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: false));
            Assert.Empty(store.FindByRpId("example.com"));
        }

        // --- FindById ---

        [Fact]
        public void FindById_NotFound_ReturnsNull()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            Assert.Null(store.FindById("missing"));
        }

        [Fact]
        public void FindById_VaultClosed_ReturnsNull()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: false));
            Assert.Null(store.FindById("cred1"));
        }

        // --- Delete ---

        [Fact]
        public void Delete_ExistingCredential_ReturnsTrueAndRemoves()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            store.Add(MakeRecord("cred1"));

            Assert.True(store.Delete("cred1"));
            Assert.Null(store.FindById("cred1"));
        }

        [Fact]
        public void Delete_Missing_ReturnsFalse()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            Assert.False(store.Delete("nope"));
        }

        [Fact]
        public void Delete_VaultClosed_ReturnsFalse()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: false));
            Assert.False(store.Delete("cred1"));
        }

        // --- GetAll ---

        [Fact]
        public void GetAll_ReturnsAllEntries()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: true));
            store.Add(MakeRecord("c1", "a.com"));
            store.Add(MakeRecord("c2", "b.com"));
            store.Add(MakeRecord("c3", "c.com"));

            var all = store.GetAll();

            Assert.Equal(3, all.Count);
        }

        [Fact]
        public void GetAll_VaultClosed_ReturnsEmpty()
        {
            var store = new KeePassPasskeyStore(new FakePluginHost(dbOpen: false));
            Assert.Empty(store.GetAll());
        }
    }
}
