using System;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;
using PassKee.Core.Ipc;
using PassKee.Core.Storage;
using Xunit;

namespace PassKee.Core.Tests.Ipc
{
    public class VaultHandlerTests
    {
        private static VaultHandler MakeHandler(out InMemoryPasskeyStore store)
        {
            store = new InMemoryPasskeyStore();
            return new VaultHandler(store);
        }

        // ── createPasskey ────────────────────────────────────────────────

        [Fact]
        public void CreatePasskey_ReturnsCredentialIdAuthDataAndPublicKey()
        {
            var handler = MakeHandler(out _);
            var result = (JObject)handler.Handle("passkee.createPasskey", new JObject
            {
                ["rpId"]            = "example.com",
                ["rpName"]          = "Example",
                ["userHandle"]      = "dXNlcjE",
                ["userName"]        = "user@example.com",
                ["userDisplayName"] = "Test User",
            })!;

            Assert.NotNull(result["credentialId"]?.Value<string>());
            Assert.NotNull(result["authData"]?.Value<string>());
            Assert.NotNull(result["publicKeyCose"]?.Value<string>());
        }

        [Fact]
        public void CreatePasskey_StoresRecordInVault()
        {
            var handler = MakeHandler(out var store);
            var result = (JObject)handler.Handle("passkee.createPasskey", new JObject
            {
                ["rpId"]       = "example.com",
                ["userHandle"] = "dXNlcjE",
                ["userName"]   = "user@example.com",
            })!;

            var credId = result["credentialId"]!.Value<string>()!;
            var record = store.FindById(credId);
            Assert.NotNull(record);
            Assert.Equal("example.com", record!.RpId);
            Assert.Equal("user@example.com", record.UserName);
        }

        [Fact]
        public void CreatePasskey_AuthDataContainsRpIdHash()
        {
            var handler = MakeHandler(out _);
            var result = (JObject)handler.Handle("passkee.createPasskey", new JObject
            {
                ["rpId"]       = "example.com",
                ["userHandle"] = "dXNlcjE",
                ["userName"]   = "user@example.com",
            })!;

            var authDataBytes = Convert.FromBase64String(result["authData"]!.Value<string>()!);
            var expectedHash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("example.com"));
            Assert.Equal(expectedHash, authDataBytes[..32]);
        }

        [Fact]
        public void CreatePasskey_MissingRpId_Throws()
        {
            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.createPasskey", new JObject
                {
                    ["userHandle"] = "dXNlcjE",
                    ["userName"]   = "u",
                }));
            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
        }

        [Fact]
        public void CreatePasskey_VaultLocked_Throws()
        {
            var handler = MakeHandler(out var store);
            store.IsVaultOpen = false;
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.createPasskey", new JObject
                {
                    ["rpId"] = "x", ["userHandle"] = "y", ["userName"] = "z",
                }));
            Assert.Equal(RpcErrorCode.VaultLocked, ex.Code);
        }

        // ── listCredentials ─────────────────────────────────────────────

        [Fact]
        public void ListCredentials_ReturnsOnlyMatchingRpId()
        {
            var handler = MakeHandler(out var store);
            store.Add(new PasskeyRecord { CredentialId = "a", RpId = "example.com", UserName = "u1", UserHandle = "h1" });
            store.Add(new PasskeyRecord { CredentialId = "b", RpId = "other.com", UserName = "u2", UserHandle = "h2" });

            var result = (JArray)handler.Handle("passkee.listCredentials", new JObject
                { ["rpId"] = "example.com" })!;

            Assert.Single(result);
            Assert.Equal("a", result[0]["credentialId"]?.Value<string>());
        }

        [Fact]
        public void ListCredentials_EmptyWhenNoMatch()
        {
            var handler = MakeHandler(out _);
            var result = (JArray)handler.Handle("passkee.listCredentials",
                new JObject { ["rpId"] = "nobody.com" })!;
            Assert.Empty(result);
        }

        // ── signAssertion ────────────────────────────────────────────────

        private static PasskeyRecord CreateStoredRecord(IPasskeyStore store, string rpId = "example.com")
        {
            var (pkcs8, x, y) = PassKee.Core.Crypto.EcdsaSigner.GenerateKeyPair();
            var record = new PasskeyRecord
            {
                CredentialId    = "test-cred-id",
                RpId            = rpId,
                RpName          = rpId,
                UserHandle      = "dXNlcjE",
                UserName        = "user",
                UserDisplayName = "User",
                PrivateKeyPkcs8 = Convert.ToBase64String(pkcs8),
                PublicKeyCose   = PassKee.Core.Cbor.CoseKey.Encode(x, y),
            };
            store.Add(record);
            return record;
        }

        [Fact]
        public void SignAssertion_ReturnsVerifiableSignature()
        {
            var handler = MakeHandler(out var store);
            var record = CreateStoredRecord(store);

            var authDataBytes     = new byte[37]; // minimal valid authData length
            var clientDataHash    = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("{}"));

            var result = (JObject)handler.Handle("passkee.signAssertion", new JObject
            {
                ["credentialId"]    = record.CredentialId,
                ["authData"]        = Convert.ToBase64String(authDataBytes),
                ["clientDataHash"]  = Convert.ToBase64String(clientDataHash),
            })!;

            var sigBytes = Convert.FromBase64String(result["signature"]!.Value<string>()!);

            // Reconstruct public key from PKCS#8 private key to verify.
            var pkcs8 = Convert.FromBase64String(record.PrivateKeyPkcs8);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(pkcs8, out _);
            var pubParams = ecdsa.ExportParameters(false);
            using var pubKey = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = pubParams.Q
            });

            // signInput = authData || clientDataHash
            var signInput = new byte[authDataBytes.Length + clientDataHash.Length];
            Buffer.BlockCopy(authDataBytes, 0, signInput, 0, authDataBytes.Length);
            Buffer.BlockCopy(clientDataHash, 0, signInput, authDataBytes.Length, clientDataHash.Length);

            bool valid = pubKey.VerifyData(signInput, sigBytes,
                HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            Assert.True(valid);
        }

        [Fact]
        public void SignAssertion_CredentialNotFound_Throws()
        {
            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.signAssertion", new JObject
                {
                    ["credentialId"]   = "nonexistent",
                    ["authData"]       = Convert.ToBase64String(new byte[37]),
                    ["clientDataHash"] = Convert.ToBase64String(new byte[32]),
                }));
            Assert.Equal(RpcErrorCode.CredentialNotFound, ex.Code);
        }

        [Fact]
        public void SignAssertion_InvalidBase64_Throws()
        {
            var handler = MakeHandler(out var store);
            CreateStoredRecord(store);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.signAssertion", new JObject
                {
                    ["credentialId"]   = "test-cred-id",
                    ["authData"]       = "!!!not-base64!!!",
                    ["clientDataHash"] = Convert.ToBase64String(new byte[32]),
                }));
            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
        }

        // ── deleteCredential ─────────────────────────────────────────────

        [Fact]
        public void DeleteCredential_ReturnsTrueWhenFound()
        {
            var handler = MakeHandler(out var store);
            CreateStoredRecord(store);

            var result = (JObject)handler.Handle("passkee.deleteCredential",
                new JObject { ["credentialId"] = "test-cred-id" })!;

            Assert.True(result["deleted"]?.Value<bool>());
            Assert.Null(store.FindById("test-cred-id"));
        }

        [Fact]
        public void DeleteCredential_ReturnsFalseWhenNotFound()
        {
            var handler = MakeHandler(out _);
            var result = (JObject)handler.Handle("passkee.deleteCredential",
                new JObject { ["credentialId"] = "no-such-id" })!;

            Assert.False(result["deleted"]?.Value<bool>());
        }

        // ── enumerateForSync ─────────────────────────────────────────────

        [Fact]
        public void EnumerateForSync_ReturnsAllRecords()
        {
            var handler = MakeHandler(out var store);
            store.Add(new PasskeyRecord { CredentialId = "a", RpId = "a.com", UserName = "u1", UserHandle = "h1" });
            store.Add(new PasskeyRecord { CredentialId = "b", RpId = "b.com", UserName = "u2", UserHandle = "h2" });

            var result = (JArray)handler.Handle("passkee.enumerateForSync", null)!;

            Assert.Equal(2, result.Count);
        }

        [Fact]
        public void EnumerateForSync_IncludesRequiredFields()
        {
            var handler = MakeHandler(out var store);
            store.Add(new PasskeyRecord
            {
                CredentialId    = "cred-1",
                RpId            = "rp.com",
                RpName          = "RP Name",
                UserHandle      = "uh",
                UserName        = "user",
                UserDisplayName = "User Name",
                AlgId           = -7,
            });

            var result = (JArray)handler.Handle("passkee.enumerateForSync", null)!;
            var item = (JObject)result[0];

            Assert.Equal("cred-1",    item["credentialId"]?.Value<string>());
            Assert.Equal("rp.com",    item["rpId"]?.Value<string>());
            Assert.Equal("RP Name",   item["rpName"]?.Value<string>());
            Assert.Equal(-7,          item["algId"]?.Value<int>());
        }

        // ── unknown method ───────────────────────────────────────────────

        [Fact]
        public void UnknownMethod_ThrowsMethodNotFound()
        {
            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.unknownMethod", null));
            Assert.Equal(RpcErrorCode.MethodNotFound, ex.Code);
        }
    }
}
