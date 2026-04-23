namespace KeePassKeyWin.Core.Security
{
    /// <summary>
    /// Named constants for the emergency bypass environment variables used to
    /// disable cryptographic verification gates during development or testing.
    ///
    /// <para>
    /// <b>Do not enable in production.</b> Setting any of these variables disables
    /// a security-critical verification step, making it impossible to detect a
    /// compromised or replaced sidecar binary.
    /// </para>
    ///
    /// <para>
    /// <b>Rust analogue</b>: the sidecar-side bypass for request-signature
    /// verification is <c>KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY</c>, documented in
    /// <c>src/KeePassKeyWin.Provider/src/com/request_sig.rs</c>.
    /// </para>
    ///
    /// <para>
    /// Each constant names the variable that controls plugin-side verification.
    /// The variables are consumed by the plugin (not the sidecar) and are checked
    /// at the point where the verification would normally occur. A value of
    /// <c>"1"</c>, <c>"true"</c>, or <c>"yes"</c> (case-insensitive) enables the bypass;
    /// any other value (or absence) leaves verification enabled.
    /// </para>
    /// </summary>
    public static class BypassEnvVars
    {
        /// <summary>
        /// When set to a truthy value (<c>"1"</c>, <c>"true"</c>, <c>"yes"</c>),
        /// plugin-side signature verification is skipped entirely — both
        /// <c>pbRequestSignature</c> verification (Phase 5.UV.2) and UV signature
        /// verification (Phase 5.UV.4).
        ///
        /// <para><b>Do not enable in production.</b></para>
        /// </summary>
        public const string SkipPluginSigVerify = "KEEPASSKEYWIN_SKIP_PLUGIN_SIG_VERIFY";
    }
}
