using System;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Defines the configuration for cryptographic algorithms.
    /// </summary>
    public class AlgorithmConfiguration
    {
        /// <summary>
        /// Gets the operating mode for the cryptographic system.
        /// </summary>
        public CryptographicMode Mode { get; }

        /// <summary>
        /// Gets the preferred post-quantum key encapsulation mechanism.
        /// </summary>
        public string PreferredKemAlgorithm { get; }

        /// <summary>
        /// Gets the preferred post-quantum signature algorithm.
        /// </summary>
        public string PreferredSignatureAlgorithm { get; }

        /// <summary>
        /// Gets the fallback classical key encapsulation mechanism.
        /// </summary>
        public string FallbackKemAlgorithm { get; }

        /// <summary>
        /// Gets the fallback classical signature algorithm.
        /// </summary>
        public string FallbackSignatureAlgorithm { get; }

        /// <summary>
        /// Gets the symmetric encryption algorithm to use.
        /// </summary>
        public string SymmetricAlgorithm { get; }

        /// <summary>
        /// Gets the hash algorithm to use for signatures.
        /// </summary>
        public string HashAlgorithm { get; }

        /// <summary>
        /// Gets a value indicating whether to always create dual signatures in hybrid mode.
        /// </summary>
        public bool AlwaysCreateDualSignatures { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlgorithmConfiguration"/> class.
        /// </summary>
        /// <param name="mode">The operating mode</param>
        /// <param name="preferredKemAlgorithm">The preferred PQC KEM algorithm</param>
        /// <param name="preferredSignatureAlgorithm">The preferred PQC signature algorithm</param>
        /// <param name="fallbackKemAlgorithm">The fallback classical KEM algorithm</param>
        /// <param name="fallbackSignatureAlgorithm">The fallback classical signature algorithm</param>
        /// <param name="symmetricAlgorithm">The symmetric encryption algorithm</param>
        /// <param name="hashAlgorithm">The hash algorithm for signatures</param>
        /// <param name="alwaysCreateDualSignatures">Whether to always create dual signatures in hybrid mode</param>
        public AlgorithmConfiguration(
            CryptographicMode mode,
            string preferredKemAlgorithm,
            string preferredSignatureAlgorithm,
            string fallbackKemAlgorithm,
            string fallbackSignatureAlgorithm,
            string symmetricAlgorithm,
            string hashAlgorithm,
            bool alwaysCreateDualSignatures = false)
        {
            Mode = mode;
            PreferredKemAlgorithm = preferredKemAlgorithm ?? throw new ArgumentNullException(nameof(preferredKemAlgorithm));
            PreferredSignatureAlgorithm = preferredSignatureAlgorithm ?? throw new ArgumentNullException(nameof(preferredSignatureAlgorithm));
            FallbackKemAlgorithm = fallbackKemAlgorithm ?? throw new ArgumentNullException(nameof(fallbackKemAlgorithm));
            FallbackSignatureAlgorithm = fallbackSignatureAlgorithm ?? throw new ArgumentNullException(nameof(fallbackSignatureAlgorithm));
            SymmetricAlgorithm = symmetricAlgorithm ?? throw new ArgumentNullException(nameof(symmetricAlgorithm));
            HashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            AlwaysCreateDualSignatures = alwaysCreateDualSignatures;
        }

        /// <summary>
        /// Creates a default configuration for hybrid mode with ML-KEM-768 and ML-DSA-65.
        /// </summary>
        /// <returns>A default algorithm configuration</returns>
        public static AlgorithmConfiguration CreateDefault()
        {
            return new AlgorithmConfiguration(
                mode: CryptographicMode.Hybrid,
                preferredKemAlgorithm: "ML-KEM-768",
                preferredSignatureAlgorithm: "ML-DSA-65",
                fallbackKemAlgorithm: "RSA-OAEP-2048",
                fallbackSignatureAlgorithm: "RSA-PSS-2048",
                symmetricAlgorithm: "AES-256-GCM",
                hashAlgorithm: "SHA-256",
                alwaysCreateDualSignatures: true
            );
        }

        /// <summary>
        /// Creates a configuration for PQC-only mode.
        /// </summary>
        /// <returns>A PQC-only algorithm configuration</returns>
        public static AlgorithmConfiguration CreatePostQuantumOnly()
        {
            return new AlgorithmConfiguration(
                mode: CryptographicMode.PostQuantumOnly,
                preferredKemAlgorithm: "ML-KEM-768",
                preferredSignatureAlgorithm: "ML-DSA-65",
                fallbackKemAlgorithm: "ML-KEM-1024", // Stronger PQC fallback
                fallbackSignatureAlgorithm: "ML-DSA-87", // Stronger PQC fallback
                symmetricAlgorithm: "AES-256-GCM",
                hashAlgorithm: "SHA-256",
                alwaysCreateDualSignatures: false
            );
        }

        /// <summary>
        /// Creates a configuration for classical-only mode (for compatibility testing).
        /// </summary>
        /// <returns>A classical-only algorithm configuration</returns>
        public static AlgorithmConfiguration CreateClassicalOnly()
        {
            return new AlgorithmConfiguration(
                mode: CryptographicMode.ClassicalOnly,
                preferredKemAlgorithm: "RSA-OAEP-2048",
                preferredSignatureAlgorithm: "RSA-PSS-2048",
                fallbackKemAlgorithm: "RSA-OAEP-4096",
                fallbackSignatureAlgorithm: "RSA-PSS-4096",
                symmetricAlgorithm: "AES-256-GCM",
                hashAlgorithm: "SHA-256",
                alwaysCreateDualSignatures: false
            );
        }
    }

    /// <summary>
    /// Defines the operating modes for the cryptographic system.
    /// </summary>
    public enum CryptographicMode
    {
        /// <summary>
        /// Use classical algorithms only (RSA, ECDSA).
        /// </summary>
        ClassicalOnly,

        /// <summary>
        /// Use post-quantum algorithms only.
        /// </summary>
        PostQuantumOnly,

        /// <summary>
        /// Use hybrid approach combining both PQC and classical algorithms.
        /// </summary>
        Hybrid
    }
}