using System;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Represents the result of a signature operation.
    /// </summary>
    public class SignatureResult
    {
        /// <summary>
        /// Gets the signature data.
        /// </summary>
        public byte[] SignatureData { get; }

        /// <summary>
        /// Gets the algorithm used for signing.
        /// </summary>
        public string Algorithm { get; }

        /// <summary>
        /// Gets additional metadata about the signature operation.
        /// </summary>
        public SignatureMetadata Metadata { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureResult"/> class.
        /// </summary>
        /// <param name="signatureData">The signature data</param>
        /// <param name="algorithm">The algorithm used for signing</param>
        /// <param name="metadata">Additional metadata about the signature operation</param>
        public SignatureResult(byte[] signatureData, string algorithm, SignatureMetadata metadata)
        {
            SignatureData = signatureData ?? throw new ArgumentNullException(nameof(signatureData));
            Algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        }
    }

    /// <summary>
    /// Contains metadata about a signature operation.
    /// </summary>
    public class SignatureMetadata
    {
        /// <summary>
        /// Gets the timestamp when the signature was created.
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Gets a value indicating whether PQC algorithms were used.
        /// </summary>
        public bool IsPostQuantum { get; }

        /// <summary>
        /// Gets a value indicating whether dual signatures were created.
        /// </summary>
        public bool IsDualSignature { get; }

        /// <summary>
        /// Gets the classical algorithm used in dual signature mode, if any.
        /// </summary>
        public string? ClassicalAlgorithm { get; }

        /// <summary>
        /// Gets the post-quantum algorithm used, if any.
        /// </summary>
        public string? PostQuantumAlgorithm { get; }

        /// <summary>
        /// Gets the hash algorithm used for the signature.
        /// </summary>
        public string HashAlgorithm { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureMetadata"/> class.
        /// </summary>
        /// <param name="timestamp">The timestamp when the signature was created</param>
        /// <param name="isPostQuantum">Whether PQC algorithms were used</param>
        /// <param name="isDualSignature">Whether dual signatures were created</param>
        /// <param name="hashAlgorithm">The hash algorithm used for the signature</param>
        /// <param name="classicalAlgorithm">The classical algorithm used in dual signature mode</param>
        /// <param name="postQuantumAlgorithm">The post-quantum algorithm used</param>
        public SignatureMetadata(DateTime timestamp, bool isPostQuantum, bool isDualSignature, 
            string hashAlgorithm, string? classicalAlgorithm = null, string? postQuantumAlgorithm = null)
        {
            Timestamp = timestamp;
            IsPostQuantum = isPostQuantum;
            IsDualSignature = isDualSignature;
            HashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            ClassicalAlgorithm = classicalAlgorithm;
            PostQuantumAlgorithm = postQuantumAlgorithm;
        }
    }
}