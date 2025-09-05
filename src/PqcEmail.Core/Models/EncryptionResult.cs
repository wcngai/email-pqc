using System;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Represents the result of an encryption operation.
    /// </summary>
    public class EncryptionResult
    {
        /// <summary>
        /// Gets the encrypted data.
        /// </summary>
        public byte[] EncryptedData { get; }

        /// <summary>
        /// Gets the algorithm used for encryption.
        /// </summary>
        public string Algorithm { get; }

        /// <summary>
        /// Gets additional metadata about the encryption operation.
        /// </summary>
        public EncryptionMetadata Metadata { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionResult"/> class.
        /// </summary>
        /// <param name="encryptedData">The encrypted data</param>
        /// <param name="algorithm">The algorithm used for encryption</param>
        /// <param name="metadata">Additional metadata about the encryption operation</param>
        public EncryptionResult(byte[] encryptedData, string algorithm, EncryptionMetadata metadata)
        {
            EncryptedData = encryptedData ?? throw new ArgumentNullException(nameof(encryptedData));
            Algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        }
    }

    /// <summary>
    /// Contains metadata about an encryption operation.
    /// </summary>
    public class EncryptionMetadata
    {
        /// <summary>
        /// Gets the timestamp when the encryption was performed.
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Gets a value indicating whether PQC algorithms were used.
        /// </summary>
        public bool IsPostQuantum { get; }

        /// <summary>
        /// Gets a value indicating whether hybrid mode was used.
        /// </summary>
        public bool IsHybrid { get; }

        /// <summary>
        /// Gets the classical algorithm used in hybrid mode, if any.
        /// </summary>
        public string? ClassicalAlgorithm { get; }

        /// <summary>
        /// Gets the post-quantum algorithm used, if any.
        /// </summary>
        public string? PostQuantumAlgorithm { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionMetadata"/> class.
        /// </summary>
        /// <param name="timestamp">The timestamp when the encryption was performed</param>
        /// <param name="isPostQuantum">Whether PQC algorithms were used</param>
        /// <param name="isHybrid">Whether hybrid mode was used</param>
        /// <param name="classicalAlgorithm">The classical algorithm used in hybrid mode</param>
        /// <param name="postQuantumAlgorithm">The post-quantum algorithm used</param>
        public EncryptionMetadata(DateTime timestamp, bool isPostQuantum, bool isHybrid, 
            string? classicalAlgorithm = null, string? postQuantumAlgorithm = null)
        {
            Timestamp = timestamp;
            IsPostQuantum = isPostQuantum;
            IsHybrid = isHybrid;
            ClassicalAlgorithm = classicalAlgorithm;
            PostQuantumAlgorithm = postQuantumAlgorithm;
        }
    }
}