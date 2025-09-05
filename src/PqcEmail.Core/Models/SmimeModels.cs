using System;
using System.Collections.Generic;
using System.Linq;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Represents an email message before encryption/after decryption.
    /// </summary>
    public class EmailMessage
    {
        /// <summary>
        /// Gets the sender's email address.
        /// </summary>
        public string From { get; }

        /// <summary>
        /// Gets the recipient email addresses.
        /// </summary>
        public IReadOnlyList<string> To { get; }

        /// <summary>
        /// Gets the CC recipient email addresses.
        /// </summary>
        public IReadOnlyList<string> Cc { get; }

        /// <summary>
        /// Gets the BCC recipient email addresses.
        /// </summary>
        public IReadOnlyList<string> Bcc { get; }

        /// <summary>
        /// Gets the email subject.
        /// </summary>
        public string Subject { get; }

        /// <summary>
        /// Gets the email body content.
        /// </summary>
        public string Body { get; }

        /// <summary>
        /// Gets the email attachments.
        /// </summary>
        public IReadOnlyList<EmailAttachment> Attachments { get; }

        /// <summary>
        /// Gets additional email headers.
        /// </summary>
        public IReadOnlyDictionary<string, string> Headers { get; }

        /// <summary>
        /// Gets the content type of the body (text/plain, text/html, etc.).
        /// </summary>
        public string ContentType { get; }

        /// <summary>
        /// Gets the timestamp when the message was created.
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="EmailMessage"/> class.
        /// </summary>
        public EmailMessage(
            string from,
            IEnumerable<string> to,
            IEnumerable<string>? cc = null,
            IEnumerable<string>? bcc = null,
            string subject = "",
            string body = "",
            IEnumerable<EmailAttachment>? attachments = null,
            IDictionary<string, string>? headers = null,
            string contentType = "text/plain",
            DateTime? timestamp = null)
        {
            From = from ?? throw new ArgumentNullException(nameof(from));
            To = to?.ToList().AsReadOnly() ?? throw new ArgumentNullException(nameof(to));
            Cc = cc?.ToList().AsReadOnly() ?? new List<string>().AsReadOnly();
            Bcc = bcc?.ToList().AsReadOnly() ?? new List<string>().AsReadOnly();
            Subject = subject ?? "";
            Body = body ?? "";
            Attachments = attachments?.ToList().AsReadOnly() ?? new List<EmailAttachment>().AsReadOnly();
            Headers = headers?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value) ?? new Dictionary<string, string>();
            ContentType = contentType ?? "text/plain";
            Timestamp = timestamp ?? DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Represents an email attachment.
    /// </summary>
    public class EmailAttachment
    {
        /// <summary>
        /// Gets the attachment filename.
        /// </summary>
        public string FileName { get; }

        /// <summary>
        /// Gets the attachment content type.
        /// </summary>
        public string ContentType { get; }

        /// <summary>
        /// Gets the attachment data.
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// Gets the content disposition (attachment, inline, etc.).
        /// </summary>
        public string ContentDisposition { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="EmailAttachment"/> class.
        /// </summary>
        public EmailAttachment(string fileName, string contentType, byte[] data, string contentDisposition = "attachment")
        {
            FileName = fileName ?? throw new ArgumentNullException(nameof(fileName));
            ContentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
            Data = data ?? throw new ArgumentNullException(nameof(data));
            ContentDisposition = contentDisposition ?? "attachment";
        }
    }

    /// <summary>
    /// Represents an S/MIME encrypted message.
    /// </summary>
    public class SmimeEncryptedMessage
    {
        /// <summary>
        /// Gets the encrypted message data in CMS EnvelopedData format.
        /// </summary>
        public byte[] EncryptedData { get; }

        /// <summary>
        /// Gets the list of recipient infos including KEMRecipientInfo structures.
        /// </summary>
        public IReadOnlyList<RecipientInfo> RecipientInfos { get; }

        /// <summary>
        /// Gets the content encryption algorithm used.
        /// </summary>
        public string ContentEncryptionAlgorithm { get; }

        /// <summary>
        /// Gets the encryption metadata.
        /// </summary>
        public SmimeEncryptionMetadata Metadata { get; }

        /// <summary>
        /// Gets the original message headers that are preserved outside encryption.
        /// </summary>
        public IReadOnlyDictionary<string, string> UnprotectedHeaders { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SmimeEncryptedMessage"/> class.
        /// </summary>
        public SmimeEncryptedMessage(
            byte[] encryptedData,
            IEnumerable<RecipientInfo> recipientInfos,
            string contentEncryptionAlgorithm,
            SmimeEncryptionMetadata metadata,
            IDictionary<string, string>? unprotectedHeaders = null)
        {
            EncryptedData = encryptedData ?? throw new ArgumentNullException(nameof(encryptedData));
            RecipientInfos = recipientInfos?.ToList().AsReadOnly() ?? throw new ArgumentNullException(nameof(recipientInfos));
            ContentEncryptionAlgorithm = contentEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(contentEncryptionAlgorithm));
            Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
            UnprotectedHeaders = unprotectedHeaders?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value) ?? new Dictionary<string, string>();
        }
    }

    /// <summary>
    /// Represents an S/MIME signed message.
    /// </summary>
    public class SmimeSignedMessage
    {
        /// <summary>
        /// Gets the signed message data in CMS SignedData format.
        /// </summary>
        public byte[] SignedData { get; }

        /// <summary>
        /// Gets the original message content.
        /// </summary>
        public EmailMessage OriginalMessage { get; }

        /// <summary>
        /// Gets the signature information.
        /// </summary>
        public IReadOnlyList<SignatureInfo> Signatures { get; }

        /// <summary>
        /// Gets the signing certificates.
        /// </summary>
        public IReadOnlyList<CertificateInfo> Certificates { get; }

        /// <summary>
        /// Gets the signing metadata.
        /// </summary>
        public SmimeSigningMetadata Metadata { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SmimeSignedMessage"/> class.
        /// </summary>
        public SmimeSignedMessage(
            byte[] signedData,
            EmailMessage originalMessage,
            IEnumerable<SignatureInfo> signatures,
            IEnumerable<CertificateInfo> certificates,
            SmimeSigningMetadata metadata)
        {
            SignedData = signedData ?? throw new ArgumentNullException(nameof(signedData));
            OriginalMessage = originalMessage ?? throw new ArgumentNullException(nameof(originalMessage));
            Signatures = signatures?.ToList().AsReadOnly() ?? throw new ArgumentNullException(nameof(signatures));
            Certificates = certificates?.ToList().AsReadOnly() ?? throw new ArgumentNullException(nameof(certificates));
            Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        }
    }

    /// <summary>
    /// Represents a recipient with their cryptographic capabilities for S/MIME operations.
    /// </summary>
    public class SmimeRecipient
    {
        /// <summary>
        /// Gets the recipient's email address.
        /// </summary>
        public string EmailAddress { get; }

        /// <summary>
        /// Gets the recipient's certificate information.
        /// </summary>
        public CertificateInfo Certificate { get; }

        /// <summary>
        /// Gets the recipient's cryptographic capabilities.
        /// </summary>
        public RecipientCapabilities Capabilities { get; }

        /// <summary>
        /// Gets the preferred encryption strategy for this recipient.
        /// </summary>
        public EncryptionStrategy PreferredStrategy { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SmimeRecipient"/> class.
        /// </summary>
        public SmimeRecipient(
            string emailAddress,
            CertificateInfo certificate,
            RecipientCapabilities capabilities,
            EncryptionStrategy preferredStrategy = EncryptionStrategy.Auto)
        {
            EmailAddress = emailAddress ?? throw new ArgumentNullException(nameof(emailAddress));
            Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            Capabilities = capabilities ?? throw new ArgumentNullException(nameof(capabilities));
            PreferredStrategy = preferredStrategy;
        }
    }

    /// <summary>
    /// Represents private keys for S/MIME operations.
    /// </summary>
    public class SmimePrivateKeys
    {
        /// <summary>
        /// Gets the post-quantum private key for encryption/decryption.
        /// </summary>
        public byte[]? PostQuantumEncryptionKey { get; }

        /// <summary>
        /// Gets the classical private key for encryption/decryption.
        /// </summary>
        public byte[]? ClassicalEncryptionKey { get; }

        /// <summary>
        /// Gets the post-quantum private key for signing.
        /// </summary>
        public byte[]? PostQuantumSigningKey { get; }

        /// <summary>
        /// Gets the classical private key for signing.
        /// </summary>
        public byte[]? ClassicalSigningKey { get; }

        /// <summary>
        /// Gets the algorithm identifiers for the keys.
        /// </summary>
        public SmimeKeyAlgorithms Algorithms { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SmimePrivateKeys"/> class.
        /// </summary>
        public SmimePrivateKeys(
            byte[]? postQuantumEncryptionKey,
            byte[]? classicalEncryptionKey,
            byte[]? postQuantumSigningKey,
            byte[]? classicalSigningKey,
            SmimeKeyAlgorithms algorithms)
        {
            PostQuantumEncryptionKey = postQuantumEncryptionKey;
            ClassicalEncryptionKey = classicalEncryptionKey;
            PostQuantumSigningKey = postQuantumSigningKey;
            ClassicalSigningKey = classicalSigningKey;
            Algorithms = algorithms ?? throw new ArgumentNullException(nameof(algorithms));
        }
    }

    /// <summary>
    /// Represents public keys for S/MIME operations.
    /// </summary>
    public class SmimePublicKeys
    {
        /// <summary>
        /// Gets the post-quantum public key for encryption/decryption.
        /// </summary>
        public byte[]? PostQuantumEncryptionKey { get; }

        /// <summary>
        /// Gets the classical public key for encryption/decryption.
        /// </summary>
        public byte[]? ClassicalEncryptionKey { get; }

        /// <summary>
        /// Gets the post-quantum public key for signing.
        /// </summary>
        public byte[]? PostQuantumSigningKey { get; }

        /// <summary>
        /// Gets the classical public key for signing.
        /// </summary>
        public byte[]? ClassicalSigningKey { get; }

        /// <summary>
        /// Gets the algorithm identifiers for the keys.
        /// </summary>
        public SmimeKeyAlgorithms Algorithms { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SmimePublicKeys"/> class.
        /// </summary>
        public SmimePublicKeys(
            byte[]? postQuantumEncryptionKey,
            byte[]? classicalEncryptionKey,
            byte[]? postQuantumSigningKey,
            byte[]? classicalSigningKey,
            SmimeKeyAlgorithms algorithms)
        {
            PostQuantumEncryptionKey = postQuantumEncryptionKey;
            ClassicalEncryptionKey = classicalEncryptionKey;
            PostQuantumSigningKey = postQuantumSigningKey;
            ClassicalSigningKey = classicalSigningKey;
            Algorithms = algorithms ?? throw new ArgumentNullException(nameof(algorithms));
        }
    }

    /// <summary>
    /// Contains algorithm identifiers for S/MIME keys.
    /// </summary>
    public class SmimeKeyAlgorithms
    {
        /// <summary>
        /// Gets the post-quantum encryption algorithm.
        /// </summary>
        public string? PostQuantumEncryption { get; }

        /// <summary>
        /// Gets the classical encryption algorithm.
        /// </summary>
        public string? ClassicalEncryption { get; }

        /// <summary>
        /// Gets the post-quantum signing algorithm.
        /// </summary>
        public string? PostQuantumSigning { get; }

        /// <summary>
        /// Gets the classical signing algorithm.
        /// </summary>
        public string? ClassicalSigning { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SmimeKeyAlgorithms"/> class.
        /// </summary>
        public SmimeKeyAlgorithms(
            string? postQuantumEncryption,
            string? classicalEncryption,
            string? postQuantumSigning,
            string? classicalSigning)
        {
            PostQuantumEncryption = postQuantumEncryption;
            ClassicalEncryption = classicalEncryption;
            PostQuantumSigning = postQuantumSigning;
            ClassicalSigning = classicalSigning;
        }
    }

    /// <summary>
    /// Represents metadata about S/MIME encryption operation.
    /// </summary>
    public class SmimeEncryptionMetadata
    {
        /// <summary>
        /// Gets the timestamp when encryption was performed.
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Gets the encryption strategy used.
        /// </summary>
        public EncryptionStrategy Strategy { get; }

        /// <summary>
        /// Gets the algorithm negotiation result.
        /// </summary>
        public SmimeAlgorithmNegotiation AlgorithmNegotiation { get; }

        /// <summary>
        /// Gets the number of recipients.
        /// </summary>
        public int RecipientCount { get; }

        /// <summary>
        /// Gets a value indicating whether protected headers were used.
        /// </summary>
        public bool UsesProtectedHeaders { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SmimeEncryptionMetadata"/> class.
        /// </summary>
        public SmimeEncryptionMetadata(
            DateTime timestamp,
            EncryptionStrategy strategy,
            SmimeAlgorithmNegotiation algorithmNegotiation,
            int recipientCount,
            bool usesProtectedHeaders = true)
        {
            Timestamp = timestamp;
            Strategy = strategy;
            AlgorithmNegotiation = algorithmNegotiation ?? throw new ArgumentNullException(nameof(algorithmNegotiation));
            RecipientCount = recipientCount;
            UsesProtectedHeaders = usesProtectedHeaders;
        }
    }

    /// <summary>
    /// Represents metadata about S/MIME signing operation.
    /// </summary>
    public class SmimeSigningMetadata
    {
        /// <summary>
        /// Gets the timestamp when signing was performed.
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Gets the signing strategy used.
        /// </summary>
        public EncryptionStrategy Strategy { get; }

        /// <summary>
        /// Gets the signature algorithms used.
        /// </summary>
        public SmimeKeyAlgorithms SignatureAlgorithms { get; }

        /// <summary>
        /// Gets a value indicating whether the signature is detached.
        /// </summary>
        public bool IsDetachedSignature { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SmimeSigningMetadata"/> class.
        /// </summary>
        public SmimeSigningMetadata(
            DateTime timestamp,
            EncryptionStrategy strategy,
            SmimeKeyAlgorithms signatureAlgorithms,
            bool isDetachedSignature = false)
        {
            Timestamp = timestamp;
            Strategy = strategy;
            SignatureAlgorithms = signatureAlgorithms ?? throw new ArgumentNullException(nameof(signatureAlgorithms));
            IsDetachedSignature = isDetachedSignature;
        }
    }

    /// <summary>
    /// Represents the result of algorithm negotiation for S/MIME operations.
    /// </summary>
    public class SmimeAlgorithmNegotiation
    {
        /// <summary>
        /// Gets the negotiated encryption strategy.
        /// </summary>
        public EncryptionStrategy NegotiatedStrategy { get; }

        /// <summary>
        /// Gets the content encryption algorithm selected.
        /// </summary>
        public string ContentEncryptionAlgorithm { get; }

        /// <summary>
        /// Gets the key encapsulation algorithms per recipient.
        /// </summary>
        public IReadOnlyDictionary<string, string> RecipientKemAlgorithms { get; }

        /// <summary>
        /// Gets a value indicating whether all recipients support the negotiated strategy.
        /// </summary>
        public bool AllRecipientsSupported { get; }

        /// <summary>
        /// Gets the capabilities that could not be satisfied.
        /// </summary>
        public IReadOnlyList<string> UnsupportedCapabilities { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SmimeAlgorithmNegotiation"/> class.
        /// </summary>
        public SmimeAlgorithmNegotiation(
            EncryptionStrategy negotiatedStrategy,
            string contentEncryptionAlgorithm,
            IDictionary<string, string> recipientKemAlgorithms,
            bool allRecipientsSupported,
            IEnumerable<string>? unsupportedCapabilities = null)
        {
            NegotiatedStrategy = negotiatedStrategy;
            ContentEncryptionAlgorithm = contentEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(contentEncryptionAlgorithm));
            RecipientKemAlgorithms = recipientKemAlgorithms?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value) ?? throw new ArgumentNullException(nameof(recipientKemAlgorithms));
            AllRecipientsSupported = allRecipientsSupported;
            UnsupportedCapabilities = unsupportedCapabilities?.ToList().AsReadOnly() ?? new List<string>().AsReadOnly();
        }
    }

    /// <summary>
    /// Represents the result of S/MIME signature verification.
    /// </summary>
    public class SmimeSignatureVerificationResult
    {
        /// <summary>
        /// Gets a value indicating whether the signature is valid.
        /// </summary>
        public bool IsValid { get; }

        /// <summary>
        /// Gets the verification results for each signature.
        /// </summary>
        public IReadOnlyList<SignatureVerificationResult> SignatureResults { get; }

        /// <summary>
        /// Gets the signer's certificate information.
        /// </summary>
        public IReadOnlyList<CertificateInfo> SignerCertificates { get; }

        /// <summary>
        /// Gets the timestamp when verification was performed.
        /// </summary>
        public DateTime VerificationTimestamp { get; }

        /// <summary>
        /// Gets any warnings from the verification process.
        /// </summary>
        public IReadOnlyList<string> Warnings { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SmimeSignatureVerificationResult"/> class.
        /// </summary>
        public SmimeSignatureVerificationResult(
            bool isValid,
            IEnumerable<SignatureVerificationResult> signatureResults,
            IEnumerable<CertificateInfo> signerCertificates,
            DateTime verificationTimestamp,
            IEnumerable<string>? warnings = null)
        {
            IsValid = isValid;
            SignatureResults = signatureResults?.ToList().AsReadOnly() ?? throw new ArgumentNullException(nameof(signatureResults));
            SignerCertificates = signerCertificates?.ToList().AsReadOnly() ?? throw new ArgumentNullException(nameof(signerCertificates));
            VerificationTimestamp = verificationTimestamp;
            Warnings = warnings?.ToList().AsReadOnly() ?? new List<string>().AsReadOnly();
        }
    }

    /// <summary>
    /// Represents verification result for a single signature.
    /// </summary>
    public class SignatureVerificationResult
    {
        /// <summary>
        /// Gets a value indicating whether this signature is valid.
        /// </summary>
        public bool IsValid { get; }

        /// <summary>
        /// Gets the signature algorithm used.
        /// </summary>
        public string Algorithm { get; }

        /// <summary>
        /// Gets the signer's certificate.
        /// </summary>
        public CertificateInfo SignerCertificate { get; }

        /// <summary>
        /// Gets the error message if validation failed.
        /// </summary>
        public string? ErrorMessage { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureVerificationResult"/> class.
        /// </summary>
        public SignatureVerificationResult(
            bool isValid,
            string algorithm,
            CertificateInfo signerCertificate,
            string? errorMessage = null)
        {
            IsValid = isValid;
            Algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            SignerCertificate = signerCertificate ?? throw new ArgumentNullException(nameof(signerCertificate));
            ErrorMessage = errorMessage;
        }
    }
}