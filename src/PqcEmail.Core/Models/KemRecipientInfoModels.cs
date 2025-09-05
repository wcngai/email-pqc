using System;
using System.Collections.Generic;
using System.Linq;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Represents a KEMRecipientInfo structure as defined in CMS/S/MIME 4.0 specification.
    /// This structure is used for key encapsulation with post-quantum algorithms.
    /// </summary>
    public class KemRecipientInfo
    {
        /// <summary>
        /// Gets the recipient identifier.
        /// </summary>
        public RecipientIdentifier RecipientId { get; }

        /// <summary>
        /// Gets the key encapsulation mechanism algorithm identifier.
        /// </summary>
        public AlgorithmIdentifier KemAlgorithm { get; }

        /// <summary>
        /// Gets the encapsulated key (ciphertext from KEM.Encaps).
        /// </summary>
        public byte[] EncapsulatedKey { get; }

        /// <summary>
        /// Gets the key derivation function algorithm identifier.
        /// </summary>
        public AlgorithmIdentifier KdfAlgorithm { get; }

        /// <summary>
        /// Gets the key encryption algorithm identifier.
        /// </summary>
        public AlgorithmIdentifier KeyEncryptionAlgorithm { get; }

        /// <summary>
        /// Gets the encrypted key-encryption-key.
        /// </summary>
        public byte[] EncryptedKey { get; }

        /// <summary>
        /// Gets the optional shared user keying material.
        /// </summary>
        public byte[]? SharedUkm { get; }

        /// <summary>
        /// Gets the key size in bits for the KEK derivation.
        /// </summary>
        public int KeySize { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="KemRecipientInfo"/> class.
        /// </summary>
        public KemRecipientInfo(
            RecipientIdentifier recipientId,
            AlgorithmIdentifier kemAlgorithm,
            byte[] encapsulatedKey,
            AlgorithmIdentifier kdfAlgorithm,
            AlgorithmIdentifier keyEncryptionAlgorithm,
            byte[] encryptedKey,
            int keySize,
            byte[]? sharedUkm = null)
        {
            RecipientId = recipientId ?? throw new ArgumentNullException(nameof(recipientId));
            KemAlgorithm = kemAlgorithm ?? throw new ArgumentNullException(nameof(kemAlgorithm));
            EncapsulatedKey = encapsulatedKey ?? throw new ArgumentNullException(nameof(encapsulatedKey));
            KdfAlgorithm = kdfAlgorithm ?? throw new ArgumentNullException(nameof(kdfAlgorithm));
            KeyEncryptionAlgorithm = keyEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(keyEncryptionAlgorithm));
            EncryptedKey = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
            KeySize = keySize;
            SharedUkm = sharedUkm;
        }
    }

    /// <summary>
    /// Represents a recipient identifier used in CMS structures.
    /// </summary>
    public class RecipientIdentifier
    {
        /// <summary>
        /// Gets the issuer and serial number identification method.
        /// </summary>
        public IssuerAndSerialNumber? IssuerAndSerialNumber { get; }

        /// <summary>
        /// Gets the subject key identifier method.
        /// </summary>
        public byte[]? SubjectKeyIdentifier { get; }

        /// <summary>
        /// Gets the recipient identifier type.
        /// </summary>
        public RecipientIdentifierType Type { get; }

        /// <summary>
        /// Initializes a new instance using issuer and serial number.
        /// </summary>
        public RecipientIdentifier(IssuerAndSerialNumber issuerAndSerialNumber)
        {
            IssuerAndSerialNumber = issuerAndSerialNumber ?? throw new ArgumentNullException(nameof(issuerAndSerialNumber));
            Type = RecipientIdentifierType.IssuerAndSerialNumber;
        }

        /// <summary>
        /// Initializes a new instance using subject key identifier.
        /// </summary>
        public RecipientIdentifier(byte[] subjectKeyIdentifier)
        {
            SubjectKeyIdentifier = subjectKeyIdentifier ?? throw new ArgumentNullException(nameof(subjectKeyIdentifier));
            Type = RecipientIdentifierType.SubjectKeyIdentifier;
        }
    }

    /// <summary>
    /// Represents an issuer and serial number identifier.
    /// </summary>
    public class IssuerAndSerialNumber
    {
        /// <summary>
        /// Gets the certificate issuer distinguished name.
        /// </summary>
        public string IssuerName { get; }

        /// <summary>
        /// Gets the certificate serial number.
        /// </summary>
        public byte[] SerialNumber { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="IssuerAndSerialNumber"/> class.
        /// </summary>
        public IssuerAndSerialNumber(string issuerName, byte[] serialNumber)
        {
            IssuerName = issuerName ?? throw new ArgumentNullException(nameof(issuerName));
            SerialNumber = serialNumber ?? throw new ArgumentNullException(nameof(serialNumber));
        }
    }

    /// <summary>
    /// Represents an algorithm identifier with optional parameters.
    /// </summary>
    public class AlgorithmIdentifier
    {
        /// <summary>
        /// Gets the algorithm object identifier (OID).
        /// </summary>
        public string Algorithm { get; }

        /// <summary>
        /// Gets the optional algorithm parameters.
        /// </summary>
        public byte[]? Parameters { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlgorithmIdentifier"/> class.
        /// </summary>
        public AlgorithmIdentifier(string algorithm, byte[]? parameters = null)
        {
            Algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            Parameters = parameters;
        }
    }

    /// <summary>
    /// Base class for all recipient info types in CMS.
    /// </summary>
    public abstract class RecipientInfo
    {
        /// <summary>
        /// Gets the recipient info type.
        /// </summary>
        public RecipientInfoType Type { get; protected set; }

        /// <summary>
        /// Gets the recipient identifier.
        /// </summary>
        public RecipientIdentifier RecipientId { get; protected set; }

        /// <summary>
        /// Gets the encrypted key material.
        /// </summary>
        public byte[] EncryptedKey { get; protected set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="RecipientInfo"/> class.
        /// </summary>
        protected RecipientInfo(RecipientInfoType type, RecipientIdentifier recipientId, byte[] encryptedKey)
        {
            Type = type;
            RecipientId = recipientId ?? throw new ArgumentNullException(nameof(recipientId));
            EncryptedKey = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
        }
    }

    /// <summary>
    /// Represents a KeyTransRecipientInfo structure for RSA key transport.
    /// </summary>
    public class KeyTransRecipientInfo : RecipientInfo
    {
        /// <summary>
        /// Gets the key encryption algorithm.
        /// </summary>
        public AlgorithmIdentifier KeyEncryptionAlgorithm { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyTransRecipientInfo"/> class.
        /// </summary>
        public KeyTransRecipientInfo(
            RecipientIdentifier recipientId,
            AlgorithmIdentifier keyEncryptionAlgorithm,
            byte[] encryptedKey)
            : base(RecipientInfoType.KeyTransRecipientInfo, recipientId, encryptedKey)
        {
            KeyEncryptionAlgorithm = keyEncryptionAlgorithm ?? throw new ArgumentNullException(nameof(keyEncryptionAlgorithm));
        }
    }

    /// <summary>
    /// Represents a KEMRecipientInfo structure for post-quantum key encapsulation.
    /// </summary>
    public class KemRecipientInfoWrapper : RecipientInfo
    {
        /// <summary>
        /// Gets the KEMRecipientInfo structure.
        /// </summary>
        public KemRecipientInfo KemInfo { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="KemRecipientInfoWrapper"/> class.
        /// </summary>
        public KemRecipientInfoWrapper(KemRecipientInfo kemInfo)
            : base(RecipientInfoType.KemRecipientInfo, kemInfo.RecipientId, kemInfo.EncryptedKey)
        {
            KemInfo = kemInfo ?? throw new ArgumentNullException(nameof(kemInfo));
        }
    }

    /// <summary>
    /// Represents signature information for S/MIME signed messages.
    /// </summary>
    public class SignatureInfo
    {
        /// <summary>
        /// Gets the signature algorithm identifier.
        /// </summary>
        public AlgorithmIdentifier SignatureAlgorithm { get; }

        /// <summary>
        /// Gets the signature value.
        /// </summary>
        public byte[] SignatureValue { get; }

        /// <summary>
        /// Gets the signed attributes.
        /// </summary>
        public IReadOnlyDictionary<string, byte[]> SignedAttributes { get; }

        /// <summary>
        /// Gets the unsigned attributes.
        /// </summary>
        public IReadOnlyDictionary<string, byte[]> UnsignedAttributes { get; }

        /// <summary>
        /// Gets the signer identifier.
        /// </summary>
        public RecipientIdentifier SignerId { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureInfo"/> class.
        /// </summary>
        public SignatureInfo(
            AlgorithmIdentifier signatureAlgorithm,
            byte[] signatureValue,
            RecipientIdentifier signerId,
            IDictionary<string, byte[]>? signedAttributes = null,
            IDictionary<string, byte[]>? unsignedAttributes = null)
        {
            SignatureAlgorithm = signatureAlgorithm ?? throw new ArgumentNullException(nameof(signatureAlgorithm));
            SignatureValue = signatureValue ?? throw new ArgumentNullException(nameof(signatureValue));
            SignerId = signerId ?? throw new ArgumentNullException(nameof(signerId));
            SignedAttributes = signedAttributes?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value) ?? new Dictionary<string, byte[]>();
            UnsignedAttributes = unsignedAttributes?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value) ?? new Dictionary<string, byte[]>();
        }
    }

    /// <summary>
    /// Defines the recipient identifier types.
    /// </summary>
    public enum RecipientIdentifierType
    {
        /// <summary>
        /// Identifies recipient by issuer and serial number.
        /// </summary>
        IssuerAndSerialNumber,

        /// <summary>
        /// Identifies recipient by subject key identifier.
        /// </summary>
        SubjectKeyIdentifier
    }

    /// <summary>
    /// Defines the types of recipient info structures.
    /// </summary>
    public enum RecipientInfoType
    {
        /// <summary>
        /// Key transport recipient info (RSA).
        /// </summary>
        KeyTransRecipientInfo,

        /// <summary>
        /// Key agreement recipient info (ECDH).
        /// </summary>
        KeyAgreeRecipientInfo,

        /// <summary>
        /// KEK recipient info (symmetric key wrapping).
        /// </summary>
        KekRecipientInfo,

        /// <summary>
        /// Password recipient info (PBKDF2).
        /// </summary>
        PasswordRecipientInfo,

        /// <summary>
        /// KEM recipient info (post-quantum).
        /// </summary>
        KemRecipientInfo
    }

    /// <summary>
    /// Contains commonly used algorithm object identifiers for PQC and classical algorithms.
    /// </summary>
    public static class AlgorithmOids
    {
        // Post-Quantum KEM Algorithms
        public const string MlKem512 = "2.16.840.1.101.3.4.4.1";
        public const string MlKem768 = "2.16.840.1.101.3.4.4.2";
        public const string MlKem1024 = "2.16.840.1.101.3.4.4.3";

        // Post-Quantum Signature Algorithms
        public const string MlDsa44 = "2.16.840.1.101.3.4.3.17";
        public const string MlDsa65 = "2.16.840.1.101.3.4.3.18";
        public const string MlDsa87 = "2.16.840.1.101.3.4.3.19";

        // Classical Algorithms
        public const string RsaEncryption = "1.2.840.113549.1.1.1";
        public const string RsaPkcs1Sha256 = "1.2.840.113549.1.1.11";
        public const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";

        // Key Derivation Functions
        public const string Hkdf = "1.2.840.113549.1.9.16.3.28";
        public const string Kdf2 = "1.2.840.113549.1.9.16.3.10";

        // Symmetric Encryption
        public const string Aes128Gcm = "2.16.840.1.101.3.4.1.6";
        public const string Aes256Gcm = "2.16.840.1.101.3.4.1.46";
        public const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
        public const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";

        // Hash Functions
        public const string Sha256 = "2.16.840.1.101.3.4.2.1";
        public const string Sha384 = "2.16.840.1.101.3.4.2.2";
        public const string Sha512 = "2.16.840.1.101.3.4.2.3";
    }

    /// <summary>
    /// Represents the result of KEMRecipientInfo processing operations.
    /// </summary>
    public class KemProcessingResult
    {
        /// <summary>
        /// Gets a value indicating whether the operation was successful.
        /// </summary>
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets the recovered key encapsulation key.
        /// </summary>
        public byte[]? KeyEncapsulationKey { get; }

        /// <summary>
        /// Gets the error message if the operation failed.
        /// </summary>
        public string? ErrorMessage { get; }

        /// <summary>
        /// Gets the exception that caused the failure, if any.
        /// </summary>
        public Exception? Exception { get; }

        /// <summary>
        /// Initializes a new successful result.
        /// </summary>
        public KemProcessingResult(byte[] keyEncapsulationKey)
        {
            IsSuccess = true;
            KeyEncapsulationKey = keyEncapsulationKey ?? throw new ArgumentNullException(nameof(keyEncapsulationKey));
        }

        /// <summary>
        /// Initializes a new failed result.
        /// </summary>
        public KemProcessingResult(string errorMessage, Exception? exception = null)
        {
            IsSuccess = false;
            ErrorMessage = errorMessage ?? throw new ArgumentNullException(nameof(errorMessage));
            Exception = exception;
        }

        /// <summary>
        /// Creates a successful result.
        /// </summary>
        public static KemProcessingResult Success(byte[] keyEncapsulationKey)
        {
            return new KemProcessingResult(keyEncapsulationKey);
        }

        /// <summary>
        /// Creates a failed result.
        /// </summary>
        public static KemProcessingResult Failure(string errorMessage, Exception? exception = null)
        {
            return new KemProcessingResult(errorMessage, exception);
        }
    }
}