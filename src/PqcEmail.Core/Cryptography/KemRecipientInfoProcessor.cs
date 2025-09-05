using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Cryptography
{
    /// <summary>
    /// Implementation of KEMRecipientInfo processing according to CMS/S/MIME 4.0 specification.
    /// Handles creation and processing of post-quantum key encapsulation structures.
    /// </summary>
    public class KemRecipientInfoProcessor : IKemRecipientInfoProcessor
    {
        private readonly ICryptographicProvider _cryptographicProvider;
        private readonly ILogger<KemRecipientInfoProcessor> _logger;
        private readonly RandomNumberGenerator _rng;

        /// <summary>
        /// Initializes a new instance of the <see cref="KemRecipientInfoProcessor"/> class.
        /// </summary>
        /// <param name="cryptographicProvider">The cryptographic provider</param>
        /// <param name="logger">The logger instance</param>
        public KemRecipientInfoProcessor(
            ICryptographicProvider cryptographicProvider,
            ILogger<KemRecipientInfoProcessor> logger)
        {
            _cryptographicProvider = cryptographicProvider ?? throw new ArgumentNullException(nameof(cryptographicProvider));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _rng = RandomNumberGenerator.Create();
        }

        /// <summary>
        /// Creates a KEMRecipientInfo structure for a recipient using PQC algorithms.
        /// </summary>
        /// <param name="recipientCertificate">The recipient's certificate containing PQC public key</param>
        /// <param name="keyEncapsulationKey">The key encapsulation key to be wrapped</param>
        /// <param name="kemAlgorithm">The KEM algorithm to use</param>
        /// <returns>A task that represents the asynchronous KEMRecipientInfo creation</returns>
        public async Task<CryptographicResult<KemRecipientInfo>> CreateKemRecipientInfoAsync(
            CertificateInfo recipientCertificate,
            byte[] keyEncapsulationKey,
            string kemAlgorithm)
        {
            if (recipientCertificate == null) throw new ArgumentNullException(nameof(recipientCertificate));
            if (keyEncapsulationKey == null) throw new ArgumentNullException(nameof(keyEncapsulationKey));
            if (string.IsNullOrEmpty(kemAlgorithm)) throw new ArgumentException("KEM algorithm cannot be null or empty", nameof(kemAlgorithm));

            try
            {
                _logger.LogDebug("Creating KEMRecipientInfo for recipient {Subject} using algorithm {Algorithm}", 
                    recipientCertificate.Subject, kemAlgorithm);

                // Create recipient identifier
                var recipientId = CreateRecipientIdentifier(recipientCertificate);

                // Extract PQC public key from certificate
                var pqcPublicKey = ExtractPqcPublicKey(recipientCertificate, kemAlgorithm);
                if (pqcPublicKey == null)
                {
                    return CryptographicResult<KemRecipientInfo>.Failure(
                        $"Certificate does not contain a compatible PQC public key for algorithm {kemAlgorithm}");
                }

                // Generate shared secret using KEM.Encaps
                var kemResult = await _cryptographicProvider.KemEncapsulateAsync(pqcPublicKey, kemAlgorithm);
                if (!kemResult.IsSuccess)
                {
                    return CryptographicResult<KemRecipientInfo>.Failure(
                        $"KEM encapsulation failed: {kemResult.ErrorMessage}", kemResult.Exception);
                }

                var sharedSecret = kemResult.Data!.SharedSecret;
                var encapsulatedKey = kemResult.Data.Ciphertext;

                // Derive KEK using HKDF
                var kekSize = GetKekSizeForAlgorithm(kemAlgorithm);
                var derivedKek = await DeriveKeyEncryptionKey(sharedSecret, kekSize, kemAlgorithm);

                // Encrypt the content encryption key with the derived KEK
                var encryptedKey = await EncryptWithAesGcm(keyEncapsulationKey, derivedKek);

                // Create algorithm identifiers
                var kemAlgorithmId = new AlgorithmIdentifier(GetKemOid(kemAlgorithm));
                var kdfAlgorithmId = new AlgorithmIdentifier(AlgorithmOids.Hkdf, CreateHkdfParameters(kemAlgorithm));
                var keyEncryptionAlgorithmId = new AlgorithmIdentifier(AlgorithmOids.Aes256Gcm);

                // Create KEMRecipientInfo structure
                var kemRecipientInfo = new KemRecipientInfo(
                    recipientId,
                    kemAlgorithmId,
                    encapsulatedKey,
                    kdfAlgorithmId,
                    keyEncryptionAlgorithmId,
                    encryptedKey.ciphertext,
                    kekSize * 8); // Convert to bits

                _logger.LogDebug("Successfully created KEMRecipientInfo with {CiphertextSize} bytes ciphertext", 
                    encapsulatedKey.Length);

                return CryptographicResult<KemRecipientInfo>.Success(kemRecipientInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create KEMRecipientInfo for recipient {Subject}", 
                    recipientCertificate.Subject);
                return CryptographicResult<KemRecipientInfo>.Failure("KEMRecipientInfo creation failed", ex);
            }
        }

        /// <summary>
        /// Processes a KEMRecipientInfo structure to recover the key encapsulation key.
        /// </summary>
        /// <param name="kemRecipientInfo">The KEMRecipientInfo structure</param>
        /// <param name="recipientPrivateKey">The recipient's private key</param>
        /// <returns>A task that represents the asynchronous key recovery operation</returns>
        public async Task<CryptographicResult<byte[]>> ProcessKemRecipientInfoAsync(
            KemRecipientInfo kemRecipientInfo,
            byte[] recipientPrivateKey)
        {
            if (kemRecipientInfo == null) throw new ArgumentNullException(nameof(kemRecipientInfo));
            if (recipientPrivateKey == null) throw new ArgumentNullException(nameof(recipientPrivateKey));

            try
            {
                _logger.LogDebug("Processing KEMRecipientInfo with algorithm {Algorithm}", 
                    kemRecipientInfo.KemAlgorithm.Algorithm);

                // Get KEM algorithm from OID
                var kemAlgorithm = GetAlgorithmFromOid(kemRecipientInfo.KemAlgorithm.Algorithm);

                // Perform KEM.Decaps to recover shared secret
                var decapsResult = await _cryptographicProvider.KemDecapsulateAsync(
                    kemRecipientInfo.EncapsulatedKey, recipientPrivateKey, kemAlgorithm);

                if (!decapsResult.IsSuccess)
                {
                    return CryptographicResult<byte[]>.Failure(
                        $"KEM decapsulation failed: {decapsResult.ErrorMessage}", decapsResult.Exception);
                }

                var sharedSecret = decapsResult.Data!;

                // Derive the same KEK using HKDF
                var kekSize = kemRecipientInfo.KeySize / 8; // Convert from bits to bytes
                var derivedKek = await DeriveKeyEncryptionKey(sharedSecret, kekSize, kemAlgorithm);

                // Decrypt the content encryption key
                var decryptedKey = await DecryptWithAesGcm(kemRecipientInfo.EncryptedKey, derivedKek);

                _logger.LogDebug("Successfully recovered {KeySize} byte key encapsulation key", decryptedKey.Length);

                return CryptographicResult<byte[]>.Success(decryptedKey);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process KEMRecipientInfo");
                return CryptographicResult<byte[]>.Failure("KEMRecipientInfo processing failed", ex);
            }
        }

        /// <summary>
        /// Encodes a KEMRecipientInfo structure to ASN.1 DER format.
        /// </summary>
        /// <param name="kemRecipientInfo">The KEMRecipientInfo structure</param>
        /// <returns>The ASN.1 DER encoded bytes</returns>
        public byte[] EncodeKemRecipientInfo(KemRecipientInfo kemRecipientInfo)
        {
            if (kemRecipientInfo == null) throw new ArgumentNullException(nameof(kemRecipientInfo));

            try
            {
                _logger.LogDebug("Encoding KEMRecipientInfo to ASN.1 DER format");

                // This is a simplified ASN.1 encoding - in a production system,
                // you would use a proper ASN.1 library like Bouncy Castle
                using (var writer = new System.IO.MemoryStream())
                {
                    // KEMRecipientInfo SEQUENCE
                    writer.WriteByte(0x30); // SEQUENCE tag

                    using (var content = new System.IO.MemoryStream())
                    {
                        // Write recipient ID
                        WriteRecipientIdentifier(content, kemRecipientInfo.RecipientId);

                        // Write KEM algorithm
                        WriteAlgorithmIdentifier(content, kemRecipientInfo.KemAlgorithm);

                        // Write encapsulated key as OCTET STRING
                        WriteOctetString(content, kemRecipientInfo.EncapsulatedKey);

                        // Write KDF algorithm
                        WriteAlgorithmIdentifier(content, kemRecipientInfo.KdfAlgorithm);

                        // Write key encryption algorithm
                        WriteAlgorithmIdentifier(content, kemRecipientInfo.KeyEncryptionAlgorithm);

                        // Write encrypted key as OCTET STRING
                        WriteOctetString(content, kemRecipientInfo.EncryptedKey);

                        // Write key size as INTEGER
                        WriteInteger(content, kemRecipientInfo.KeySize);

                        // Write optional shared UKM if present
                        if (kemRecipientInfo.SharedUkm != null)
                        {
                            WriteOctetString(content, kemRecipientInfo.SharedUkm);
                        }

                        var contentBytes = content.ToArray();
                        WriteLength(writer, contentBytes.Length);
                        writer.Write(contentBytes);
                    }

                    var result = writer.ToArray();
                    _logger.LogDebug("Encoded KEMRecipientInfo to {Size} bytes", result.Length);
                    return result;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to encode KEMRecipientInfo");
                throw new InvalidOperationException("KEMRecipientInfo encoding failed", ex);
            }
        }

        /// <summary>
        /// Decodes a KEMRecipientInfo structure from ASN.1 DER format.
        /// </summary>
        /// <param name="encodedData">The ASN.1 DER encoded bytes</param>
        /// <returns>The decoded KEMRecipientInfo structure</returns>
        public KemRecipientInfo DecodeKemRecipientInfo(byte[] encodedData)
        {
            if (encodedData == null) throw new ArgumentNullException(nameof(encodedData));

            try
            {
                _logger.LogDebug("Decoding KEMRecipientInfo from {Size} bytes ASN.1 DER data", encodedData.Length);

                // This is a simplified ASN.1 decoding - in a production system,
                // you would use a proper ASN.1 library like Bouncy Castle
                using (var reader = new System.IO.MemoryStream(encodedData))
                {
                    // Read SEQUENCE tag
                    var tag = reader.ReadByte();
                    if (tag != 0x30) throw new ArgumentException("Invalid ASN.1 format - expected SEQUENCE");

                    var length = ReadLength(reader);

                    // Read components
                    var recipientId = ReadRecipientIdentifier(reader);
                    var kemAlgorithm = ReadAlgorithmIdentifier(reader);
                    var encapsulatedKey = ReadOctetString(reader);
                    var kdfAlgorithm = ReadAlgorithmIdentifier(reader);
                    var keyEncryptionAlgorithm = ReadAlgorithmIdentifier(reader);
                    var encryptedKey = ReadOctetString(reader);
                    var keySize = ReadInteger(reader);

                    // Optional shared UKM
                    byte[]? sharedUkm = null;
                    if (reader.Position < reader.Length)
                    {
                        sharedUkm = ReadOctetString(reader);
                    }

                    var result = new KemRecipientInfo(
                        recipientId,
                        kemAlgorithm,
                        encapsulatedKey,
                        kdfAlgorithm,
                        keyEncryptionAlgorithm,
                        encryptedKey,
                        keySize,
                        sharedUkm);

                    _logger.LogDebug("Successfully decoded KEMRecipientInfo");
                    return result;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to decode KEMRecipientInfo");
                throw new ArgumentException("KEMRecipientInfo decoding failed", ex);
            }
        }

        #region Private Methods

        private RecipientIdentifier CreateRecipientIdentifier(CertificateInfo certificate)
        {
            // Prefer subject key identifier if available
            if (!string.IsNullOrEmpty(certificate.SubjectKeyIdentifier))
            {
                var ski = Convert.FromBase64String(certificate.SubjectKeyIdentifier);
                return new RecipientIdentifier(ski);
            }

            // Fall back to issuer and serial number
            var serialNumber = Convert.FromBase64String(certificate.SerialNumber);
            var issuerAndSerial = new IssuerAndSerialNumber(certificate.Issuer, serialNumber);
            return new RecipientIdentifier(issuerAndSerial);
        }

        private byte[]? ExtractPqcPublicKey(CertificateInfo certificate, string kemAlgorithm)
        {
            // In a real implementation, this would parse the certificate and extract
            // the appropriate PQC public key based on the algorithm
            return certificate.PostQuantumEncryptionPublicKey;
        }

        private async Task<byte[]> DeriveKeyEncryptionKey(byte[] sharedSecret, int keySize, string kemAlgorithm)
        {
            // Use HKDF to derive the key encryption key
            using (var hkdf = new System.Security.Cryptography.HKDF())
            {
                var salt = new byte[32]; // Use empty salt or derive from algorithm/context
                var info = System.Text.Encoding.UTF8.GetBytes($"S/MIME KEK {kemAlgorithm}");
                
                return HKDF.Expand(HashAlgorithmName.SHA256, sharedSecret, keySize, info);
            }
        }

        private async Task<(byte[] ciphertext, byte[] authTag)> EncryptWithAesGcm(byte[] plaintext, byte[] key)
        {
            var iv = new byte[12]; // 96-bit IV for AES-GCM
            _rng.GetBytes(iv);

            using (var aes = new AesGcm(key))
            {
                var ciphertext = new byte[plaintext.Length];
                var authTag = new byte[16]; // 128-bit auth tag
                
                aes.Encrypt(iv, plaintext, ciphertext, authTag);
                
                // Prepend IV to ciphertext for storage
                var result = new byte[iv.Length + ciphertext.Length + authTag.Length];
                Array.Copy(iv, 0, result, 0, iv.Length);
                Array.Copy(ciphertext, 0, result, iv.Length, ciphertext.Length);
                Array.Copy(authTag, 0, result, iv.Length + ciphertext.Length, authTag.Length);
                
                return (result, authTag);
            }
        }

        private async Task<byte[]> DecryptWithAesGcm(byte[] ciphertext, byte[] key)
        {
            if (ciphertext.Length < 28) // 12 IV + 16 auth tag minimum
                throw new ArgumentException("Ciphertext too short for AES-GCM");

            var iv = new byte[12];
            var authTag = new byte[16];
            var encryptedData = new byte[ciphertext.Length - 28];

            Array.Copy(ciphertext, 0, iv, 0, 12);
            Array.Copy(ciphertext, 12, encryptedData, 0, encryptedData.Length);
            Array.Copy(ciphertext, ciphertext.Length - 16, authTag, 0, 16);

            using (var aes = new AesGcm(key))
            {
                var plaintext = new byte[encryptedData.Length];
                aes.Decrypt(iv, encryptedData, authTag, plaintext);
                return plaintext;
            }
        }

        private int GetKekSizeForAlgorithm(string kemAlgorithm)
        {
            // Return appropriate KEK size based on algorithm
            return kemAlgorithm switch
            {
                "ML-KEM-512" => 32,  // 256 bits
                "ML-KEM-768" => 32,  // 256 bits
                "ML-KEM-1024" => 32, // 256 bits
                _ => 32
            };
        }

        private string GetKemOid(string kemAlgorithm)
        {
            return kemAlgorithm switch
            {
                "ML-KEM-512" => AlgorithmOids.MlKem512,
                "ML-KEM-768" => AlgorithmOids.MlKem768,
                "ML-KEM-1024" => AlgorithmOids.MlKem1024,
                _ => throw new ArgumentException($"Unknown KEM algorithm: {kemAlgorithm}")
            };
        }

        private string GetAlgorithmFromOid(string oid)
        {
            return oid switch
            {
                AlgorithmOids.MlKem512 => "ML-KEM-512",
                AlgorithmOids.MlKem768 => "ML-KEM-768",
                AlgorithmOids.MlKem1024 => "ML-KEM-1024",
                _ => throw new ArgumentException($"Unknown KEM algorithm OID: {oid}")
            };
        }

        private byte[] CreateHkdfParameters(string kemAlgorithm)
        {
            // Create HKDF parameters structure
            // This is a simplified implementation - real ASN.1 structure would be more complex
            var info = System.Text.Encoding.UTF8.GetBytes($"S/MIME KEK {kemAlgorithm}");
            return info;
        }

        #region ASN.1 Encoding/Decoding Helpers

        private void WriteRecipientIdentifier(System.IO.Stream stream, RecipientIdentifier recipientId)
        {
            // Simplified - real implementation would handle both types properly
            if (recipientId.Type == RecipientIdentifierType.SubjectKeyIdentifier)
            {
                WriteOctetString(stream, recipientId.SubjectKeyIdentifier!);
            }
            else
            {
                // Write issuer and serial number sequence
                // This is simplified - full implementation needed
                WriteOctetString(stream, recipientId.IssuerAndSerialNumber!.SerialNumber);
            }
        }

        private void WriteAlgorithmIdentifier(System.IO.Stream stream, AlgorithmIdentifier algorithm)
        {
            stream.WriteByte(0x30); // SEQUENCE
            using (var content = new System.IO.MemoryStream())
            {
                WriteOid(content, algorithm.Algorithm);
                if (algorithm.Parameters != null)
                {
                    content.Write(algorithm.Parameters);
                }
                var contentBytes = content.ToArray();
                WriteLength(stream, contentBytes.Length);
                stream.Write(contentBytes);
            }
        }

        private void WriteOctetString(System.IO.Stream stream, byte[] data)
        {
            stream.WriteByte(0x04); // OCTET STRING
            WriteLength(stream, data.Length);
            stream.Write(data);
        }

        private void WriteInteger(System.IO.Stream stream, int value)
        {
            stream.WriteByte(0x02); // INTEGER
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            WriteLength(stream, bytes.Length);
            stream.Write(bytes);
        }

        private void WriteOid(System.IO.Stream stream, string oid)
        {
            stream.WriteByte(0x06); // OBJECT IDENTIFIER
            var oidBytes = EncodeOid(oid);
            WriteLength(stream, oidBytes.Length);
            stream.Write(oidBytes);
        }

        private void WriteLength(System.IO.Stream stream, int length)
        {
            if (length < 0x80)
            {
                stream.WriteByte((byte)length);
            }
            else
            {
                var bytes = BitConverter.GetBytes(length);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(bytes);
                
                var nonZeroIndex = Array.FindIndex(bytes, b => b != 0);
                var lengthBytes = bytes[nonZeroIndex..];
                
                stream.WriteByte((byte)(0x80 | lengthBytes.Length));
                stream.Write(lengthBytes);
            }
        }

        private byte[] EncodeOid(string oid)
        {
            // Simplified OID encoding - production code would handle this properly
            var parts = oid.Split('.');
            var result = new System.Collections.Generic.List<byte>();
            
            // First two components are encoded together
            var first = int.Parse(parts[0]);
            var second = int.Parse(parts[1]);
            result.Add((byte)(first * 40 + second));
            
            // Remaining components
            for (int i = 2; i < parts.Length; i++)
            {
                var value = int.Parse(parts[i]);
                if (value < 128)
                {
                    result.Add((byte)value);
                }
                else
                {
                    // Multi-byte encoding for larger values
                    var bytes = new System.Collections.Generic.List<byte>();
                    while (value > 0)
                    {
                        bytes.Insert(0, (byte)((value & 0x7F) | (bytes.Count > 0 ? 0x80 : 0)));
                        value >>= 7;
                    }
                    result.AddRange(bytes);
                }
            }
            
            return result.ToArray();
        }

        private RecipientIdentifier ReadRecipientIdentifier(System.IO.Stream stream)
        {
            // Simplified - real implementation would detect type first
            var data = ReadOctetString(stream);
            return new RecipientIdentifier(data);
        }

        private AlgorithmIdentifier ReadAlgorithmIdentifier(System.IO.Stream stream)
        {
            var tag = stream.ReadByte();
            if (tag != 0x30) throw new ArgumentException("Expected SEQUENCE for AlgorithmIdentifier");
            
            var length = ReadLength(stream);
            var oid = ReadOid(stream);
            
            byte[]? parameters = null;
            // Check if there are parameters
            if (stream.Position < stream.Length)
            {
                // Read remaining bytes as parameters (simplified)
                var remaining = (int)(stream.Length - stream.Position);
                if (remaining > 0)
                {
                    parameters = new byte[remaining];
                    stream.Read(parameters);
                }
            }
            
            return new AlgorithmIdentifier(oid, parameters);
        }

        private byte[] ReadOctetString(System.IO.Stream stream)
        {
            var tag = stream.ReadByte();
            if (tag != 0x04) throw new ArgumentException("Expected OCTET STRING");
            
            var length = ReadLength(stream);
            var data = new byte[length];
            stream.Read(data);
            return data;
        }

        private int ReadInteger(System.IO.Stream stream)
        {
            var tag = stream.ReadByte();
            if (tag != 0x02) throw new ArgumentException("Expected INTEGER");
            
            var length = ReadLength(stream);
            var bytes = new byte[length];
            stream.Read(bytes);
            
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            
            return BitConverter.ToInt32(bytes);
        }

        private string ReadOid(System.IO.Stream stream)
        {
            var tag = stream.ReadByte();
            if (tag != 0x06) throw new ArgumentException("Expected OBJECT IDENTIFIER");
            
            var length = ReadLength(stream);
            var data = new byte[length];
            stream.Read(data);
            
            return DecodeOid(data);
        }

        private int ReadLength(System.IO.Stream stream)
        {
            var firstByte = stream.ReadByte();
            if (firstByte < 0x80)
            {
                return firstByte;
            }
            
            var lengthBytes = firstByte & 0x7F;
            var bytes = new byte[lengthBytes];
            stream.Read(bytes);
            
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            
            return BitConverter.ToInt32(bytes);
        }

        private string DecodeOid(byte[] data)
        {
            // Simplified OID decoding
            var result = new System.Collections.Generic.List<string>();
            
            // First byte encodes first two components
            var firstByte = data[0];
            result.Add((firstByte / 40).ToString());
            result.Add((firstByte % 40).ToString());
            
            // Decode remaining components
            var i = 1;
            while (i < data.Length)
            {
                var value = 0;
                byte b;
                do
                {
                    b = data[i++];
                    value = (value << 7) | (b & 0x7F);
                } while ((b & 0x80) != 0 && i < data.Length);
                
                result.Add(value.ToString());
            }
            
            return string.Join(".", result);
        }

        #endregion

        #endregion
    }
}