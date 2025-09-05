using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Cryptography
{
    /// <summary>
    /// Implementation of S/MIME message processing with hybrid PQC and classical algorithms.
    /// Provides transparent encryption/decryption workflow for email messages.
    /// </summary>
    public class SmimeMessageProcessor : ISmimeMessageProcessor
    {
        private readonly IHybridEncryptionEngine _hybridEncryptionEngine;
        private readonly IKemRecipientInfoProcessor _kemRecipientInfoProcessor;
        private readonly ICryptographicProvider _cryptographicProvider;
        private readonly ILogger<SmimeMessageProcessor> _logger;
        private readonly RandomNumberGenerator _rng;

        /// <summary>
        /// Initializes a new instance of the <see cref="SmimeMessageProcessor"/> class.
        /// </summary>
        public SmimeMessageProcessor(
            IHybridEncryptionEngine hybridEncryptionEngine,
            IKemRecipientInfoProcessor kemRecipientInfoProcessor,
            ICryptographicProvider cryptographicProvider,
            ILogger<SmimeMessageProcessor> logger)
        {
            _hybridEncryptionEngine = hybridEncryptionEngine ?? throw new ArgumentNullException(nameof(hybridEncryptionEngine));
            _kemRecipientInfoProcessor = kemRecipientInfoProcessor ?? throw new ArgumentNullException(nameof(kemRecipientInfoProcessor));
            _cryptographicProvider = cryptographicProvider ?? throw new ArgumentNullException(nameof(cryptographicProvider));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _rng = RandomNumberGenerator.Create();
        }

        /// <summary>
        /// Encrypts an email message using S/MIME with hybrid algorithms.
        /// </summary>
        /// <param name="message">The email message to encrypt</param>
        /// <param name="recipients">The recipient information with their capabilities</param>
        /// <returns>A task that represents the asynchronous S/MIME encryption operation</returns>
        public async Task<CryptographicResult<SmimeEncryptedMessage>> EncryptMessageAsync(
            EmailMessage message,
            IEnumerable<SmimeRecipient> recipients)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (recipients == null) throw new ArgumentNullException(nameof(recipients));

            var recipientList = recipients.ToList();
            if (recipientList.Count == 0)
                return CryptographicResult<SmimeEncryptedMessage>.Failure("No recipients provided");

            try
            {
                _logger.LogInformation("Starting S/MIME encryption for message to {RecipientCount} recipients", 
                    recipientList.Count);

                // Negotiate encryption algorithms based on all recipients' capabilities
                var negotiation = NegotiateEncryptionAlgorithms(recipientList);
                if (!negotiation.AllRecipientsSupported)
                {
                    _logger.LogWarning("Not all recipients support negotiated algorithms. Unsupported capabilities: {Capabilities}",
                        string.Join(", ", negotiation.UnsupportedCapabilities));
                }

                // Serialize the message content
                var messageContent = await SerializeMessageContent(message);

                // Generate content encryption key (CEK)
                var contentEncryptionKey = GenerateContentEncryptionKey(negotiation.ContentEncryptionAlgorithm);

                // Encrypt the message content with CEK
                var encryptedContent = await EncryptMessageContent(messageContent, contentEncryptionKey, negotiation.ContentEncryptionAlgorithm);

                // Create recipient infos for each recipient
                var recipientInfos = new List<RecipientInfo>();
                
                foreach (var recipient in recipientList)
                {
                    var recipientInfo = await CreateRecipientInfo(recipient, contentEncryptionKey, negotiation);
                    if (recipientInfo != null)
                    {
                        recipientInfos.Add(recipientInfo);
                    }
                    else
                    {
                        _logger.LogWarning("Failed to create recipient info for {Email}", recipient.EmailAddress);
                    }
                }

                if (recipientInfos.Count == 0)
                {
                    return CryptographicResult<SmimeEncryptedMessage>.Failure("Failed to create recipient info for any recipient");
                }

                // Create encryption metadata
                var metadata = new SmimeEncryptionMetadata(
                    DateTime.UtcNow,
                    negotiation.NegotiatedStrategy,
                    negotiation,
                    recipientList.Count,
                    true); // Always use protected headers for security

                // Preserve non-sensitive headers outside encryption
                var unprotectedHeaders = ExtractUnprotectedHeaders(message);

                // Create encrypted message
                var encryptedMessage = new SmimeEncryptedMessage(
                    encryptedContent,
                    recipientInfos,
                    negotiation.ContentEncryptionAlgorithm,
                    metadata,
                    unprotectedHeaders);

                _logger.LogInformation("Successfully encrypted S/MIME message with {RecipientCount} recipients using {Strategy} strategy",
                    recipientInfos.Count, negotiation.NegotiatedStrategy);

                return CryptographicResult<SmimeEncryptedMessage>.Success(encryptedMessage);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "S/MIME message encryption failed");
                return CryptographicResult<SmimeEncryptedMessage>.Failure("S/MIME encryption failed", ex);
            }
        }

        /// <summary>
        /// Decrypts an S/MIME encrypted email message.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted S/MIME message</param>
        /// <param name="recipientPrivateKeys">The recipient's private keys for decryption</param>
        /// <returns>A task that represents the asynchronous S/MIME decryption operation</returns>
        public async Task<CryptographicResult<EmailMessage>> DecryptMessageAsync(
            SmimeEncryptedMessage encryptedMessage,
            SmimePrivateKeys recipientPrivateKeys)
        {
            if (encryptedMessage == null) throw new ArgumentNullException(nameof(encryptedMessage));
            if (recipientPrivateKeys == null) throw new ArgumentNullException(nameof(recipientPrivateKeys));

            try
            {
                _logger.LogInformation("Starting S/MIME decryption for message with {RecipientCount} recipient infos",
                    encryptedMessage.RecipientInfos.Count);

                // Try to decrypt the content encryption key using available private keys
                byte[]? contentEncryptionKey = null;
                RecipientInfo? successfulRecipient = null;

                foreach (var recipientInfo in encryptedMessage.RecipientInfos)
                {
                    var dekResult = await TryDecryptContentEncryptionKey(recipientInfo, recipientPrivateKeys);
                    if (dekResult.IsSuccess)
                    {
                        contentEncryptionKey = dekResult.Data;
                        successfulRecipient = recipientInfo;
                        _logger.LogDebug("Successfully decrypted CEK using recipient info of type {Type}", 
                            recipientInfo.Type);
                        break;
                    }
                }

                if (contentEncryptionKey == null)
                {
                    return CryptographicResult<EmailMessage>.Failure(
                        "Failed to decrypt content encryption key with any available private key");
                }

                // Decrypt the message content
                var decryptedContent = await DecryptMessageContent(
                    encryptedMessage.EncryptedData,
                    contentEncryptionKey,
                    encryptedMessage.ContentEncryptionAlgorithm);

                // Deserialize the message
                var message = await DeserializeMessageContent(decryptedContent, encryptedMessage.UnprotectedHeaders);

                _logger.LogInformation("Successfully decrypted S/MIME message from {From}", message.From);

                return CryptographicResult<EmailMessage>.Success(message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "S/MIME message decryption failed");
                return CryptographicResult<EmailMessage>.Failure("S/MIME decryption failed", ex);
            }
        }

        /// <summary>
        /// Signs an email message using S/MIME with hybrid algorithms.
        /// </summary>
        /// <param name="message">The email message to sign</param>
        /// <param name="signingKeys">The private keys for signing</param>
        /// <returns>A task that represents the asynchronous S/MIME signing operation</returns>
        public async Task<CryptographicResult<SmimeSignedMessage>> SignMessageAsync(
            EmailMessage message,
            SmimePrivateKeys signingKeys)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (signingKeys == null) throw new ArgumentNullException(nameof(signingKeys));

            try
            {
                _logger.LogInformation("Starting S/MIME signing for message from {From}", message.From);

                // Serialize the message content
                var messageContent = await SerializeMessageContent(message);

                // Create signatures using available signing keys
                var signatures = new List<SignatureInfo>();
                var certificates = new List<CertificateInfo>();

                // Sign with post-quantum key if available
                if (signingKeys.PostQuantumSigningKey != null && signingKeys.Algorithms.PostQuantumSigning != null)
                {
                    var pqSignatureResult = await _cryptographicProvider.SignAsync(
                        messageContent, signingKeys.PostQuantumSigningKey);
                    
                    if (pqSignatureResult.IsSuccess)
                    {
                        var signatureInfo = CreateSignatureInfo(
                            pqSignatureResult.Data!,
                            signingKeys.Algorithms.PostQuantumSigning);
                        signatures.Add(signatureInfo);
                        
                        _logger.LogDebug("Created post-quantum signature using {Algorithm}", 
                            signingKeys.Algorithms.PostQuantumSigning);
                    }
                }

                // Sign with classical key if available
                if (signingKeys.ClassicalSigningKey != null && signingKeys.Algorithms.ClassicalSigning != null)
                {
                    var classicalSignatureResult = await _cryptographicProvider.SignAsync(
                        messageContent, signingKeys.ClassicalSigningKey);
                    
                    if (classicalSignatureResult.IsSuccess)
                    {
                        var signatureInfo = CreateSignatureInfo(
                            classicalSignatureResult.Data!,
                            signingKeys.Algorithms.ClassicalSigning);
                        signatures.Add(signatureInfo);
                        
                        _logger.LogDebug("Created classical signature using {Algorithm}", 
                            signingKeys.Algorithms.ClassicalSigning);
                    }
                }

                if (signatures.Count == 0)
                {
                    return CryptographicResult<SmimeSignedMessage>.Failure("No signatures could be created");
                }

                // Create signing metadata
                var metadata = new SmimeSigningMetadata(
                    DateTime.UtcNow,
                    DetermineSigningStrategy(signingKeys),
                    signingKeys.Algorithms,
                    false); // Not detached signature

                // Create signed message structure (placeholder for actual CMS SignedData)
                var signedData = CreateCmsSignedData(messageContent, signatures, certificates);

                var signedMessage = new SmimeSignedMessage(
                    signedData,
                    message,
                    signatures,
                    certificates,
                    metadata);

                _logger.LogInformation("Successfully created S/MIME signed message with {SignatureCount} signatures",
                    signatures.Count);

                return CryptographicResult<SmimeSignedMessage>.Success(signedMessage);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "S/MIME message signing failed");
                return CryptographicResult<SmimeSignedMessage>.Failure("S/MIME signing failed", ex);
            }
        }

        /// <summary>
        /// Verifies the signature of an S/MIME signed message.
        /// </summary>
        /// <param name="signedMessage">The signed S/MIME message</param>
        /// <param name="senderPublicKeys">The sender's public keys for verification</param>
        /// <returns>A task that represents the asynchronous S/MIME signature verification operation</returns>
        public async Task<CryptographicResult<SmimeSignatureVerificationResult>> VerifySignatureAsync(
            SmimeSignedMessage signedMessage,
            SmimePublicKeys senderPublicKeys)
        {
            if (signedMessage == null) throw new ArgumentNullException(nameof(signedMessage));
            if (senderPublicKeys == null) throw new ArgumentNullException(nameof(senderPublicKeys));

            try
            {
                _logger.LogInformation("Starting S/MIME signature verification for message with {SignatureCount} signatures",
                    signedMessage.Signatures.Count);

                var verificationResults = new List<SignatureVerificationResult>();
                var warnings = new List<string>();
                var overallValid = true;

                // Serialize the original message content for verification
                var messageContent = await SerializeMessageContent(signedMessage.OriginalMessage);

                foreach (var signature in signedMessage.Signatures)
                {
                    var result = await VerifySingleSignature(signature, messageContent, senderPublicKeys);
                    verificationResults.Add(result);
                    
                    if (!result.IsValid)
                    {
                        overallValid = false;
                        _logger.LogWarning("Signature verification failed for algorithm {Algorithm}: {Error}",
                            signature.SignatureAlgorithm.Algorithm, result.ErrorMessage);
                    }
                }

                var verificationResult = new SmimeSignatureVerificationResult(
                    overallValid,
                    verificationResults,
                    signedMessage.Certificates,
                    DateTime.UtcNow,
                    warnings);

                _logger.LogInformation("S/MIME signature verification completed. Overall valid: {IsValid}", overallValid);

                return CryptographicResult<SmimeSignatureVerificationResult>.Success(verificationResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "S/MIME signature verification failed");
                return CryptographicResult<SmimeSignatureVerificationResult>.Failure("S/MIME signature verification failed", ex);
            }
        }

        /// <summary>
        /// Determines the recipient capabilities by examining their certificates.
        /// </summary>
        /// <param name="recipientCertificates">The recipient's certificates</param>
        /// <returns>The recipient's cryptographic capabilities</returns>
        public RecipientCapabilities DetermineRecipientCapabilities(IEnumerable<CertificateInfo> recipientCertificates)
        {
            if (recipientCertificates == null) throw new ArgumentNullException(nameof(recipientCertificates));

            var certificates = recipientCertificates.ToList();
            if (certificates.Count == 0)
            {
                // Default to classical only if no certificates
                return new RecipientCapabilities(
                    false,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    new[] { "RSA-2048", "ECDSA-P256" },
                    false);
            }

            var supportedPqcKem = new List<string>();
            var supportedPqcSig = new List<string>();
            var supportedClassical = new List<string>();
            var supportsPostQuantum = false;
            var supportsHybrid = false;

            foreach (var cert in certificates)
            {
                // Check for PQC capabilities
                if (cert.PostQuantumEncryptionPublicKey != null)
                {
                    supportsPostQuantum = true;
                    if (!string.IsNullOrEmpty(cert.PostQuantumEncryptionAlgorithm))
                    {
                        supportedPqcKem.Add(cert.PostQuantumEncryptionAlgorithm);
                    }
                }

                if (cert.PostQuantumSigningPublicKey != null)
                {
                    supportsPostQuantum = true;
                    if (!string.IsNullOrEmpty(cert.PostQuantumSigningAlgorithm))
                    {
                        supportedPqcSig.Add(cert.PostQuantumSigningAlgorithm);
                    }
                }

                // Check for classical capabilities
                if (cert.ClassicalEncryptionPublicKey != null && !string.IsNullOrEmpty(cert.ClassicalEncryptionAlgorithm))
                {
                    supportedClassical.Add(cert.ClassicalEncryptionAlgorithm);
                }

                if (cert.ClassicalSigningPublicKey != null && !string.IsNullOrEmpty(cert.ClassicalSigningAlgorithm))
                {
                    supportedClassical.Add(cert.ClassicalSigningAlgorithm);
                }

                // Check if hybrid mode is supported (has both PQC and classical)
                if (cert.PostQuantumEncryptionPublicKey != null && cert.ClassicalEncryptionPublicKey != null)
                {
                    supportsHybrid = true;
                }
            }

            return new RecipientCapabilities(
                supportsPostQuantum,
                supportedPqcKem.Distinct().ToArray(),
                supportedPqcSig.Distinct().ToArray(),
                supportedClassical.Distinct().ToArray(),
                supportsHybrid);
        }

        /// <summary>
        /// Negotiates the optimal encryption algorithm based on all recipients' capabilities.
        /// </summary>
        /// <param name="recipients">The recipients with their capabilities</param>
        /// <returns>The negotiated encryption strategy and algorithms</returns>
        public SmimeAlgorithmNegotiation NegotiateEncryptionAlgorithms(IEnumerable<SmimeRecipient> recipients)
        {
            if (recipients == null) throw new ArgumentNullException(nameof(recipients));

            var recipientList = recipients.ToList();
            if (recipientList.Count == 0)
            {
                throw new ArgumentException("No recipients provided for algorithm negotiation");
            }

            _logger.LogDebug("Negotiating encryption algorithms for {RecipientCount} recipients", recipientList.Count);

            // Determine common capabilities
            var allSupportsHybrid = recipientList.All(r => r.Capabilities.SupportsHybrid);
            var allSupportsPqc = recipientList.All(r => r.Capabilities.SupportsPostQuantum);
            var allSupportsClassical = recipientList.All(r => r.Capabilities.SupportedClassicalAlgorithms.Length > 0);

            // Find common PQC KEM algorithms
            var commonPqcKem = recipientList
                .SelectMany(r => r.Capabilities.SupportedPqcKemAlgorithms)
                .GroupBy(alg => alg)
                .Where(g => g.Count() == recipientList.Count)
                .Select(g => g.Key)
                .ToList();

            // Find common classical algorithms
            var commonClassical = recipientList
                .SelectMany(r => r.Capabilities.SupportedClassicalAlgorithms)
                .GroupBy(alg => alg)
                .Where(g => g.Count() == recipientList.Count)
                .Select(g => g.Key)
                .ToList();

            // Determine strategy based on provider configuration and capabilities
            EncryptionStrategy negotiatedStrategy;
            var unsupportedCapabilities = new List<string>();

            if (_cryptographicProvider.Configuration.Mode == CryptographicMode.Hybrid && allSupportsHybrid)
            {
                negotiatedStrategy = EncryptionStrategy.Hybrid;
            }
            else if (_cryptographicProvider.Configuration.Mode == CryptographicMode.PostQuantumOnly && allSupportsPqc)
            {
                negotiatedStrategy = EncryptionStrategy.PostQuantumOnly;
            }
            else if (allSupportsClassical)
            {
                negotiatedStrategy = EncryptionStrategy.ClassicalOnly;
                if (_cryptographicProvider.Configuration.Mode != CryptographicMode.ClassicalOnly)
                {
                    unsupportedCapabilities.Add("Some recipients don't support PQC, falling back to classical");
                }
            }
            else
            {
                // Fall back to best available
                if (allSupportsPqc)
                {
                    negotiatedStrategy = EncryptionStrategy.PostQuantumOnly;
                }
                else
                {
                    negotiatedStrategy = EncryptionStrategy.ClassicalOnly;
                    unsupportedCapabilities.Add("Mixed recipient capabilities, using classical only");
                }
            }

            // Select content encryption algorithm
            var contentEncryptionAlgorithm = "AES-256-GCM"; // Default

            // Create per-recipient KEM algorithm mapping
            var recipientKemAlgorithms = new Dictionary<string, string>();
            
            foreach (var recipient in recipientList)
            {
                var kemAlgorithm = SelectKemAlgorithmForRecipient(recipient, negotiatedStrategy, commonPqcKem, commonClassical);
                recipientKemAlgorithms[recipient.EmailAddress] = kemAlgorithm;
            }

            var result = new SmimeAlgorithmNegotiation(
                negotiatedStrategy,
                contentEncryptionAlgorithm,
                recipientKemAlgorithms,
                unsupportedCapabilities.Count == 0,
                unsupportedCapabilities);

            _logger.LogInformation("Negotiated encryption strategy: {Strategy} with content algorithm: {ContentAlgorithm}",
                negotiatedStrategy, contentEncryptionAlgorithm);

            return result;
        }

        #region Private Methods

        private async Task<byte[]> SerializeMessageContent(EmailMessage message)
        {
            // Create MIME message structure
            var mimeBuilder = new System.Text.StringBuilder();
            
            // Add headers
            mimeBuilder.AppendLine($"From: {message.From}");
            mimeBuilder.AppendLine($"To: {string.Join(", ", message.To)}");
            if (message.Cc.Count > 0)
                mimeBuilder.AppendLine($"Cc: {string.Join(", ", message.Cc)}");
            mimeBuilder.AppendLine($"Subject: {message.Subject}");
            mimeBuilder.AppendLine($"Date: {message.Timestamp:R}");
            mimeBuilder.AppendLine($"Content-Type: {message.ContentType}");
            
            foreach (var header in message.Headers)
            {
                mimeBuilder.AppendLine($"{header.Key}: {header.Value}");
            }
            
            mimeBuilder.AppendLine(); // Empty line between headers and body
            mimeBuilder.AppendLine(message.Body);
            
            // Add attachments if any
            if (message.Attachments.Count > 0)
            {
                // This is simplified - real MIME would use multipart
                foreach (var attachment in message.Attachments)
                {
                    mimeBuilder.AppendLine($"--boundary");
                    mimeBuilder.AppendLine($"Content-Type: {attachment.ContentType}");
                    mimeBuilder.AppendLine($"Content-Disposition: {attachment.ContentDisposition}; filename=\"{attachment.FileName}\"");
                    mimeBuilder.AppendLine();
                    mimeBuilder.AppendLine(Convert.ToBase64String(attachment.Data));
                }
                mimeBuilder.AppendLine($"--boundary--");
            }

            return System.Text.Encoding.UTF8.GetBytes(mimeBuilder.ToString());
        }

        private async Task<EmailMessage> DeserializeMessageContent(byte[] content, IReadOnlyDictionary<string, string> unprotectedHeaders)
        {
            var mimeContent = System.Text.Encoding.UTF8.GetString(content);
            var lines = mimeContent.Split('\n');
            
            var headers = new Dictionary<string, string>();
            var bodyLines = new List<string>();
            var attachments = new List<EmailAttachment>();
            
            bool inBody = false;
            
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) && !inBody)
                {
                    inBody = true;
                    continue;
                }
                
                if (!inBody && line.Contains(':'))
                {
                    var colonIndex = line.IndexOf(':');
                    var key = line.Substring(0, colonIndex).Trim();
                    var value = line.Substring(colonIndex + 1).Trim();
                    headers[key] = value;
                }
                else if (inBody)
                {
                    bodyLines.Add(line);
                }
            }
            
            // Extract standard headers
            var from = headers.GetValueOrDefault("From", "");
            var to = headers.GetValueOrDefault("To", "").Split(',').Select(t => t.Trim()).Where(t => !string.IsNullOrEmpty(t)).ToList();
            var cc = headers.GetValueOrDefault("Cc", "").Split(',').Select(t => t.Trim()).Where(t => !string.IsNullOrEmpty(t)).ToList();
            var subject = headers.GetValueOrDefault("Subject", "");
            var contentType = headers.GetValueOrDefault("Content-Type", "text/plain");
            
            DateTime timestamp = DateTime.UtcNow;
            if (headers.ContainsKey("Date") && DateTime.TryParse(headers["Date"], out var parsedDate))
            {
                timestamp = parsedDate;
            }
            
            var body = string.Join("\n", bodyLines);
            
            return new EmailMessage(from, to, cc, null, subject, body, attachments, headers, contentType, timestamp);
        }

        private byte[] GenerateContentEncryptionKey(string algorithm)
        {
            // Generate appropriate key size based on algorithm
            var keySize = algorithm switch
            {
                "AES-128-GCM" => 16,
                "AES-256-GCM" => 32,
                "AES-128-CBC" => 16,
                "AES-256-CBC" => 32,
                _ => 32 // Default to 256-bit
            };

            var key = new byte[keySize];
            _rng.GetBytes(key);
            return key;
        }

        private async Task<byte[]> EncryptMessageContent(byte[] content, byte[] key, string algorithm)
        {
            // Simplified content encryption - real implementation would handle different algorithms
            using (var aes = new AesGcm(key))
            {
                var iv = new byte[12]; // 96-bit IV for AES-GCM
                _rng.GetBytes(iv);
                
                var ciphertext = new byte[content.Length];
                var authTag = new byte[16]; // 128-bit auth tag
                
                aes.Encrypt(iv, content, ciphertext, authTag);
                
                // Combine IV, ciphertext, and auth tag
                var result = new byte[iv.Length + ciphertext.Length + authTag.Length];
                Array.Copy(iv, 0, result, 0, iv.Length);
                Array.Copy(ciphertext, 0, result, iv.Length, ciphertext.Length);
                Array.Copy(authTag, 0, result, iv.Length + ciphertext.Length, authTag.Length);
                
                return result;
            }
        }

        private async Task<byte[]> DecryptMessageContent(byte[] encryptedContent, byte[] key, string algorithm)
        {
            // Simplified content decryption - real implementation would handle different algorithms
            if (encryptedContent.Length < 28) // 12 IV + 16 auth tag minimum
                throw new ArgumentException("Encrypted content too short");

            var iv = new byte[12];
            var authTag = new byte[16];
            var ciphertext = new byte[encryptedContent.Length - 28];

            Array.Copy(encryptedContent, 0, iv, 0, 12);
            Array.Copy(encryptedContent, 12, ciphertext, 0, ciphertext.Length);
            Array.Copy(encryptedContent, encryptedContent.Length - 16, authTag, 0, 16);

            using (var aes = new AesGcm(key))
            {
                var plaintext = new byte[ciphertext.Length];
                aes.Decrypt(iv, ciphertext, authTag, plaintext);
                return plaintext;
            }
        }

        private async Task<RecipientInfo?> CreateRecipientInfo(
            SmimeRecipient recipient, 
            byte[] contentEncryptionKey,
            SmimeAlgorithmNegotiation negotiation)
        {
            var kemAlgorithm = negotiation.RecipientKemAlgorithms.GetValueOrDefault(recipient.EmailAddress);
            if (string.IsNullOrEmpty(kemAlgorithm))
            {
                _logger.LogError("No KEM algorithm negotiated for recipient {Email}", recipient.EmailAddress);
                return null;
            }

            // Check if this is a PQC algorithm
            if (kemAlgorithm.StartsWith("ML-KEM"))
            {
                // Use KEMRecipientInfo for post-quantum algorithms
                var kemResult = await _kemRecipientInfoProcessor.CreateKemRecipientInfoAsync(
                    recipient.Certificate, contentEncryptionKey, kemAlgorithm);
                
                if (kemResult.IsSuccess)
                {
                    return new KemRecipientInfoWrapper(kemResult.Data!);
                }
                else
                {
                    _logger.LogError("Failed to create KEMRecipientInfo for recipient {Email}: {Error}",
                        recipient.EmailAddress, kemResult.ErrorMessage);
                    return null;
                }
            }
            else
            {
                // Use KeyTransRecipientInfo for classical algorithms
                return await CreateClassicalRecipientInfo(recipient, contentEncryptionKey, kemAlgorithm);
            }
        }

        private async Task<RecipientInfo?> CreateClassicalRecipientInfo(
            SmimeRecipient recipient,
            byte[] contentEncryptionKey,
            string algorithm)
        {
            try
            {
                // Get the appropriate classical public key
                var publicKey = recipient.Certificate.ClassicalEncryptionPublicKey;
                if (publicKey == null)
                {
                    _logger.LogError("No classical encryption public key available for recipient {Email}", recipient.EmailAddress);
                    return null;
                }

                // Encrypt the content encryption key using classical algorithm
                var encryptionResult = await _cryptographicProvider.EncryptAsync(contentEncryptionKey, publicKey);
                if (!encryptionResult.IsSuccess)
                {
                    _logger.LogError("Failed to encrypt CEK for recipient {Email}: {Error}",
                        recipient.EmailAddress, encryptionResult.ErrorMessage);
                    return null;
                }

                // Create recipient identifier
                var recipientId = CreateRecipientIdentifier(recipient.Certificate);

                // Create key encryption algorithm identifier
                var keyEncryptionAlgorithm = new AlgorithmIdentifier(GetClassicalAlgorithmOid(algorithm));

                return new KeyTransRecipientInfo(recipientId, keyEncryptionAlgorithm, encryptionResult.Data!.EncryptedData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create classical recipient info for {Email}", recipient.EmailAddress);
                return null;
            }
        }

        private async Task<CryptographicResult<byte[]>> TryDecryptContentEncryptionKey(
            RecipientInfo recipientInfo,
            SmimePrivateKeys privateKeys)
        {
            try
            {
                if (recipientInfo is KemRecipientInfoWrapper kemWrapper)
                {
                    // Handle PQC KEMRecipientInfo
                    var privateKey = privateKeys.PostQuantumEncryptionKey;
                    if (privateKey == null)
                    {
                        return CryptographicResult<byte[]>.Failure("No PQC private key available");
                    }

                    return await _kemRecipientInfoProcessor.ProcessKemRecipientInfoAsync(kemWrapper.KemInfo, privateKey);
                }
                else if (recipientInfo is KeyTransRecipientInfo keyTransInfo)
                {
                    // Handle classical KeyTransRecipientInfo
                    var privateKey = privateKeys.ClassicalEncryptionKey;
                    if (privateKey == null)
                    {
                        return CryptographicResult<byte[]>.Failure("No classical private key available");
                    }

                    return await _cryptographicProvider.DecryptAsync(keyTransInfo.EncryptedKey, privateKey);
                }
                else
                {
                    return CryptographicResult<byte[]>.Failure($"Unsupported recipient info type: {recipientInfo.Type}");
                }
            }
            catch (Exception ex)
            {
                return CryptographicResult<byte[]>.Failure("Failed to decrypt content encryption key", ex);
            }
        }

        private Dictionary<string, string> ExtractUnprotectedHeaders(EmailMessage message)
        {
            // Only preserve non-sensitive headers outside encryption
            var unprotectedHeaders = new Dictionary<string, string>
            {
                ["Content-Type"] = "application/pkcs7-mime; smime-type=enveloped-data",
                ["Content-Transfer-Encoding"] = "base64"
            };

            return unprotectedHeaders;
        }

        private string SelectKemAlgorithmForRecipient(
            SmimeRecipient recipient,
            EncryptionStrategy strategy,
            List<string> commonPqcKem,
            List<string> commonClassical)
        {
            return strategy switch
            {
                EncryptionStrategy.PostQuantumOnly => commonPqcKem.FirstOrDefault() ?? "ML-KEM-768",
                EncryptionStrategy.ClassicalOnly => commonClassical.FirstOrDefault() ?? "RSA-2048",
                EncryptionStrategy.Hybrid => commonPqcKem.FirstOrDefault() ?? "ML-KEM-768",
                _ => "RSA-2048"
            };
        }

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

        private string GetClassicalAlgorithmOid(string algorithm)
        {
            return algorithm switch
            {
                "RSA-2048" => AlgorithmOids.RsaEncryption,
                "RSA-4096" => AlgorithmOids.RsaEncryption,
                "ECDSA-P256" => AlgorithmOids.EcdsaWithSha256,
                _ => AlgorithmOids.RsaEncryption
            };
        }

        private SignatureInfo CreateSignatureInfo(SignatureResult signatureResult, string algorithm)
        {
            var algorithmId = new AlgorithmIdentifier(GetSignatureAlgorithmOid(algorithm));
            var recipientId = new RecipientIdentifier(new byte[0]); // Simplified - would need actual identifier

            return new SignatureInfo(
                algorithmId,
                signatureResult.Signature,
                recipientId);
        }

        private string GetSignatureAlgorithmOid(string algorithm)
        {
            return algorithm switch
            {
                "ML-DSA-44" => AlgorithmOids.MlDsa44,
                "ML-DSA-65" => AlgorithmOids.MlDsa65,
                "ML-DSA-87" => AlgorithmOids.MlDsa87,
                "RSA-SHA256" => AlgorithmOids.RsaPkcs1Sha256,
                "ECDSA-SHA256" => AlgorithmOids.EcdsaWithSha256,
                _ => AlgorithmOids.RsaPkcs1Sha256
            };
        }

        private EncryptionStrategy DetermineSigningStrategy(SmimePrivateKeys signingKeys)
        {
            var hasPqc = signingKeys.PostQuantumSigningKey != null;
            var hasClassical = signingKeys.ClassicalSigningKey != null;

            if (hasPqc && hasClassical)
                return EncryptionStrategy.Hybrid;
            else if (hasPqc)
                return EncryptionStrategy.PostQuantumOnly;
            else
                return EncryptionStrategy.ClassicalOnly;
        }

        private byte[] CreateCmsSignedData(
            byte[] content,
            List<SignatureInfo> signatures,
            List<CertificateInfo> certificates)
        {
            // This is a placeholder - real implementation would create proper CMS SignedData structure
            var signedDataBuilder = new System.Text.StringBuilder();
            signedDataBuilder.AppendLine("-----BEGIN PKCS7-----");
            
            // Simplified CMS structure encoding
            var combinedSignatures = signatures.SelectMany(s => s.SignatureValue).ToArray();
            var encodedSignatures = Convert.ToBase64String(combinedSignatures);
            signedDataBuilder.AppendLine(encodedSignatures);
            
            signedDataBuilder.AppendLine("-----END PKCS7-----");
            
            return System.Text.Encoding.UTF8.GetBytes(signedDataBuilder.ToString());
        }

        private async Task<SignatureVerificationResult> VerifySingleSignature(
            SignatureInfo signature,
            byte[] messageContent,
            SmimePublicKeys senderPublicKeys)
        {
            try
            {
                var algorithm = GetAlgorithmFromSignatureOid(signature.SignatureAlgorithm.Algorithm);
                
                // Determine which public key to use based on algorithm
                byte[]? publicKey = null;
                if (algorithm.StartsWith("ML-DSA"))
                {
                    publicKey = senderPublicKeys.PostQuantumSigningKey;
                }
                else
                {
                    publicKey = senderPublicKeys.ClassicalSigningKey;
                }

                if (publicKey == null)
                {
                    return new SignatureVerificationResult(
                        false,
                        algorithm,
                        new CertificateInfo("", "", "", DateTime.UtcNow, DateTime.UtcNow, null, null, null, null, null, null, "", "", "", ""),
                        $"No appropriate public key available for algorithm {algorithm}");
                }

                var verificationResult = await _cryptographicProvider.VerifySignatureAsync(
                    messageContent, signature.SignatureValue, publicKey);

                var certificateInfo = new CertificateInfo("", "", "", DateTime.UtcNow, DateTime.UtcNow, null, null, null, null, null, null, "", "", "", "");

                return new SignatureVerificationResult(
                    verificationResult.IsSuccess && verificationResult.Data == true,
                    algorithm,
                    certificateInfo,
                    verificationResult.IsSuccess ? null : verificationResult.ErrorMessage);
            }
            catch (Exception ex)
            {
                var certificateInfo = new CertificateInfo("", "", "", DateTime.UtcNow, DateTime.UtcNow, null, null, null, null, null, null, "", "", "", "");
                return new SignatureVerificationResult(
                    false,
                    "unknown",
                    certificateInfo,
                    ex.Message);
            }
        }

        private string GetAlgorithmFromSignatureOid(string oid)
        {
            return oid switch
            {
                AlgorithmOids.MlDsa44 => "ML-DSA-44",
                AlgorithmOids.MlDsa65 => "ML-DSA-65",
                AlgorithmOids.MlDsa87 => "ML-DSA-87",
                AlgorithmOids.RsaPkcs1Sha256 => "RSA-SHA256",
                AlgorithmOids.EcdsaWithSha256 => "ECDSA-SHA256",
                _ => "unknown"
            };
        }

        #endregion
    }
}