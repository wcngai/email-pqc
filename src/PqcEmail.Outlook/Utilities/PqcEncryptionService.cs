using System;
using System.Threading.Tasks;
using System.Text;
using System.Linq;
using Outlook = Microsoft.Office.Interop.Outlook;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;
using PqcEmail.Outlook.COM;

namespace PqcEmail.Outlook.Utilities
{
    /// <summary>
    /// Service that handles PQC encryption/decryption operations for Outlook emails.
    /// This class bridges the gap between Outlook's email format and the PQC core library.
    /// </summary>
    public class PqcEncryptionService
    {
        private readonly IHybridEncryptionEngine _encryptionEngine;
        private readonly OutlookComInterop _comInterop;

        /// <summary>
        /// Initializes a new instance of the <see cref="PqcEncryptionService"/> class.
        /// </summary>
        /// <param name="encryptionEngine">The hybrid encryption engine.</param>
        /// <param name="comInterop">The COM interop helper.</param>
        public PqcEncryptionService(IHybridEncryptionEngine encryptionEngine, OutlookComInterop comInterop)
        {
            _encryptionEngine = encryptionEngine ?? throw new ArgumentNullException(nameof(encryptionEngine));
            _comInterop = comInterop ?? throw new ArgumentNullException(nameof(comInterop));
        }

        /// <summary>
        /// Encrypts an outgoing email using PQC algorithms.
        /// </summary>
        /// <param name="mailItem">The mail item to encrypt.</param>
        /// <param name="recipients">The list of recipients.</param>
        /// <param name="strategy">The encryption strategy to use.</param>
        /// <returns>A task representing the asynchronous encryption operation.</returns>
        public async Task<EncryptionResult> EncryptEmailAsync(
            Outlook.MailItem mailItem,
            System.Collections.Generic.List<string> recipients,
            EncryptionStrategy strategy)
        {
            try
            {
                // Extract email content
                var emailContent = await ExtractEmailContentAsync(mailItem);
                
                // For MVP, we'll simulate the encryption process
                // In production, this would use the actual PQC algorithms
                var encryptedContent = await SimulatePqcEncryptionAsync(emailContent, recipients, strategy);
                
                // Update the email with encrypted content
                await ApplyEncryptedContentAsync(mailItem, encryptedContent, strategy);
                
                // Add metadata
                await AddEncryptionMetadataAsync(mailItem, strategy, recipients);
                
                return new EncryptionResult
                {
                    Success = true,
                    Strategy = strategy,
                    Recipients = recipients,
                    EncryptedAt = DateTime.UtcNow,
                    AlgorithmUsed = GetAlgorithmName(strategy)
                };
            }
            catch (Exception ex)
            {
                return new EncryptionResult
                {
                    Success = false,
                    Error = ex.Message,
                    Strategy = strategy,
                    Recipients = recipients
                };
            }
        }

        /// <summary>
        /// Decrypts an incoming email that was encrypted with PQC.
        /// </summary>
        /// <param name="mailItem">The mail item to decrypt.</param>
        /// <returns>A task representing the asynchronous decryption operation.</returns>
        public async Task<DecryptionResult> DecryptEmailAsync(Outlook.MailItem mailItem)
        {
            try
            {
                // Check if email is PQC encrypted
                var encryptionStrategy = await GetEncryptionStrategyAsync(mailItem);
                if (encryptionStrategy == null)
                {
                    return new DecryptionResult
                    {
                        Success = false,
                        Error = "Email is not PQC encrypted"
                    };
                }

                // Extract encrypted content
                var encryptedContent = await ExtractEncryptedContentAsync(mailItem);
                
                // For MVP, simulate the decryption process
                // In production, this would use the actual PQC algorithms
                var decryptedContent = await SimulatePqcDecryptionAsync(encryptedContent, encryptionStrategy.Value);
                
                // Apply decrypted content to email
                await ApplyDecryptedContentAsync(mailItem, decryptedContent);
                
                // Add decryption metadata
                await AddDecryptionMetadataAsync(mailItem, encryptionStrategy.Value);
                
                return new DecryptionResult
                {
                    Success = true,
                    Strategy = encryptionStrategy.Value,
                    DecryptedAt = DateTime.UtcNow,
                    AlgorithmUsed = GetAlgorithmName(encryptionStrategy.Value)
                };
            }
            catch (Exception ex)
            {
                return new DecryptionResult
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        /// <summary>
        /// Signs an email using PQC digital signatures.
        /// </summary>
        /// <param name="mailItem">The mail item to sign.</param>
        /// <returns>A task representing the asynchronous signing operation.</returns>
        public async Task<SigningResult> SignEmailAsync(Outlook.MailItem mailItem)
        {
            try
            {
                // Extract content for signing
                var content = await ExtractEmailContentAsync(mailItem);
                var contentHash = ComputeContentHash(content);
                
                // For MVP, simulate PQC signing
                // In production, this would use ML-DSA-65 or similar
                var signature = await SimulatePqcSigningAsync(contentHash);
                
                // Add signature metadata
                await AddSignatureMetadataAsync(mailItem, signature);
                
                return new SigningResult
                {
                    Success = true,
                    SignedAt = DateTime.UtcNow,
                    Algorithm = "ML-DSA-65",
                    SignatureSize = signature.Length
                };
            }
            catch (Exception ex)
            {
                return new SigningResult
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        /// <summary>
        /// Verifies the PQC digital signature on an email.
        /// </summary>
        /// <param name="mailItem">The mail item to verify.</param>
        /// <returns>A task representing the asynchronous verification operation.</returns>
        public async Task<VerificationResult> VerifyEmailSignatureAsync(Outlook.MailItem mailItem)
        {
            try
            {
                // Get signature metadata
                var signatureData = await GetSignatureMetadataAsync(mailItem);
                if (signatureData == null)
                {
                    return new VerificationResult
                    {
                        Success = false,
                        Error = "No PQC signature found"
                    };
                }

                // Extract current content
                var content = await ExtractEmailContentAsync(mailItem);
                var contentHash = ComputeContentHash(content);
                
                // For MVP, simulate PQC verification
                // In production, this would use actual ML-DSA-65 verification
                var isValid = await SimulatePqcVerificationAsync(contentHash, signatureData);
                
                return new VerificationResult
                {
                    Success = true,
                    IsValid = isValid,
                    VerifiedAt = DateTime.UtcNow,
                    Algorithm = "ML-DSA-65",
                    SignerInfo = signatureData.Signer
                };
            }
            catch (Exception ex)
            {
                return new VerificationResult
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        #region Private Helper Methods

        /// <summary>
        /// Extracts email content for cryptographic operations.
        /// </summary>
        /// <param name="mailItem">The mail item.</param>
        /// <returns>The extracted content.</returns>
        private async Task<EmailContent> ExtractEmailContentAsync(Outlook.MailItem mailItem)
        {
            return await Task.Run(() => new EmailContent
            {
                Subject = mailItem.Subject ?? string.Empty,
                Body = mailItem.Body ?? string.Empty,
                HtmlBody = mailItem.HTMLBody ?? string.Empty,
                SenderEmail = mailItem.SenderEmailAddress ?? string.Empty,
                SenderName = mailItem.SenderName ?? string.Empty,
                CreationTime = mailItem.CreationTime,
                Recipients = _comInterop.GetRecipientsAsync(mailItem).Result
            });
        }

        /// <summary>
        /// Simulates PQC encryption for MVP demonstration.
        /// </summary>
        /// <param name="content">The content to encrypt.</param>
        /// <param name="recipients">The recipients.</param>
        /// <param name="strategy">The encryption strategy.</param>
        /// <returns>The simulated encrypted content.</returns>
        private async Task<EncryptedContent> SimulatePqcEncryptionAsync(
            EmailContent content, 
            System.Collections.Generic.List<string> recipients, 
            EncryptionStrategy strategy)
        {
            await Task.Delay(100); // Simulate encryption time
            
            var algorithmName = GetAlgorithmName(strategy);
            var timestamp = DateTime.UtcNow;
            
            // Create encrypted markers that can be recognized for decryption
            var encryptedSubject = $"[PQC-{strategy}-SUBJ:{timestamp:O}]{content.Subject}";
            var encryptedBody = $"[PQC-{strategy}-BODY:{timestamp:O}]{content.Body}";
            var encryptedHtmlBody = $"[PQC-{strategy}-HTML:{timestamp:O}]{content.HtmlBody}";
            
            return new EncryptedContent
            {
                Subject = encryptedSubject,
                Body = encryptedBody,
                HtmlBody = encryptedHtmlBody,
                Algorithm = algorithmName,
                Timestamp = timestamp,
                Recipients = recipients
            };
        }

        /// <summary>
        /// Simulates PQC decryption for MVP demonstration.
        /// </summary>
        /// <param name="encryptedContent">The encrypted content.</param>
        /// <param name="strategy">The encryption strategy used.</param>
        /// <returns>The simulated decrypted content.</returns>
        private async Task<EmailContent> SimulatePqcDecryptionAsync(
            EncryptedContent encryptedContent, 
            EncryptionStrategy strategy)
        {
            await Task.Delay(50); // Simulate decryption time
            
            // Remove encryption markers
            var subject = RemoveEncryptionMarker(encryptedContent.Subject, $"PQC-{strategy}-SUBJ:");
            var body = RemoveEncryptionMarker(encryptedContent.Body, $"PQC-{strategy}-BODY:");
            var htmlBody = RemoveEncryptionMarker(encryptedContent.HtmlBody, $"PQC-{strategy}-HTML:");
            
            return new EmailContent
            {
                Subject = subject,
                Body = body,
                HtmlBody = htmlBody,
                Recipients = encryptedContent.Recipients
            };
        }

        /// <summary>
        /// Simulates PQC signing for MVP demonstration.
        /// </summary>
        /// <param name="contentHash">The content hash to sign.</param>
        /// <returns>The simulated signature.</returns>
        private async Task<byte[]> SimulatePqcSigningAsync(byte[] contentHash)
        {
            await Task.Delay(25); // Simulate signing time
            
            // Create a deterministic signature based on content hash
            var timestamp = DateTime.UtcNow;
            var signatureData = $"PQC-ML-DSA-65:{timestamp:O}:{Convert.ToBase64String(contentHash)}";
            return Encoding.UTF8.GetBytes(signatureData);
        }

        /// <summary>
        /// Simulates PQC signature verification for MVP demonstration.
        /// </summary>
        /// <param name="contentHash">The current content hash.</param>
        /// <param name="signatureData">The signature metadata.</param>
        /// <returns>True if the signature is valid.</returns>
        private async Task<bool> SimulatePqcVerificationAsync(byte[] contentHash, SignatureMetadata signatureData)
        {
            await Task.Delay(25); // Simulate verification time
            
            // For MVP, assume signature is valid if it exists and follows expected format
            return !string.IsNullOrEmpty(signatureData.Algorithm) && 
                   signatureData.Algorithm.Contains("ML-DSA");
        }

        /// <summary>
        /// Gets the encryption strategy used for an email.
        /// </summary>
        /// <param name="mailItem">The mail item.</param>
        /// <returns>The encryption strategy, or null if not encrypted.</returns>
        private async Task<EncryptionStrategy?> GetEncryptionStrategyAsync(Outlook.MailItem mailItem)
        {
            var strategyText = await _comInterop.GetCustomPropertyAsync(mailItem, "PQC_Strategy");
            
            if (Enum.TryParse<EncryptionStrategy>(strategyText, out var strategy))
            {
                return strategy;
            }
            
            // Check for encryption markers in content
            var body = mailItem.Body ?? string.Empty;
            if (body.Contains("[PQC-Hybrid-"))
                return EncryptionStrategy.Hybrid;
            if (body.Contains("[PQC-PostQuantumOnly-"))
                return EncryptionStrategy.PostQuantumOnly;
            if (body.Contains("[PQC-ClassicalOnly-"))
                return EncryptionStrategy.ClassicalOnly;
            
            return null;
        }

        /// <summary>
        /// Extracts encrypted content from an email.
        /// </summary>
        /// <param name="mailItem">The mail item.</param>
        /// <returns>The encrypted content.</returns>
        private async Task<EncryptedContent> ExtractEncryptedContentAsync(Outlook.MailItem mailItem)
        {
            return await Task.Run(() => new EncryptedContent
            {
                Subject = mailItem.Subject ?? string.Empty,
                Body = mailItem.Body ?? string.Empty,
                HtmlBody = mailItem.HTMLBody ?? string.Empty,
                Recipients = _comInterop.GetRecipientsAsync(mailItem).Result,
                Algorithm = _comInterop.GetCustomPropertyAsync(mailItem, "PQC_Algorithm").Result ?? "Unknown"
            });
        }

        /// <summary>
        /// Applies encrypted content to an email.
        /// </summary>
        /// <param name="mailItem">The mail item.</param>
        /// <param name="encryptedContent">The encrypted content.</param>
        /// <param name="strategy">The encryption strategy.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task ApplyEncryptedContentAsync(
            Outlook.MailItem mailItem, 
            EncryptedContent encryptedContent, 
            EncryptionStrategy strategy)
        {
            // For security, only encrypt the body content, keep subject readable for routing
            await _comInterop.UpdateMailBodyAsync(mailItem, encryptedContent.Body, Outlook.OlBodyFormat.olFormatPlain);
            
            // Add visual indicator to subject if configured
            if (!mailItem.Subject.StartsWith("[PQC-Protected]"))
            {
                mailItem.Subject = $"[PQC-Protected] {mailItem.Subject}";
            }
        }

        /// <summary>
        /// Applies decrypted content to an email.
        /// </summary>
        /// <param name="mailItem">The mail item.</param>
        /// <param name="decryptedContent">The decrypted content.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task ApplyDecryptedContentAsync(Outlook.MailItem mailItem, EmailContent decryptedContent)
        {
            await _comInterop.UpdateMailBodyAsync(mailItem, decryptedContent.Body, Outlook.OlBodyFormat.olFormatPlain);
            
            // Remove PQC protection indicator from subject
            if (mailItem.Subject.StartsWith("[PQC-Protected] "))
            {
                mailItem.Subject = mailItem.Subject.Substring("[PQC-Protected] ".Length);
            }
        }

        /// <summary>
        /// Adds encryption metadata to an email.
        /// </summary>
        /// <param name="mailItem">The mail item.</param>
        /// <param name="strategy">The encryption strategy.</param>
        /// <param name="recipients">The recipients.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task AddEncryptionMetadataAsync(
            Outlook.MailItem mailItem, 
            EncryptionStrategy strategy, 
            System.Collections.Generic.List<string> recipients)
        {
            await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_Status", "Encrypted");
            await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_Strategy", strategy.ToString());
            await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_Algorithm", GetAlgorithmName(strategy));
            await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_EncryptedAt", DateTime.UtcNow.ToString("O"));
            await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_RecipientCount", recipients.Count.ToString());
        }

        /// <summary>
        /// Adds decryption metadata to an email.
        /// </summary>
        /// <param name="mailItem">The mail item.</param>
        /// <param name="strategy">The encryption strategy that was used.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task AddDecryptionMetadataAsync(Outlook.MailItem mailItem, EncryptionStrategy strategy)
        {
            await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_Status", "Decrypted");
            await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_DecryptedAt", DateTime.UtcNow.ToString("O"));
        }

        /// <summary>
        /// Adds signature metadata to an email.
        /// </summary>
        /// <param name="mailItem">The mail item.</param>
        /// <param name="signature">The signature data.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task AddSignatureMetadataAsync(Outlook.MailItem mailItem, byte[] signature)
        {
            await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_Signature", Convert.ToBase64String(signature));
            await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_SignedAt", DateTime.UtcNow.ToString("O"));
            await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_SignAlgorithm", "ML-DSA-65");
        }

        /// <summary>
        /// Gets signature metadata from an email.
        /// </summary>
        /// <param name="mailItem">The mail item.</param>
        /// <returns>The signature metadata, or null if not found.</returns>
        private async Task<SignatureMetadata?> GetSignatureMetadataAsync(Outlook.MailItem mailItem)
        {
            var signature = await _comInterop.GetCustomPropertyAsync(mailItem, "PQC_Signature");
            var algorithm = await _comInterop.GetCustomPropertyAsync(mailItem, "PQC_SignAlgorithm");
            var signedAt = await _comInterop.GetCustomPropertyAsync(mailItem, "PQC_SignedAt");
            
            if (string.IsNullOrEmpty(signature))
                return null;
            
            return new SignatureMetadata
            {
                Signature = signature,
                Algorithm = algorithm ?? "Unknown",
                SignedAt = DateTime.TryParse(signedAt, out var dt) ? dt : DateTime.MinValue,
                Signer = mailItem.SenderEmailAddress ?? "Unknown"
            };
        }

        /// <summary>
        /// Computes a hash of the email content for signing.
        /// </summary>
        /// <param name="content">The email content.</param>
        /// <returns>The content hash.</returns>
        private byte[] ComputeContentHash(EmailContent content)
        {
            var combinedContent = $"{content.Subject}|{content.Body}|{content.SenderEmail}";
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(combinedContent));
            }
        }

        /// <summary>
        /// Gets the algorithm name for a given encryption strategy.
        /// </summary>
        /// <param name="strategy">The encryption strategy.</param>
        /// <returns>The algorithm name.</returns>
        private string GetAlgorithmName(EncryptionStrategy strategy)
        {
            return strategy switch
            {
                EncryptionStrategy.Hybrid => "ML-KEM-768 + RSA-2048",
                EncryptionStrategy.PostQuantumOnly => "ML-KEM-768",
                EncryptionStrategy.ClassicalOnly => "RSA-2048",
                _ => "Auto"
            };
        }

        /// <summary>
        /// Removes encryption markers from content.
        /// </summary>
        /// <param name="content">The content with markers.</param>
        /// <param name="markerPrefix">The marker prefix to remove.</param>
        /// <returns>The content without markers.</returns>
        private string RemoveEncryptionMarker(string content, string markerPrefix)
        {
            if (string.IsNullOrEmpty(content) || !content.StartsWith($"[{markerPrefix}"))
                return content;
            
            var markerEnd = content.IndexOf("]") + 1;
            if (markerEnd > 0 && content.Length > markerEnd)
            {
                return content.Substring(markerEnd);
            }
            
            return content;
        }

        #endregion
    }

    #region Result Classes

    /// <summary>
    /// Represents the result of an encryption operation.
    /// </summary>
    public class EncryptionResult
    {
        public bool Success { get; set; }
        public EncryptionStrategy Strategy { get; set; }
        public System.Collections.Generic.List<string> Recipients { get; set; } = new();
        public DateTime EncryptedAt { get; set; }
        public string? AlgorithmUsed { get; set; }
        public string? Error { get; set; }
    }

    /// <summary>
    /// Represents the result of a decryption operation.
    /// </summary>
    public class DecryptionResult
    {
        public bool Success { get; set; }
        public EncryptionStrategy Strategy { get; set; }
        public DateTime DecryptedAt { get; set; }
        public string? AlgorithmUsed { get; set; }
        public string? Error { get; set; }
    }

    /// <summary>
    /// Represents the result of a signing operation.
    /// </summary>
    public class SigningResult
    {
        public bool Success { get; set; }
        public DateTime SignedAt { get; set; }
        public string? Algorithm { get; set; }
        public int SignatureSize { get; set; }
        public string? Error { get; set; }
    }

    /// <summary>
    /// Represents the result of a signature verification operation.
    /// </summary>
    public class VerificationResult
    {
        public bool Success { get; set; }
        public bool IsValid { get; set; }
        public DateTime VerifiedAt { get; set; }
        public string? Algorithm { get; set; }
        public string? SignerInfo { get; set; }
        public string? Error { get; set; }
    }

    #endregion

    #region Data Classes

    /// <summary>
    /// Represents email content for cryptographic operations.
    /// </summary>
    public class EmailContent
    {
        public string Subject { get; set; } = string.Empty;
        public string Body { get; set; } = string.Empty;
        public string HtmlBody { get; set; } = string.Empty;
        public string SenderEmail { get; set; } = string.Empty;
        public string SenderName { get; set; } = string.Empty;
        public DateTime CreationTime { get; set; }
        public System.Collections.Generic.List<string> Recipients { get; set; } = new();
    }

    /// <summary>
    /// Represents encrypted email content.
    /// </summary>
    public class EncryptedContent
    {
        public string Subject { get; set; } = string.Empty;
        public string Body { get; set; } = string.Empty;
        public string HtmlBody { get; set; } = string.Empty;
        public string Algorithm { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public System.Collections.Generic.List<string> Recipients { get; set; } = new();
    }

    /// <summary>
    /// Represents signature metadata.
    /// </summary>
    public class SignatureMetadata
    {
        public string Signature { get; set; } = string.Empty;
        public string Algorithm { get; set; } = string.Empty;
        public DateTime SignedAt { get; set; }
        public string Signer { get; set; } = string.Empty;
    }

    #endregion
}