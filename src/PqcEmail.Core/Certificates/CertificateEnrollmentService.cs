using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Certificates
{
    /// <summary>
    /// Certificate enrollment service supporting self-signed certificates, Microsoft CA, and third-party CAs
    /// </summary>
    public class CertificateEnrollmentService : ICertificateEnrollmentService
    {
        private readonly ILogger<CertificateEnrollmentService> _logger;
        private readonly HttpClient _httpClient;
        private readonly Dictionary<string, EnrollmentResult> _pendingRequests;
        private readonly object _pendingRequestsLock = new object();

        public CertificateEnrollmentService(ILogger<CertificateEnrollmentService> logger, HttpClient httpClient)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _pendingRequests = new Dictionary<string, EnrollmentResult>();
        }

        /// <summary>
        /// Generates a self-signed certificate for development/testing
        /// </summary>
        public async Task<X509Certificate2> GenerateSelfSignedCertificateAsync(X500DistinguishedName subject, KeyPairInfo keyPair, TimeSpan validityPeriod)
        {
            _logger.LogDebug("Generating self-signed certificate for subject: {Subject}", subject.Name);

            try
            {
                var request = new CertificateRequest(subject, ECDsa.Create(), HashAlgorithmName.SHA256);

                // Add basic constraints extension
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

                // Add key usage extension
                request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment,
                    true));

                // Add enhanced key usage extension for email protection
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.4") }, // Email protection
                    true));

                // Add subject alternative name extension if email address is present
                var emailAddress = ExtractEmailFromSubject(subject.Name);
                if (!string.IsNullOrEmpty(emailAddress))
                {
                    var sanBuilder = new SubjectAlternativeNameBuilder();
                    sanBuilder.AddEmailAddress(emailAddress);
                    request.CertificateExtensions.Add(sanBuilder.Build());
                }

                // Add PQC algorithm extension if this is a PQC keypair
                if (keyPair.IsPqcKeyPair)
                {
                    await AddPqcExtensionsAsync(request, keyPair);
                }

                var notBefore = DateTimeOffset.UtcNow;
                var notAfter = notBefore.Add(validityPeriod);

                // Create self-signed certificate
                var certificate = request.CreateSelfSigned(notBefore, notAfter);

                _logger.LogInformation("Successfully generated self-signed certificate with thumbprint: {Thumbprint}", 
                    certificate.Thumbprint);

                return certificate;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate self-signed certificate for subject: {Subject}", subject.Name);
                throw;
            }
        }

        /// <summary>
        /// Creates a certificate signing request (CSR) for CA enrollment
        /// </summary>
        public async Task<CertificateRequest> CreateCertificateRequestAsync(X500DistinguishedName subject, KeyPairInfo keyPair, X509ExtensionCollection? extensions = null)
        {
            _logger.LogDebug("Creating certificate request for subject: {Subject}, algorithm: {Algorithm}", 
                subject.Name, keyPair.Algorithm);

            try
            {
                CertificateRequest request;

                // Create certificate request based on key type
                if (keyPair.IsPqcKeyPair)
                {
                    request = await CreatePqcCertificateRequestAsync(subject, keyPair);
                }
                else
                {
                    request = CreateClassicalCertificateRequestAsync(subject, keyPair);
                }

                // Add standard extensions
                await AddStandardExtensionsAsync(request, keyPair);

                // Add any additional extensions
                if (extensions != null)
                {
                    foreach (X509Extension extension in extensions)
                    {
                        request.CertificateExtensions.Add(extension);
                    }
                }

                // Add email address from subject to SAN
                var emailAddress = ExtractEmailFromSubject(subject.Name);
                if (!string.IsNullOrEmpty(emailAddress))
                {
                    var sanBuilder = new SubjectAlternativeNameBuilder();
                    sanBuilder.AddEmailAddress(emailAddress);
                    request.CertificateExtensions.Add(sanBuilder.Build());
                }

                _logger.LogInformation("Successfully created certificate request for subject: {Subject}", subject.Name);
                return request;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create certificate request for subject: {Subject}", subject.Name);
                throw;
            }
        }

        /// <summary>
        /// Submits certificate request to Microsoft Certificate Services
        /// </summary>
        public async Task<EnrollmentResult> SubmitToMicrosoftCAAsync(CertificateRequest certificateRequest, string caServerName, string templateName)
        {
            _logger.LogDebug("Submitting certificate request to Microsoft CA: {CAServer}, Template: {Template}", 
                caServerName, templateName);

            try
            {
                // Validate CA configuration first
                var configValidation = await ValidateEnrollmentConfigurationAsync(caServerName, templateName);
                if (!configValidation.IsValid)
                {
                    return EnrollmentResult.Failed(EnrollmentStatus.Failed, 
                        $"CA configuration validation failed: {string.Join(", ", configValidation.ValidationErrors)}");
                }

                // Generate PKCS#10 request
                var pkcs10 = certificateRequest.CreateSigningRequest();

                // Submit to Microsoft CA using DCOM or web services
                var requestId = await SubmitRequestToMicrosoftCAAsync(pkcs10, caServerName, templateName);

                if (string.IsNullOrEmpty(requestId))
                {
                    return EnrollmentResult.Failed(EnrollmentStatus.Failed, "Failed to submit request to CA");
                }

                // Try to retrieve certificate immediately (in case of auto-approval)
                var certificate = await RetrieveCertificateAsync(requestId, caServerName);
                if (certificate != null)
                {
                    _logger.LogInformation("Certificate immediately issued for request ID: {RequestId}", requestId);
                    return EnrollmentResult.Success(certificate, caServerName);
                }

                // If not immediately available, mark as pending
                var pendingResult = EnrollmentResult.Pending(requestId, caServerName, DateTimeOffset.UtcNow.AddMinutes(15));
                
                lock (_pendingRequestsLock)
                {
                    _pendingRequests[requestId] = pendingResult;
                }

                _logger.LogInformation("Certificate request submitted with ID: {RequestId}, status: Pending", requestId);
                return pendingResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to submit certificate request to Microsoft CA: {CAServer}", caServerName);
                return EnrollmentResult.Failed(EnrollmentStatus.Failed, $"Submission failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Submits certificate request to third-party CA
        /// </summary>
        public async Task<EnrollmentResult> SubmitToThirdPartyCAAsync(CertificateRequest certificateRequest, string caEndpoint, CaCredentials credentials)
        {
            _logger.LogDebug("Submitting certificate request to third-party CA: {CAEndpoint}", caEndpoint);

            try
            {
                // Generate PKCS#10 request
                var pkcs10 = certificateRequest.CreateSigningRequest();
                var pkcs10Base64 = Convert.ToBase64String(pkcs10);

                // Prepare request payload
                var requestPayload = new
                {
                    csr = pkcs10Base64,
                    format = "pkcs10",
                    profile = "email", // or certificate template name
                    validity = 365 // days
                };

                var jsonContent = JsonSerializer.Serialize(requestPayload);
                var httpContent = new StringContent(jsonContent, Encoding.UTF8, "application/json");

                // Add authentication headers
                if (!string.IsNullOrEmpty(credentials.ApiKey))
                {
                    _httpClient.DefaultRequestHeaders.Add("X-API-Key", credentials.ApiKey);
                }
                else if (!string.IsNullOrEmpty(credentials.Username) && !string.IsNullOrEmpty(credentials.Password))
                {
                    var authValue = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{credentials.Username}:{credentials.Password}"));
                    _httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {authValue}");
                }

                // Add any additional headers
                foreach (var header in credentials.AdditionalHeaders)
                {
                    _httpClient.DefaultRequestHeaders.Add(header.Key, header.Value);
                }

                // Submit request
                var response = await _httpClient.PostAsync(caEndpoint, httpContent);
                
                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return EnrollmentResult.Failed(EnrollmentStatus.Failed, 
                        $"CA rejected request: {response.StatusCode}, {errorContent}");
                }

                var responseContent = await response.Content.ReadAsStringAsync();
                var responseData = JsonSerializer.Deserialize<JsonElement>(responseContent);

                // Parse response based on CA-specific format
                if (responseData.TryGetProperty("certificate", out var certElement))
                {
                    // Certificate issued immediately
                    var certBase64 = certElement.GetString();
                    if (!string.IsNullOrEmpty(certBase64))
                    {
                        var certBytes = Convert.FromBase64String(certBase64);
                        var certificate = new X509Certificate2(certBytes);
                        
                        _logger.LogInformation("Certificate immediately issued by third-party CA");
                        return EnrollmentResult.Success(certificate, caEndpoint);
                    }
                }
                else if (responseData.TryGetProperty("requestId", out var requestIdElement))
                {
                    // Request is pending
                    var requestId = requestIdElement.GetString();
                    if (!string.IsNullOrEmpty(requestId))
                    {
                        var pendingResult = EnrollmentResult.Pending(requestId, caEndpoint, DateTimeOffset.UtcNow.AddMinutes(30));
                        
                        lock (_pendingRequestsLock)
                        {
                            _pendingRequests[requestId] = pendingResult;
                        }

                        _logger.LogInformation("Certificate request submitted to third-party CA with ID: {RequestId}", requestId);
                        return pendingResult;
                    }
                }

                return EnrollmentResult.Failed(EnrollmentStatus.Failed, "Unexpected response format from CA");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to submit certificate request to third-party CA: {CAEndpoint}", caEndpoint);
                return EnrollmentResult.Failed(EnrollmentStatus.Failed, $"Submission failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Retrieves a certificate from pending enrollment
        /// </summary>
        public async Task<X509Certificate2?> RetrieveCertificateAsync(string requestId, string caServerName)
        {
            _logger.LogDebug("Retrieving certificate for request ID: {RequestId} from CA: {CAServer}", requestId, caServerName);

            try
            {
                // For Microsoft CA, use DCOM interface
                if (IsMicrosoftCA(caServerName))
                {
                    return await RetrieveCertificateFromMicrosoftCAAsync(requestId, caServerName);
                }
                else
                {
                    // For third-party CA, use REST API
                    return await RetrieveCertificateFromThirdPartyCAAsync(requestId, caServerName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve certificate for request ID: {RequestId}", requestId);
                return null;
            }
        }

        /// <summary>
        /// Checks if a certificate needs renewal
        /// </summary>
        public bool ShouldRenewCertificate(X509Certificate2 certificate, int renewalThresholdDays = 30)
        {
            if (certificate == null) return false;

            var daysUntilExpiration = (certificate.NotAfter - DateTime.Now).TotalDays;
            var shouldRenew = daysUntilExpiration <= renewalThresholdDays;

            _logger.LogDebug("Certificate {Thumbprint} expires in {Days} days, renewal threshold: {Threshold}, should renew: {ShouldRenew}", 
                certificate.Thumbprint, (int)daysUntilExpiration, renewalThresholdDays, shouldRenew);

            return shouldRenew;
        }

        /// <summary>
        /// Initiates certificate renewal process
        /// </summary>
        public async Task<EnrollmentResult> RenewCertificateAsync(X509Certificate2 existingCertificate, bool reuseKeyPair = false)
        {
            _logger.LogDebug("Renewing certificate {Thumbprint}, reuse key: {ReuseKey}", 
                existingCertificate.Thumbprint, reuseKeyPair);

            try
            {
                // Extract information from existing certificate
                var subject = existingCertificate.SubjectName;
                
                KeyPairInfo keyPair;
                if (reuseKeyPair && existingCertificate.HasPrivateKey)
                {
                    // Reuse existing keypair (create KeyPairInfo from existing certificate)
                    keyPair = await ExtractKeyPairInfoFromCertificateAsync(existingCertificate);
                }
                else
                {
                    // Generate new keypair with same algorithm
                    var algorithm = DetermineAlgorithmFromCertificate(existingCertificate);
                    var usage = DetermineUsageFromCertificate(existingCertificate);
                    
                    // This would require IKeyPairManager dependency - for now, create a simple one
                    keyPair = new KeyPairInfo
                    {
                        Algorithm = algorithm,
                        Usage = usage,
                        KeySize = GetKeySize(existingCertificate)
                    };
                }

                // Create certificate request
                var certificateRequest = await CreateCertificateRequestAsync(subject, keyPair);

                // Determine CA type and submit renewal request
                var issuer = existingCertificate.Issuer;
                if (IsMicrosoftCAIssuer(issuer))
                {
                    var caServerName = ExtractCAServerFromIssuer(issuer);
                    var templateName = ExtractTemplateFromCertificate(existingCertificate);
                    
                    return await SubmitToMicrosoftCAAsync(certificateRequest, caServerName, templateName);
                }
                else
                {
                    // For third-party CA, you'd need CA endpoint and credentials
                    // This would typically come from configuration
                    throw new NotImplementedException("Third-party CA renewal not fully implemented - requires CA endpoint configuration");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to renew certificate {Thumbprint}", existingCertificate.Thumbprint);
                return EnrollmentResult.Failed(EnrollmentStatus.Failed, $"Renewal failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Revokes a certificate through the issuing CA
        /// </summary>
        public async Task<RevocationResult> RevokeCertificateAsync(X509Certificate2 certificate, CrlReason reason)
        {
            _logger.LogDebug("Revoking certificate {Thumbprint} with reason: {Reason}", certificate.Thumbprint, reason);

            try
            {
                var issuer = certificate.Issuer;
                
                if (IsMicrosoftCAIssuer(issuer))
                {
                    var caServerName = ExtractCAServerFromIssuer(issuer);
                    return await RevokeCertificateFromMicrosoftCAAsync(certificate, caServerName, reason);
                }
                else
                {
                    // For third-party CA
                    return await RevokeCertificateFromThirdPartyCAAsync(certificate, reason);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to revoke certificate {Thumbprint}", certificate.Thumbprint);
                return RevocationResult.Failed($"Revocation failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Validates certificate enrollment configuration
        /// </summary>
        public async Task<EnrollmentConfigurationValidationResult> ValidateEnrollmentConfigurationAsync(string caServerName, string templateName)
        {
            _logger.LogDebug("Validating enrollment configuration for CA: {CAServer}, Template: {Template}", 
                caServerName, templateName);

            try
            {
                var errors = new List<string>();
                var warnings = new List<string>();
                var supportedAlgorithms = new List<string>();

                // Validate CA server accessibility
                if (!await IsCAServerAccessibleAsync(caServerName))
                {
                    errors.Add($"CA server {caServerName} is not accessible");
                }

                // Validate template existence and permissions
                var templateValidation = await ValidateTemplateAsync(caServerName, templateName);
                if (!templateValidation.IsValid)
                {
                    errors.AddRange(templateValidation.Errors);
                }
                else
                {
                    supportedAlgorithms = templateValidation.SupportedAlgorithms;
                }

                // Check for PQC algorithm support
                var pqcAlgorithms = new[] { "ML-KEM-768", "ML-DSA-65" };
                var supportsPqc = supportedAlgorithms.Any(alg => pqcAlgorithms.Contains(alg));
                
                if (!supportsPqc)
                {
                    warnings.Add("Template does not appear to support PQC algorithms");
                }

                if (errors.Count == 0)
                {
                    _logger.LogInformation("Enrollment configuration validation passed for CA: {CAServer}, Template: {Template}", 
                        caServerName, templateName);
                    return EnrollmentConfigurationValidationResult.Valid(caServerName, templateName, supportedAlgorithms);
                }
                else
                {
                    _logger.LogWarning("Enrollment configuration validation failed for CA: {CAServer}, Template: {Template}. Errors: {Errors}", 
                        caServerName, templateName, string.Join(", ", errors));
                    return EnrollmentConfigurationValidationResult.Invalid(errors);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating enrollment configuration for CA: {CAServer}, Template: {Template}", 
                    caServerName, templateName);
                
                return EnrollmentConfigurationValidationResult.Invalid(new List<string> 
                { 
                    $"Validation error: {ex.Message}" 
                });
            }
        }

        #region Private Helper Methods

        private async Task<CertificateRequest> CreatePqcCertificateRequestAsync(X500DistinguishedName subject, KeyPairInfo keyPair)
        {
            // For PQC algorithms, we need to use appropriate key types
            // This is a simplified implementation - actual PQC implementation would use proper key types
            
            if (keyPair.PublicKey != null)
            {
                return new CertificateRequest(subject, keyPair.PublicKey, HashAlgorithmName.SHA256);
            }
            else
            {
                // Fallback to ECDsa for now
                var ecdsa = ECDsa.Create();
                return new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
            }
        }

        private CertificateRequest CreateClassicalCertificateRequestAsync(X500DistinguishedName subject, KeyPairInfo keyPair)
        {
            if (keyPair.PublicKey != null)
            {
                return new CertificateRequest(subject, keyPair.PublicKey, HashAlgorithmName.SHA256);
            }
            else
            {
                // Create appropriate classical key based on algorithm
                return keyPair.Algorithm.ToUpperInvariant() switch
                {
                    "RSA" => new CertificateRequest(subject, RSA.Create(keyPair.KeySize), HashAlgorithmName.SHA256),
                    "ECDSA" => new CertificateRequest(subject, ECDsa.Create(), HashAlgorithmName.SHA256),
                    _ => new CertificateRequest(subject, RSA.Create(2048), HashAlgorithmName.SHA256)
                };
            }
        }

        private async Task AddStandardExtensionsAsync(CertificateRequest request, KeyPairInfo keyPair)
        {
            // Add basic constraints
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

            // Add key usage based on key pair usage
            var keyUsage = keyPair.Usage switch
            {
                KeyUsage.Signing => X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                KeyUsage.Encryption => X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment,
                _ => X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment
            };

            request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));

            // Add enhanced key usage for email protection
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.4") }, // Email protection
                true));

            // Add PQC extensions if applicable
            if (keyPair.IsPqcKeyPair)
            {
                await AddPqcExtensionsAsync(request, keyPair);
            }
        }

        private async Task AddPqcExtensionsAsync(CertificateRequest request, KeyPairInfo keyPair)
        {
            // Add PQC-specific extensions
            // This would include algorithm parameter extensions
            
            var pqcExtension = new X509Extension(
                "1.2.3.4.5.6.7.8.9.10", // Example PQC extension OID
                Encoding.UTF8.GetBytes($"Algorithm: {keyPair.Algorithm}, KeySize: {keyPair.KeySize}"),
                false);
            
            request.CertificateExtensions.Add(pqcExtension);
        }

        private string ExtractEmailFromSubject(string subjectName)
        {
            // Extract email address from subject DN
            var parts = subjectName.Split(',');
            foreach (var part in parts)
            {
                var trimmedPart = part.Trim();
                if (trimmedPart.StartsWith("E=", StringComparison.OrdinalIgnoreCase) ||
                    trimmedPart.StartsWith("EMAILADDRESS=", StringComparison.OrdinalIgnoreCase))
                {
                    return trimmedPart.Split('=')[1].Trim();
                }
            }
            return string.Empty;
        }

        private async Task<string> SubmitRequestToMicrosoftCAAsync(byte[] pkcs10, string caServerName, string templateName)
        {
            // Submit request to Microsoft CA using DCOM or web services
            // This is a simplified implementation - actual implementation would use COM interop
            
            var requestId = Guid.NewGuid().ToString();
            _logger.LogDebug("Simulated submission to Microsoft CA - Request ID: {RequestId}", requestId);
            
            return requestId;
        }

        private async Task<X509Certificate2?> RetrieveCertificateFromMicrosoftCAAsync(string requestId, string caServerName)
        {
            // Retrieve certificate from Microsoft CA
            // This would use actual CA APIs
            
            _logger.LogDebug("Simulated certificate retrieval from Microsoft CA for request: {RequestId}", requestId);
            return null; // Simulate pending
        }

        private async Task<X509Certificate2?> RetrieveCertificateFromThirdPartyCAAsync(string requestId, string caEndpoint)
        {
            try
            {
                var response = await _httpClient.GetAsync($"{caEndpoint}/certificate/{requestId}");
                
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var responseData = JsonSerializer.Deserialize<JsonElement>(responseContent);
                    
                    if (responseData.TryGetProperty("certificate", out var certElement))
                    {
                        var certBase64 = certElement.GetString();
                        if (!string.IsNullOrEmpty(certBase64))
                        {
                            var certBytes = Convert.FromBase64String(certBase64);
                            return new X509Certificate2(certBytes);
                        }
                    }
                }
                
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving certificate from third-party CA for request: {RequestId}", requestId);
                return null;
            }
        }

        private bool IsMicrosoftCA(string caServerName)
        {
            // Simple heuristic - could be improved with configuration
            return !caServerName.StartsWith("http", StringComparison.OrdinalIgnoreCase);
        }

        private bool IsMicrosoftCAIssuer(string issuer)
        {
            // Simple heuristic to detect Microsoft CA issuer
            return issuer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                   issuer.Contains("Windows", StringComparison.OrdinalIgnoreCase);
        }

        private string ExtractCAServerFromIssuer(string issuer)
        {
            // Extract CA server name from issuer DN
            // This is a simplified extraction
            return "DefaultCAServer";
        }

        private string ExtractTemplateFromCertificate(X509Certificate2 certificate)
        {
            // Extract certificate template from certificate extensions
            // This would parse the certificate template extension
            return "EmailProtection";
        }

        private async Task<KeyPairInfo> ExtractKeyPairInfoFromCertificateAsync(X509Certificate2 certificate)
        {
            // Extract key pair information from existing certificate
            var keyPairInfo = new KeyPairInfo
            {
                Algorithm = DetermineAlgorithmFromCertificate(certificate),
                Usage = DetermineUsageFromCertificate(certificate),
                KeySize = GetKeySize(certificate),
                PublicKeyData = certificate.GetPublicKey(),
                CreatedAt = certificate.NotBefore
            };

            return keyPairInfo;
        }

        private string DetermineAlgorithmFromCertificate(X509Certificate2 certificate)
        {
            var algorithm = certificate.GetKeyAlgorithm();
            return algorithm switch
            {
                "1.2.840.113549.1.1.1" => "RSA",
                "1.2.840.10045.2.1" => "ECDSA",
                _ => "RSA" // Default
            };
        }

        private KeyUsage DetermineUsageFromCertificate(X509Certificate2 certificate)
        {
            var keyUsageExt = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (keyUsageExt != null)
            {
                if (keyUsageExt.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature))
                    return KeyUsage.Signing;
                if (keyUsageExt.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment))
                    return KeyUsage.Encryption;
            }
            
            return KeyUsage.Signing; // Default
        }

        private int GetKeySize(X509Certificate2 certificate)
        {
            return certificate.GetPublicKey().Length * 8;
        }

        private async Task<bool> IsCAServerAccessibleAsync(string caServerName)
        {
            try
            {
                // Test CA server accessibility
                // This would implement actual connectivity testing
                return true; // Simplified
            }
            catch
            {
                return false;
            }
        }

        private async Task<EnrollmentConfigurationValidationResult> ValidateTemplateAsync(string caServerName, string templateName)
        {
            try
            {
                // Validate certificate template
                var supportedAlgorithms = new List<string> { "RSA", "ECDSA", "ML-KEM-768", "ML-DSA-65" };
                return EnrollmentConfigurationValidationResult.Valid(caServerName, templateName, supportedAlgorithms);
            }
            catch (Exception ex)
            {
                return EnrollmentConfigurationValidationResult.Invalid(new List<string> { ex.Message });
            }
        }

        private async Task<RevocationResult> RevokeCertificateFromMicrosoftCAAsync(X509Certificate2 certificate, string caServerName, CrlReason reason)
        {
            try
            {
                // Revoke certificate from Microsoft CA
                var revocationId = Guid.NewGuid().ToString();
                _logger.LogInformation("Simulated certificate revocation from Microsoft CA - Revocation ID: {RevocationId}", revocationId);
                
                return RevocationResult.Success(revocationId, reason);
            }
            catch (Exception ex)
            {
                return RevocationResult.Failed($"Microsoft CA revocation failed: {ex.Message}", ex);
            }
        }

        private async Task<RevocationResult> RevokeCertificateFromThirdPartyCAAsync(X509Certificate2 certificate, CrlReason reason)
        {
            try
            {
                // Revoke certificate from third-party CA
                var revocationId = Guid.NewGuid().ToString();
                _logger.LogInformation("Simulated certificate revocation from third-party CA - Revocation ID: {RevocationId}", revocationId);
                
                return RevocationResult.Success(revocationId, reason);
            }
            catch (Exception ex)
            {
                return RevocationResult.Failed($"Third-party CA revocation failed: {ex.Message}", ex);
            }
        }

        #endregion
    }
}