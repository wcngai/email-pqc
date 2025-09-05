using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Discovery
{
    /// <summary>
    /// Active Directory integration for discovering internal recipient capabilities
    /// </summary>
    public class ActiveDirectoryCapabilityProvider : IActiveDirectoryCapabilityProvider, IDisposable
    {
        private readonly CapabilityDiscoveryConfiguration _configuration;
        private readonly string? _domainController;
        private readonly string? _searchBase;
        private bool _disposed = false;

        public ActiveDirectoryCapabilityProvider(CapabilityDiscoveryConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _domainController = configuration.ActiveDirectoryServer;
            
            try
            {
                // Get the current domain's distinguished name as search base
                var domain = Domain.GetCurrentDomain();
                _searchBase = $"DC={string.Join(",DC=", domain.Name.Split('.'))}";
            }
            catch (ActiveDirectoryObjectNotFoundException)
            {
                // Not in a domain environment, will need explicit configuration
                _searchBase = null;
            }
            catch (Exception)
            {
                // Other AD errors, continue without domain detection
                _searchBase = null;
            }
        }

        /// <summary>
        /// Queries Active Directory for recipient capabilities
        /// </summary>
        public async Task<RecipientCapabilities?> QueryCapabilitiesAsync(string emailAddress, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                throw new ArgumentException("Email address cannot be null or empty", nameof(emailAddress));

            if (string.IsNullOrEmpty(_searchBase))
            {
                // Cannot query AD without proper configuration
                return null;
            }

            try
            {
                return await Task.Run(() => QueryCapabilitiesFromAD(emailAddress), cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                // If AD query fails, return null rather than throwing
                return null;
            }
        }

        /// <summary>
        /// Checks if an email address is internal (in the organization)
        /// </summary>
        public async Task<bool> IsInternalRecipientAsync(string emailAddress, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                return false;

            if (string.IsNullOrEmpty(_searchBase))
                return false;

            try
            {
                return await Task.Run(() => CheckInternalRecipient(emailAddress), cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                // If AD query fails, assume external
                return false;
            }
        }

        /// <summary>
        /// Gets certificate information from Active Directory for a user
        /// </summary>
        public async Task<CertificateInfo?> GetUserCertificateAsync(string emailAddress, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                return null;

            if (string.IsNullOrEmpty(_searchBase))
                return null;

            try
            {
                return await Task.Run(() => GetUserCertificateFromAD(emailAddress), cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                // If AD query fails, return null
                return null;
            }
        }

        private RecipientCapabilities? QueryCapabilitiesFromAD(string emailAddress)
        {
            using var searcher = CreateDirectorySearcher();
            if (searcher == null)
                return null;

            // Search for user by email address
            searcher.Filter = $"(&(objectClass=user)(mail={EscapeLdapString(emailAddress)}))";
            searcher.PropertiesToLoad.AddRange(new[]
            {
                "mail", "userCertificate", "userSMIMECertificate", 
                "distinguishedName", "displayName", "department"
            });

            using var result = searcher.FindOne();
            if (result == null)
                return null;

            var capabilities = new RecipientCapabilities
            {
                EmailAddress = emailAddress,
                Source = CapabilitySource.ActiveDirectory,
                DiscoveredAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.Add(_configuration.DefaultCacheTtl),
                ConfidenceLevel = 0.8 // High confidence for internal users
            };

            // Extract certificate information to determine capabilities
            var certificates = ExtractCertificatesFromResult(result);
            if (certificates.Any())
            {
                AnalyzeCertificateCapabilities(certificates, capabilities);
            }
            else
            {
                // No certificates found, assume basic capabilities
                SetDefaultInternalCapabilities(capabilities);
            }

            // Add AD-specific metadata
            capabilities.Metadata["ad_dn"] = result.Properties["distinguishedName"][0]?.ToString() ?? "";
            capabilities.Metadata["ad_department"] = result.Properties["department"][0]?.ToString() ?? "";

            return capabilities;
        }

        private bool CheckInternalRecipient(string emailAddress)
        {
            using var searcher = CreateDirectorySearcher();
            if (searcher == null)
                return false;

            searcher.Filter = $"(&(objectClass=user)(mail={EscapeLdapString(emailAddress)}))";
            searcher.PropertiesToLoad.Add("mail");

            using var result = searcher.FindOne();
            return result != null;
        }

        private CertificateInfo? GetUserCertificateFromAD(string emailAddress)
        {
            using var searcher = CreateDirectorySearcher();
            if (searcher == null)
                return null;

            searcher.Filter = $"(&(objectClass=user)(mail={EscapeLdapString(emailAddress)}))";
            searcher.PropertiesToLoad.AddRange(new[] { "userCertificate", "userSMIMECertificate" });

            using var result = searcher.FindOne();
            if (result == null)
                return null;

            var certificates = ExtractCertificatesFromResult(result);
            var primaryCert = certificates.FirstOrDefault();
            
            if (primaryCert == null)
                return null;

            return CreateCertificateInfo(primaryCert, emailAddress);
        }

        private DirectorySearcher? CreateDirectorySearcher()
        {
            try
            {
                DirectoryEntry rootEntry;

                if (!string.IsNullOrEmpty(_domainController))
                {
                    // Use specified domain controller
                    var ldapPath = $"LDAP://{_domainController}/{_searchBase}";
                    rootEntry = new DirectoryEntry(ldapPath);
                }
                else if (!string.IsNullOrEmpty(_searchBase))
                {
                    // Use default domain controller
                    var ldapPath = $"LDAP://{_searchBase}";
                    rootEntry = new DirectoryEntry(ldapPath);
                }
                else
                {
                    return null;
                }

                var searcher = new DirectorySearcher(rootEntry)
                {
                    SearchScope = SearchScope.Subtree,
                    PageSize = 1000,
                    ServerTimeLimit = _configuration.ActiveDirectoryTimeout
                };

                return searcher;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private List<X509Certificate2> ExtractCertificatesFromResult(SearchResult result)
        {
            var certificates = new List<X509Certificate2>();

            // Check both userCertificate and userSMIMECertificate attributes
            var certAttributes = new[] { "userCertificate", "userSMIMECertificate" };

            foreach (var attribute in certAttributes)
            {
                if (result.Properties[attribute].Count > 0)
                {
                    foreach (byte[] certBytes in result.Properties[attribute])
                    {
                        try
                        {
                            var cert = new X509Certificate2(certBytes);
                            certificates.Add(cert);
                        }
                        catch (Exception)
                        {
                            // Skip invalid certificates
                            continue;
                        }
                    }
                }
            }

            return certificates;
        }

        private void AnalyzeCertificateCapabilities(List<X509Certificate2> certificates, RecipientCapabilities capabilities)
        {
            var hasClassical = false;
            var hasPqc = false;

            foreach (var cert in certificates)
            {
                try
                {
                    // Analyze the certificate's public key algorithm
                    var publicKeyAlgorithm = cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value ?? "";

                    if (IsClassicalAlgorithm(publicKeyAlgorithm))
                    {
                        hasClassical = true;
                        AddClassicalCapabilities(capabilities, publicKeyAlgorithm);
                    }
                    else if (IsPqcAlgorithm(publicKeyAlgorithm))
                    {
                        hasPqc = true;
                        AddPqcCapabilities(capabilities, publicKeyAlgorithm);
                    }
                }
                catch (Exception)
                {
                    // Skip certificate analysis errors
                    continue;
                }
            }

            // Determine supported modes based on certificates found
            if (hasPqc && hasClassical)
            {
                capabilities.SupportedModes.Add(CryptographicMode.Hybrid);
                capabilities.SupportedModes.Add(CryptographicMode.PostQuantumOnly);
                capabilities.SupportedModes.Add(CryptographicMode.ClassicalOnly);
            }
            else if (hasPqc)
            {
                capabilities.SupportedModes.Add(CryptographicMode.PostQuantumOnly);
            }
            else if (hasClassical)
            {
                capabilities.SupportedModes.Add(CryptographicMode.ClassicalOnly);
                capabilities.SupportedModes.Add(CryptographicMode.Hybrid); // Assume can receive hybrid
            }
            else
            {
                SetDefaultInternalCapabilities(capabilities);
            }
        }

        private void SetDefaultInternalCapabilities(RecipientCapabilities capabilities)
        {
            // Default capabilities for internal users without certificates
            capabilities.SupportedModes.AddRange(new[]
            {
                CryptographicMode.Hybrid,
                CryptographicMode.ClassicalOnly
            });

            capabilities.SupportedKemAlgorithms.AddRange(new[]
            {
                "ML-KEM-768",
                "RSA-OAEP-2048"
            });

            capabilities.SupportedSignatureAlgorithms.AddRange(new[]
            {
                "ML-DSA-65",
                "RSA-PSS-2048"
            });

            capabilities.SupportedClassicalAlgorithms.AddRange(new[]
            {
                "RSA-OAEP-2048",
                "RSA-PSS-2048"
            });

            capabilities.ConfidenceLevel = 0.6; // Medium confidence for assumptions
        }

        private bool IsClassicalAlgorithm(string algorithmName)
        {
            var classicalAlgorithms = new[] { "RSA", "ECDSA", "ECDH", "DH" };
            return classicalAlgorithms.Any(alg => algorithmName.Contains(alg, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsPqcAlgorithm(string algorithmName)
        {
            var pqcAlgorithms = new[] { "ML-KEM", "ML-DSA", "Kyber", "Dilithium", "CRYSTALS" };
            return pqcAlgorithms.Any(alg => algorithmName.Contains(alg, StringComparison.OrdinalIgnoreCase));
        }

        private void AddClassicalCapabilities(RecipientCapabilities capabilities, string algorithmName)
        {
            if (algorithmName.Contains("RSA", StringComparison.OrdinalIgnoreCase))
            {
                capabilities.SupportedClassicalAlgorithms.Add("RSA-OAEP-2048");
                capabilities.SupportedClassicalAlgorithms.Add("RSA-PSS-2048");
            }
            else if (algorithmName.Contains("ECDSA", StringComparison.OrdinalIgnoreCase))
            {
                capabilities.SupportedClassicalAlgorithms.Add("ECDSA-P256");
                capabilities.SupportedClassicalAlgorithms.Add("ECDH-P256");
            }
        }

        private void AddPqcCapabilities(RecipientCapabilities capabilities, string algorithmName)
        {
            if (algorithmName.Contains("ML-KEM", StringComparison.OrdinalIgnoreCase) ||
                algorithmName.Contains("Kyber", StringComparison.OrdinalIgnoreCase))
            {
                capabilities.SupportedKemAlgorithms.Add("ML-KEM-768");
                capabilities.SupportedKemAlgorithms.Add("ML-KEM-1024");
            }

            if (algorithmName.Contains("ML-DSA", StringComparison.OrdinalIgnoreCase) ||
                algorithmName.Contains("Dilithium", StringComparison.OrdinalIgnoreCase))
            {
                capabilities.SupportedSignatureAlgorithms.Add("ML-DSA-65");
                capabilities.SupportedSignatureAlgorithms.Add("ML-DSA-87");
            }
        }

        private CertificateInfo CreateCertificateInfo(X509Certificate2 certificate, string emailAddress)
        {
            var certInfo = new CertificateInfo
            {
                Certificate = certificate,
                StoreLocation = StoreLocation.CurrentUser, // Default for AD certificates
                StoreName = StoreName.AddressBook, // Common for email certificates
                KeyUsage = X509KeyUsageFlags.None, // Would be extracted from certificate
                EmailAddresses = new List<string> { emailAddress },
                LastUpdated = DateTimeOffset.UtcNow
            };

            // Analyze if it's a PQC certificate
            var publicKeyAlgorithm = certificate.PublicKey.Oid.FriendlyName ?? certificate.PublicKey.Oid.Value ?? "";
            if (IsPqcAlgorithm(publicKeyAlgorithm))
            {
                certInfo.IsPqcCertificate = true;
                certInfo.PqcAlgorithm = new PqcAlgorithmInfo
                {
                    AlgorithmName = publicKeyAlgorithm,
                    ObjectIdentifier = certificate.PublicKey.Oid.Value ?? "",
                    KeySize = certificate.PublicKey.Key?.KeySize ?? 0
                };
            }
            else
            {
                certInfo.ClassicalAlgorithm = new ClassicalAlgorithmInfo
                {
                    AlgorithmName = publicKeyAlgorithm,
                    ObjectIdentifier = certificate.PublicKey.Oid.Value ?? "",
                    KeySize = certificate.PublicKey.Key?.KeySize ?? 0
                };
            }

            return certInfo;
        }

        private string EscapeLdapString(string input)
        {
            // Basic LDAP string escaping
            return input.Replace("\\", "\\5c")
                       .Replace("*", "\\2a")
                       .Replace("(", "\\28")
                       .Replace(")", "\\29")
                       .Replace("\0", "\\00");
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
            }
        }
    }
}