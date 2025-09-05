using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Policies.Sources
{
    /// <summary>
    /// Provides policy configuration from Windows Registry (Group Policy).
    /// Registry path: HKLM\SOFTWARE\Policies\PqcEmail
    /// </summary>
    public class WindowsRegistryPolicyProvider : IPolicySourceProvider, IDisposable
    {
        private readonly ILogger<WindowsRegistryPolicyProvider> _logger;
        private readonly string _registryPath;
        private bool _disposed;

        /// <summary>
        /// Gets the policy source type.
        /// </summary>
        public PolicySource SourceType => PolicySource.GroupPolicy;

        /// <summary>
        /// Gets the priority of this policy source (Group Policy has high priority).
        /// </summary>
        public int Priority => 800;

        /// <summary>
        /// Event raised when the policy source is updated.
        /// </summary>
        public event EventHandler<PolicySourceUpdatedEventArgs>? PolicySourceUpdated;

        /// <summary>
        /// Initializes a new instance of the <see cref="WindowsRegistryPolicyProvider"/> class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="registryPath">The registry path to monitor (optional, defaults to standard Group Policy path)</param>
        public WindowsRegistryPolicyProvider(
            ILogger<WindowsRegistryPolicyProvider> logger, 
            string? registryPath = null)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _registryPath = registryPath ?? @"SOFTWARE\Policies\PqcEmail";
        }

        /// <summary>
        /// Gets the policy configuration from the Windows Registry.
        /// </summary>
        /// <returns>The policy configuration or null if not available</returns>
        public async Task<PqcEmailPolicy?> GetPolicyAsync()
        {
            try
            {
                _logger.LogDebug("Reading policy configuration from registry path: {RegistryPath}", _registryPath);

                using var baseKey = Registry.LocalMachine.OpenSubKey(_registryPath, false);
                if (baseKey == null)
                {
                    _logger.LogDebug("Registry path not found, no Group Policy configuration available");
                    return null;
                }

                var policy = new PqcEmailPolicy
                {
                    Source = PolicySource.GroupPolicy,
                    LastUpdated = DateTime.UtcNow,
                    Version = "1.0"
                };

                // Read cryptographic settings
                await ReadCryptographicSettings(policy, baseKey);

                // Read security settings
                await ReadSecuritySettings(policy, baseKey);

                // Read domain settings
                await ReadDomainSettings(policy, baseKey);

                // Read inheritance settings
                await ReadInheritanceSettings(policy, baseKey);

                // Read fallback settings
                await ReadFallbackSettings(policy, baseKey);

                // Read audit settings
                await ReadAuditSettings(policy, baseKey);

                // Read performance settings
                await ReadPerformanceSettings(policy, baseKey);

                // Read certificate settings
                await ReadCertificateSettings(policy, baseKey);

                _logger.LogInformation("Successfully loaded Group Policy configuration from registry");
                return policy;
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogError(ex, "Access denied reading Group Policy configuration from registry");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to read Group Policy configuration from registry");
                return null;
            }
        }

        /// <summary>
        /// Checks if this policy source is available and accessible.
        /// </summary>
        /// <returns>True if the source is available</returns>
        public async Task<bool> IsAvailableAsync()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(_registryPath, false);
                var isAvailable = key != null;
                
                _logger.LogDebug("Registry policy source availability: {IsAvailable}", isAvailable);
                return await Task.FromResult(isAvailable);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Registry policy source is not available");
                return await Task.FromResult(false);
            }
        }

        #region Registry Reading Methods

        /// <summary>
        /// Reads cryptographic settings from the registry.
        /// </summary>
        /// <param name="policy">The policy to populate</param>
        /// <param name="baseKey">The base registry key</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task ReadCryptographicSettings(PqcEmailPolicy policy, RegistryKey baseKey)
        {
            using var cryptoKey = baseKey.OpenSubKey("Cryptographic");
            if (cryptoKey == null) return;

            var globalPolicy = policy.GlobalCryptographic;

            // Read global mode
            var modeValue = cryptoKey.GetValue("GlobalMode") as string;
            if (Enum.TryParse<CryptographicMode>(modeValue, out var mode))
            {
                globalPolicy.Mode = mode;
            }

            // Read preferred algorithms
            globalPolicy.PreferredKemAlgorithm = 
                cryptoKey.GetValue("PreferredKemAlgorithm") as string ?? globalPolicy.PreferredKemAlgorithm;
            globalPolicy.PreferredSignatureAlgorithm = 
                cryptoKey.GetValue("PreferredSignatureAlgorithm") as string ?? globalPolicy.PreferredSignatureAlgorithm;
            globalPolicy.FallbackKemAlgorithm = 
                cryptoKey.GetValue("FallbackKemAlgorithm") as string ?? globalPolicy.FallbackKemAlgorithm;
            globalPolicy.FallbackSignatureAlgorithm = 
                cryptoKey.GetValue("FallbackSignatureAlgorithm") as string ?? globalPolicy.FallbackSignatureAlgorithm;

            _logger.LogDebug("Read cryptographic settings: Mode={Mode}, PreferredKEM={KEM}", 
                globalPolicy.Mode, globalPolicy.PreferredKemAlgorithm);

            await Task.CompletedTask;
        }

        /// <summary>
        /// Reads security settings from the registry.
        /// </summary>
        /// <param name="policy">The policy to populate</param>
        /// <param name="baseKey">The base registry key</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task ReadSecuritySettings(PqcEmailPolicy policy, RegistryKey baseKey)
        {
            using var securityKey = baseKey.OpenSubKey("Security");
            if (securityKey == null) return;

            var securityPolicy = policy.Security;

            // Read minimum RSA key size
            if (securityKey.GetValue("MinimumRsaKeySize") is int minRsaKeySize)
            {
                securityPolicy.MinimumRsaKeySize = minRsaKeySize;
            }

            // Read boolean flags
            securityPolicy.ProhibitWeakAlgorithms = 
                ConvertToBoolean(securityKey.GetValue("ProhibitWeakAlgorithms"), securityPolicy.ProhibitWeakAlgorithms);
            securityPolicy.RequireHardwareProtection = 
                ConvertToBoolean(securityKey.GetValue("RequireHardwareProtection"), securityPolicy.RequireHardwareProtection);

            _logger.LogDebug("Read security settings: MinRSAKeySize={MinKeySize}, ProhibitWeak={ProhibitWeak}", 
                securityPolicy.MinimumRsaKeySize, securityPolicy.ProhibitWeakAlgorithms);

            await Task.CompletedTask;
        }

        /// <summary>
        /// Reads domain settings from the registry.
        /// </summary>
        /// <param name="policy">The policy to populate</param>
        /// <param name="baseKey">The base registry key</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task ReadDomainSettings(PqcEmailPolicy policy, RegistryKey baseKey)
        {
            using var domainKey = baseKey.OpenSubKey("Domains");
            if (domainKey == null) return;

            var domainPolicy = policy.Domain;

            // Read domain lists
            domainPolicy.ForcePqcDomains = ReadDomainRuleList(domainKey, "ForcePqcDomains");
            domainPolicy.ProhibitUnencryptedDomains = ReadDomainRuleList(domainKey, "ProhibitUnencryptedDomains");
            domainPolicy.AllowClassicalOnlyDomains = ReadDomainRuleList(domainKey, "AllowClassicalOnlyDomains");

            _logger.LogDebug("Read domain settings: ForcePQC={ForcePqcCount}, ProhibitUnencrypted={ProhibitUnencryptedCount}, AllowClassical={AllowClassicalCount}", 
                domainPolicy.ForcePqcDomains.Count, 
                domainPolicy.ProhibitUnencryptedDomains.Count,
                domainPolicy.AllowClassicalOnlyDomains.Count);

            await Task.CompletedTask;
        }

        /// <summary>
        /// Reads inheritance settings from the registry.
        /// </summary>
        /// <param name="policy">The policy to populate</param>
        /// <param name="baseKey">The base registry key</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task ReadInheritanceSettings(PqcEmailPolicy policy, RegistryKey baseKey)
        {
            using var inheritanceKey = baseKey.OpenSubKey("Inheritance");
            if (inheritanceKey == null) return;

            var inheritancePolicy = policy.Inheritance;

            inheritancePolicy.AllowUserOverrides = 
                ConvertToBoolean(inheritanceKey.GetValue("AllowUserOverrides"), inheritancePolicy.AllowUserOverrides);
            inheritancePolicy.AllowDomainOverrides = 
                ConvertToBoolean(inheritanceKey.GetValue("AllowDomainOverrides"), inheritancePolicy.AllowDomainOverrides);

            var overrideModeValue = inheritanceKey.GetValue("OverrideMode") as string;
            if (Enum.TryParse<OverrideMode>(overrideModeValue, out var overrideMode))
            {
                inheritancePolicy.OverrideMode = overrideMode;
            }

            _logger.LogDebug("Read inheritance settings: AllowUserOverrides={AllowUser}, AllowDomainOverrides={AllowDomain}, OverrideMode={OverrideMode}", 
                inheritancePolicy.AllowUserOverrides, inheritancePolicy.AllowDomainOverrides, inheritancePolicy.OverrideMode);

            await Task.CompletedTask;
        }

        /// <summary>
        /// Reads fallback settings from the registry.
        /// </summary>
        /// <param name="policy">The policy to populate</param>
        /// <param name="baseKey">The base registry key</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task ReadFallbackSettings(PqcEmailPolicy policy, RegistryKey baseKey)
        {
            using var fallbackKey = baseKey.OpenSubKey("Fallback");
            if (fallbackKey == null) return;

            var fallbackPolicy = policy.Fallback;

            fallbackPolicy.AllowUnencryptedFallback = 
                ConvertToBoolean(fallbackKey.GetValue("AllowUnencryptedFallback"), fallbackPolicy.AllowUnencryptedFallback);

            if (fallbackKey.GetValue("MaxFallbackAttempts") is int maxAttempts)
            {
                fallbackPolicy.MaxFallbackAttempts = maxAttempts;
            }

            if (fallbackKey.GetValue("FallbackTimeoutSeconds") is int timeoutSeconds)
            {
                fallbackPolicy.FallbackTimeoutSeconds = timeoutSeconds;
            }

            _logger.LogDebug("Read fallback settings: AllowUnencrypted={AllowUnencrypted}, MaxAttempts={MaxAttempts}, Timeout={Timeout}s", 
                fallbackPolicy.AllowUnencryptedFallback, fallbackPolicy.MaxFallbackAttempts, fallbackPolicy.FallbackTimeoutSeconds);

            await Task.CompletedTask;
        }

        /// <summary>
        /// Reads audit settings from the registry.
        /// </summary>
        /// <param name="policy">The policy to populate</param>
        /// <param name="baseKey">The base registry key</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task ReadAuditSettings(PqcEmailPolicy policy, RegistryKey baseKey)
        {
            using var auditKey = baseKey.OpenSubKey("Audit");
            if (auditKey == null) return;

            var auditPolicy = policy.Audit;

            auditPolicy.EnableDetailedLogging = 
                ConvertToBoolean(auditKey.GetValue("EnableDetailedLogging"), auditPolicy.EnableDetailedLogging);
            auditPolicy.LogPolicyDecisions = 
                ConvertToBoolean(auditKey.GetValue("LogPolicyDecisions"), auditPolicy.LogPolicyDecisions);
            auditPolicy.LogFallbackEvents = 
                ConvertToBoolean(auditKey.GetValue("LogFallbackEvents"), auditPolicy.LogFallbackEvents);
            auditPolicy.LogSecurityViolations = 
                ConvertToBoolean(auditKey.GetValue("LogSecurityViolations"), auditPolicy.LogSecurityViolations);

            auditPolicy.CustomLogPath = auditKey.GetValue("CustomLogPath") as string;

            var logLevelValue = auditKey.GetValue("LogLevel") as string;
            if (Enum.TryParse<LogLevel>(logLevelValue, out var logLevel))
            {
                auditPolicy.LogLevel = logLevel;
            }

            _logger.LogDebug("Read audit settings: DetailedLogging={DetailedLogging}, LogLevel={LogLevel}", 
                auditPolicy.EnableDetailedLogging, auditPolicy.LogLevel);

            await Task.CompletedTask;
        }

        /// <summary>
        /// Reads performance settings from the registry.
        /// </summary>
        /// <param name="policy">The policy to populate</param>
        /// <param name="baseKey">The base registry key</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task ReadPerformanceSettings(PqcEmailPolicy policy, RegistryKey baseKey)
        {
            using var perfKey = baseKey.OpenSubKey("Performance");
            if (perfKey == null) return;

            var perfPolicy = policy.Performance;

            if (perfKey.GetValue("MaxOperationTimeMs") is int maxOpTimeMs)
            {
                perfPolicy.MaxOperationTimeMs = maxOpTimeMs;
            }

            if (perfKey.GetValue("MaxMemoryUsageMB") is int maxMemoryMB)
            {
                perfPolicy.MaxMemoryUsageMB = maxMemoryMB;
            }

            if (perfKey.GetValue("CacheExpiryMinutes") is int cacheExpiryMin)
            {
                perfPolicy.CacheExpiryMinutes = cacheExpiryMin;
            }

            perfPolicy.EnablePerformanceMonitoring = 
                ConvertToBoolean(perfKey.GetValue("EnablePerformanceMonitoring"), perfPolicy.EnablePerformanceMonitoring);

            _logger.LogDebug("Read performance settings: MaxOpTime={MaxOpTime}ms, MaxMemory={MaxMemory}MB, CacheExpiry={CacheExpiry}min", 
                perfPolicy.MaxOperationTimeMs, perfPolicy.MaxMemoryUsageMB, perfPolicy.CacheExpiryMinutes);

            await Task.CompletedTask;
        }

        /// <summary>
        /// Reads certificate settings from the registry.
        /// </summary>
        /// <param name="policy">The policy to populate</param>
        /// <param name="baseKey">The base registry key</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task ReadCertificateSettings(PqcEmailPolicy policy, RegistryKey baseKey)
        {
            using var certKey = baseKey.OpenSubKey("Certificates");
            if (certKey == null) return;

            var certPolicy = policy.Certificate;

            certPolicy.RequireValidCertChain = 
                ConvertToBoolean(certKey.GetValue("RequireValidCertChain"), certPolicy.RequireValidCertChain);
            certPolicy.AllowSelfSignedCerts = 
                ConvertToBoolean(certKey.GetValue("AllowSelfSignedCerts"), certPolicy.AllowSelfSignedCerts);

            if (certKey.GetValue("CertificateValidityDays") is int validityDays)
            {
                certPolicy.CertificateValidityDays = validityDays;
            }

            certPolicy.RequireOcspValidation = 
                ConvertToBoolean(certKey.GetValue("RequireOcspValidation"), certPolicy.RequireOcspValidation);
            certPolicy.RequireCrlChecking = 
                ConvertToBoolean(certKey.GetValue("RequireCrlChecking"), certPolicy.RequireCrlChecking);

            // Read trusted CAs (stored as multi-string value)
            if (certKey.GetValue("TrustedCertificateAuthorities") is string[] trustedCAs)
            {
                certPolicy.TrustedCertificateAuthorities = trustedCAs.Where(ca => !string.IsNullOrWhiteSpace(ca)).ToList();
            }

            _logger.LogDebug("Read certificate settings: RequireValidChain={RequireValidChain}, AllowSelfSigned={AllowSelfSigned}, TrustedCAs={TrustedCAsCount}", 
                certPolicy.RequireValidCertChain, certPolicy.AllowSelfSignedCerts, certPolicy.TrustedCertificateAuthorities.Count);

            await Task.CompletedTask;
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Reads a list of domain rules from a registry multi-string value.
        /// </summary>
        /// <param name="domainKey">The domain registry key</param>
        /// <param name="valueName">The value name to read</param>
        /// <returns>A list of domain rules</returns>
        private List<DomainRule> ReadDomainRuleList(RegistryKey domainKey, string valueName)
        {
            var rules = new List<DomainRule>();

            if (domainKey.GetValue(valueName) is string[] domainPatterns)
            {
                var priority = 100; // Default priority
                foreach (var pattern in domainPatterns.Where(p => !string.IsNullOrWhiteSpace(p)))
                {
                    rules.Add(new DomainRule
                    {
                        Pattern = pattern.Trim(),
                        Enabled = true,
                        Priority = priority++,
                        Description = $"Group Policy rule from {valueName}"
                    });
                }
            }

            return rules;
        }

        /// <summary>
        /// Converts a registry value to a boolean.
        /// </summary>
        /// <param name="value">The registry value</param>
        /// <param name="defaultValue">The default value if conversion fails</param>
        /// <returns>The boolean value</returns>
        private static bool ConvertToBoolean(object? value, bool defaultValue)
        {
            return value switch
            {
                bool boolValue => boolValue,
                int intValue => intValue != 0,
                string strValue => bool.TryParse(strValue, out var result) ? result : (strValue.Equals("1") || strValue.Equals("true", StringComparison.OrdinalIgnoreCase)),
                _ => defaultValue
            };
        }

        #endregion

        #region IDisposable Implementation

        /// <summary>
        /// Disposes of resources used by this policy provider.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes of resources used by this policy provider.
        /// </summary>
        /// <param name="disposing">True if disposing managed resources</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                // Clean up any resources if needed
                _disposed = true;
            }
        }

        #endregion
    }
}