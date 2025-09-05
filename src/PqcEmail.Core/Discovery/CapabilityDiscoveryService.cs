using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Discovery
{
    /// <summary>
    /// Main service for discovering recipient cryptographic capabilities
    /// Orchestrates DNS SMIMEA queries, Active Directory lookup, and caching
    /// </summary>
    public class CapabilityDiscoveryService : ICapabilityDiscoveryService, IDisposable
    {
        private readonly CapabilityDiscoveryConfiguration _configuration;
        private readonly ISmimeaDnsResolver _dnsResolver;
        private readonly ICapabilityCache _cache;
        private readonly IRecipientCapabilityRepository _repository;
        private readonly IActiveDirectoryCapabilityProvider _activeDirectoryProvider;
        private readonly SemaphoreSlim _concurrencyLimiter;
        private readonly object _statsLock = new object();
        private CapabilityDiscoveryStats _stats;
        private bool _disposed = false;

        public CapabilityDiscoveryService(
            CapabilityDiscoveryConfiguration? configuration = null,
            ISmimeaDnsResolver? dnsResolver = null,
            ICapabilityCache? cache = null,
            IRecipientCapabilityRepository? repository = null,
            IActiveDirectoryCapabilityProvider? activeDirectoryProvider = null)
        {
            _configuration = configuration ?? CapabilityDiscoveryConfiguration.CreateDefault();
            _dnsResolver = dnsResolver ?? new SmimeaDnsResolver(_configuration);
            _cache = cache ?? new CapabilityCache();
            _repository = repository ?? new RecipientCapabilityRepository();
            _activeDirectoryProvider = activeDirectoryProvider ?? new ActiveDirectoryCapabilityProvider(_configuration);
            
            _concurrencyLimiter = new SemaphoreSlim(_configuration.MaxConcurrentDiscoveries, _configuration.MaxConcurrentDiscoveries);
            _stats = new CapabilityDiscoveryStats { LastResetTime = DateTime.UtcNow };
        }

        /// <summary>
        /// Discovers capabilities for a single recipient
        /// </summary>
        public async Task<CapabilityDiscoveryResult> DiscoverCapabilitiesAsync(string emailAddress, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                throw new ArgumentException("Email address cannot be null or empty", nameof(emailAddress));

            var stopwatch = Stopwatch.StartNew();
            IncrementStats(s => s.TotalQueries++);

            try
            {
                // Step 1: Check cache first
                var cachedCapabilities = await _cache.GetAsync(emailAddress, cancellationToken);
                if (cachedCapabilities != null && cachedCapabilities.IsValid)
                {
                    IncrementStats(s => s.CacheHits++);
                    return CapabilityDiscoveryResult.Success(cachedCapabilities, stopwatch.Elapsed, fromCache: true);
                }

                IncrementStats(s => s.CacheMisses++);

                // Step 2: Try discovery from various sources
                await _concurrencyLimiter.WaitAsync(cancellationToken);
                try
                {
                    var capabilities = await DiscoverFromSourcesAsync(emailAddress, cancellationToken);
                    
                    if (capabilities != null)
                    {
                        // Step 3: Cache the discovered capabilities
                        await CacheDiscoveredCapabilities(capabilities, cancellationToken);
                        
                        IncrementStats(s => s.SuccessfulQueries++);
                        return CapabilityDiscoveryResult.Success(capabilities, stopwatch.Elapsed);
                    }
                    else
                    {
                        // Step 4: Use fallback capabilities if configured
                        if (_configuration.DefaultCapabilities != null)
                        {
                            var fallbackCapabilities = CreateFallbackCapabilities(emailAddress, _configuration.DefaultCapabilities);
                            await CacheDiscoveredCapabilities(fallbackCapabilities, cancellationToken);
                            return CapabilityDiscoveryResult.Success(fallbackCapabilities, stopwatch.Elapsed);
                        }

                        var error = new CapabilityDiscoveryError
                        {
                            Type = CapabilityErrorType.NoSmimeaRecord,
                            Message = "No capabilities found and no fallback configured"
                        };
                        return CapabilityDiscoveryResult.Failure(error, stopwatch.Elapsed);
                    }
                }
                finally
                {
                    _concurrencyLimiter.Release();
                }
            }
            catch (OperationCanceledException)
            {
                var error = new CapabilityDiscoveryError
                {
                    Type = CapabilityErrorType.DnsTimeout,
                    Message = "Discovery operation was cancelled"
                };
                return CapabilityDiscoveryResult.Failure(error, stopwatch.Elapsed);
            }
            catch (Exception ex)
            {
                var error = new CapabilityDiscoveryError
                {
                    Type = CapabilityErrorType.Unknown,
                    Message = "Unexpected error during discovery",
                    Details = ex.Message,
                    InnerException = ex
                };
                return CapabilityDiscoveryResult.Failure(error, stopwatch.Elapsed);
            }
            finally
            {
                UpdateAverageDiscoveryTime(stopwatch.Elapsed);
            }
        }

        /// <summary>
        /// Discovers capabilities for multiple recipients in parallel
        /// </summary>
        public async Task<Dictionary<string, CapabilityDiscoveryResult>> DiscoverCapabilitiesAsync(IEnumerable<string> emailAddresses, CancellationToken cancellationToken = default)
        {
            if (emailAddresses == null)
                throw new ArgumentNullException(nameof(emailAddresses));

            var addresses = emailAddresses.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var results = new Dictionary<string, CapabilityDiscoveryResult>(StringComparer.OrdinalIgnoreCase);

            if (addresses.Count == 0)
                return results;

            // Process in parallel with concurrency control
            var tasks = addresses.Select(async address =>
            {
                var result = await DiscoverCapabilitiesAsync(address, cancellationToken);
                return new KeyValuePair<string, CapabilityDiscoveryResult>(address, result);
            });

            var completedTasks = await Task.WhenAll(tasks);
            
            foreach (var task in completedTasks)
            {
                results[task.Key] = task.Value;
            }

            return results;
        }

        /// <summary>
        /// Gets cached capabilities for a recipient if available
        /// </summary>
        public async Task<RecipientCapabilities?> GetCachedCapabilitiesAsync(string emailAddress, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                throw new ArgumentException("Email address cannot be null or empty", nameof(emailAddress));

            return await _cache.GetAsync(emailAddress, cancellationToken);
        }

        /// <summary>
        /// Manually sets capabilities for a recipient (overrides discovery)
        /// </summary>
        public async Task SetCapabilitiesAsync(string emailAddress, RecipientCapabilities capabilities, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                throw new ArgumentException("Email address cannot be null or empty", nameof(emailAddress));

            if (capabilities == null)
                throw new ArgumentNullException(nameof(capabilities));

            capabilities.EmailAddress = emailAddress;
            capabilities.Source = CapabilitySource.Manual;
            capabilities.DiscoveredAt = DateTimeOffset.UtcNow;
            
            if (capabilities.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                capabilities.ExpiresAt = DateTimeOffset.UtcNow.Add(_configuration.DefaultCacheTtl);
            }

            await _cache.SetAsync(emailAddress, capabilities, _configuration.DefaultCacheTtl, cancellationToken);
            await _repository.StoreCapabilitiesAsync(capabilities, cancellationToken);
        }

        /// <summary>
        /// Clears cached capabilities for a recipient (forces fresh discovery)
        /// </summary>
        public async Task ClearCacheAsync(string emailAddress, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                throw new ArgumentException("Email address cannot be null or empty", nameof(emailAddress));

            await _cache.RemoveAsync(emailAddress, cancellationToken);
            await _repository.DeleteCapabilitiesAsync(emailAddress, cancellationToken);
        }

        /// <summary>
        /// Clears all cached capabilities
        /// </summary>
        public async Task ClearAllCacheAsync(CancellationToken cancellationToken = default)
        {
            await _cache.ClearAsync(cancellationToken);
            
            // Note: We don't clear the repository as it contains persistent data
            // Only clear expired entries
            await _repository.CleanupExpiredAsync(cancellationToken);
        }

        /// <summary>
        /// Gets discovery statistics
        /// </summary>
        public Task<CapabilityDiscoveryStats> GetStatsAsync(CancellationToken cancellationToken = default)
        {
            lock (_statsLock)
            {
                return Task.FromResult(new CapabilityDiscoveryStats
                {
                    TotalQueries = _stats.TotalQueries,
                    SuccessfulQueries = _stats.SuccessfulQueries,
                    CacheHits = _stats.CacheHits,
                    CacheMisses = _stats.CacheMisses,
                    DnsQueries = _stats.DnsQueries,
                    ActiveDirectoryQueries = _stats.ActiveDirectoryQueries,
                    AverageDiscoveryTime = _stats.AverageDiscoveryTime,
                    LastResetTime = _stats.LastResetTime
                });
            }
        }

        private async Task<RecipientCapabilities?> DiscoverFromSourcesAsync(string emailAddress, CancellationToken cancellationToken)
        {
            // Step 1: Check if this is an internal recipient (Active Directory)
            var isInternal = await _activeDirectoryProvider.IsInternalRecipientAsync(emailAddress, cancellationToken);
            
            if (isInternal)
            {
                IncrementStats(s => s.ActiveDirectoryQueries++);
                var adCapabilities = await _activeDirectoryProvider.QueryCapabilitiesAsync(emailAddress, cancellationToken);
                if (adCapabilities != null)
                {
                    await _repository.StoreCapabilitiesAsync(adCapabilities, cancellationToken);
                    return adCapabilities;
                }
            }

            // Step 2: Try DNS SMIMEA record lookup
            IncrementStats(s => s.DnsQueries++);
            var dnsResult = await _dnsResolver.QuerySmimeaRecordsAsync(emailAddress, cancellationToken);
            
            if (dnsResult.SmimeaRecords.Count > 0 && string.IsNullOrEmpty(dnsResult.ErrorMessage))
            {
                var capabilities = ConvertSmimeaToCapabilities(emailAddress, dnsResult);
                if (capabilities != null)
                {
                    await _repository.StoreCapabilitiesAsync(capabilities, cancellationToken);
                    return capabilities;
                }
            }

            // Step 3: Check repository for previously stored capabilities (including expired ones for partial info)
            var storedCapabilities = await _repository.GetCapabilitiesAsync(emailAddress, cancellationToken);
            if (storedCapabilities != null)
            {
                // Even if expired, we might use it as a basis for capabilities
                if (!storedCapabilities.IsValid && _configuration.EnableClassicalFallback)
                {
                    // Extend expiry and use as fallback
                    storedCapabilities.ExpiresAt = DateTimeOffset.UtcNow.Add(_configuration.DefaultCacheTtl);
                    storedCapabilities.ConfidenceLevel *= 0.5; // Reduce confidence for stale data
                    return storedCapabilities;
                }
                else if (storedCapabilities.IsValid)
                {
                    return storedCapabilities;
                }
            }

            return null;
        }

        private RecipientCapabilities? ConvertSmimeaToCapabilities(string emailAddress, DnsQueryResult dnsResult)
        {
            try
            {
                var capabilities = new RecipientCapabilities
                {
                    EmailAddress = emailAddress,
                    Source = CapabilitySource.SmimeaDns,
                    DiscoveredAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.Add(_configuration.DefaultCacheTtl),
                    ConfidenceLevel = dnsResult.DnssecValidated ? 0.9 : 0.7
                };

                // Analyze SMIMEA records to determine capabilities
                foreach (var record in dnsResult.SmimeaRecords)
                {
                    if (record.IsPqcExtended && record.PqcAlgorithms.Count > 0)
                    {
                        // PQC-extended SMIMEA record
                        capabilities.SupportedModes.Add(CryptographicMode.PostQuantumOnly);
                        capabilities.SupportedModes.Add(CryptographicMode.Hybrid);
                        
                        foreach (var algorithm in record.PqcAlgorithms)
                        {
                            if (algorithm.Contains("KEM", StringComparison.OrdinalIgnoreCase))
                            {
                                capabilities.SupportedKemAlgorithms.Add(algorithm);
                            }
                            else if (algorithm.Contains("SIG", StringComparison.OrdinalIgnoreCase) || 
                                     algorithm.Contains("DSA", StringComparison.OrdinalIgnoreCase))
                            {
                                capabilities.SupportedSignatureAlgorithms.Add(algorithm);
                            }
                        }
                    }
                    else
                    {
                        // Standard SMIMEA record - assume classical capabilities
                        capabilities.SupportedModes.Add(CryptographicMode.ClassicalOnly);
                        if (_configuration.EnableClassicalFallback)
                        {
                            capabilities.SupportedModes.Add(CryptographicMode.Hybrid);
                        }
                        
                        capabilities.SupportedClassicalAlgorithms.AddRange(new[] { "RSA-OAEP-2048", "RSA-PSS-2048" });
                    }
                }

                // Ensure we have some default capabilities
                if (capabilities.SupportedModes.Count == 0)
                {
                    capabilities.SupportedModes.Add(CryptographicMode.ClassicalOnly);
                    capabilities.SupportedClassicalAlgorithms.Add("RSA-OAEP-2048");
                }

                // Add DNS-specific metadata
                capabilities.Metadata["dns_query"] = dnsResult.Query;
                capabilities.Metadata["dns_server"] = dnsResult.DnsServer ?? "default";
                capabilities.Metadata["dnssec_validated"] = dnsResult.DnssecValidated;
                capabilities.Metadata["response_time_ms"] = dnsResult.ResponseTime.TotalMilliseconds;

                return capabilities;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private RecipientCapabilities CreateFallbackCapabilities(string emailAddress, RecipientCapabilities template)
        {
            var capabilities = new RecipientCapabilities
            {
                EmailAddress = emailAddress,
                SupportedKemAlgorithms = new List<string>(template.SupportedKemAlgorithms),
                SupportedSignatureAlgorithms = new List<string>(template.SupportedSignatureAlgorithms),
                SupportedClassicalAlgorithms = new List<string>(template.SupportedClassicalAlgorithms),
                SupportedModes = new List<CryptographicMode>(template.SupportedModes),
                Source = CapabilitySource.Fallback,
                DiscoveredAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.Add(_configuration.DefaultCacheTtl),
                ConfidenceLevel = template.ConfidenceLevel,
                Metadata = new Dictionary<string, object>(template.Metadata)
            };

            capabilities.Metadata["fallback_reason"] = "No capabilities discovered from any source";

            return capabilities;
        }

        private async Task CacheDiscoveredCapabilities(RecipientCapabilities capabilities, CancellationToken cancellationToken)
        {
            try
            {
                var ttl = capabilities.ExpiresAt - DateTimeOffset.UtcNow;
                if (ttl > TimeSpan.Zero)
                {
                    await _cache.SetAsync(capabilities.EmailAddress, capabilities, ttl, cancellationToken);
                }

                // Always store in repository for historical data
                await _repository.StoreCapabilitiesAsync(capabilities, cancellationToken);
            }
            catch (Exception)
            {
                // Don't fail the main operation if caching fails
            }
        }

        private void IncrementStats(Action<CapabilityDiscoveryStats> updateAction)
        {
            lock (_statsLock)
            {
                updateAction(_stats);
            }
        }

        private void UpdateAverageDiscoveryTime(TimeSpan discoveryTime)
        {
            lock (_statsLock)
            {
                if (_stats.TotalQueries <= 1)
                {
                    _stats.AverageDiscoveryTime = discoveryTime;
                }
                else
                {
                    // Rolling average calculation
                    var totalTime = _stats.AverageDiscoveryTime.TotalMilliseconds * (_stats.TotalQueries - 1) + discoveryTime.TotalMilliseconds;
                    _stats.AverageDiscoveryTime = TimeSpan.FromMilliseconds(totalTime / _stats.TotalQueries);
                }
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _concurrencyLimiter?.Dispose();
                (_cache as IDisposable)?.Dispose();
                (_repository as IDisposable)?.Dispose();
                (_activeDirectoryProvider as IDisposable)?.Dispose();
                _disposed = true;
            }
        }
    }
}