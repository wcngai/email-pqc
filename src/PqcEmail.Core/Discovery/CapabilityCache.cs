using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Discovery
{
    /// <summary>
    /// In-memory cache for recipient capabilities with TTL support
    /// </summary>
    public class CapabilityCache : ICapabilityCache
    {
        private readonly ConcurrentDictionary<string, CacheEntry> _cache;
        private readonly Timer _cleanupTimer;
        private readonly object _statsLock = new object();
        private CacheStats _stats;

        public CapabilityCache()
        {
            _cache = new ConcurrentDictionary<string, CacheEntry>(StringComparer.OrdinalIgnoreCase);
            _stats = new CacheStats { LastCleanup = DateTime.UtcNow };
            
            // Clean up expired entries every 5 minutes
            _cleanupTimer = new Timer(CleanupExpiredEntries, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        }

        /// <summary>
        /// Gets cached capabilities for an email address
        /// </summary>
        public Task<RecipientCapabilities?> GetAsync(string emailAddress, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                throw new ArgumentException("Email address cannot be null or empty", nameof(emailAddress));

            var normalizedEmail = NormalizeEmailAddress(emailAddress);

            if (_cache.TryGetValue(normalizedEmail, out var entry))
            {
                if (entry.ExpiresAt > DateTimeOffset.UtcNow)
                {
                    // Valid cache hit
                    lock (_statsLock)
                    {
                        _stats.Hits++;
                    }
                    
                    entry.LastAccessed = DateTimeOffset.UtcNow;
                    return Task.FromResult<RecipientCapabilities?>(entry.Capabilities);
                }
                else
                {
                    // Expired entry, remove it
                    _cache.TryRemove(normalizedEmail, out _);
                }
            }

            // Cache miss
            lock (_statsLock)
            {
                _stats.Misses++;
            }

            return Task.FromResult<RecipientCapabilities?>(null);
        }

        /// <summary>
        /// Sets capabilities in cache with TTL
        /// </summary>
        public Task SetAsync(string emailAddress, RecipientCapabilities capabilities, TimeSpan ttl, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                throw new ArgumentException("Email address cannot be null or empty", nameof(emailAddress));

            if (capabilities == null)
                throw new ArgumentNullException(nameof(capabilities));

            if (ttl <= TimeSpan.Zero)
                throw new ArgumentException("TTL must be positive", nameof(ttl));

            var normalizedEmail = NormalizeEmailAddress(emailAddress);
            var now = DateTimeOffset.UtcNow;

            var entry = new CacheEntry
            {
                Capabilities = capabilities,
                CreatedAt = now,
                ExpiresAt = now.Add(ttl),
                LastAccessed = now,
                AccessCount = 0
            };

            _cache.AddOrUpdate(normalizedEmail, entry, (key, existing) => entry);

            // Update capabilities with cache information
            capabilities.Source = CapabilitySource.Cache;
            capabilities.ExpiresAt = entry.ExpiresAt;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Removes capabilities from cache
        /// </summary>
        public Task RemoveAsync(string emailAddress, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                throw new ArgumentException("Email address cannot be null or empty", nameof(emailAddress));

            var normalizedEmail = NormalizeEmailAddress(emailAddress);
            _cache.TryRemove(normalizedEmail, out _);

            return Task.CompletedTask;
        }

        /// <summary>
        /// Clears all cached capabilities
        /// </summary>
        public Task ClearAsync(CancellationToken cancellationToken = default)
        {
            _cache.Clear();
            
            lock (_statsLock)
            {
                _stats = new CacheStats { LastCleanup = DateTime.UtcNow };
            }

            return Task.CompletedTask;
        }

        /// <summary>
        /// Gets cache statistics
        /// </summary>
        public Task<CacheStats> GetStatsAsync(CancellationToken cancellationToken = default)
        {
            lock (_statsLock)
            {
                var currentStats = new CacheStats
                {
                    TotalEntries = _cache.Count,
                    ExpiredEntries = CountExpiredEntries(),
                    Hits = _stats.Hits,
                    Misses = _stats.Misses,
                    MemoryUsage = EstimateMemoryUsage(),
                    LastCleanup = _stats.LastCleanup
                };

                return Task.FromResult(currentStats);
            }
        }

        private int CountExpiredEntries()
        {
            var now = DateTimeOffset.UtcNow;
            return _cache.Values.Count(entry => entry.ExpiresAt <= now);
        }

        private long EstimateMemoryUsage()
        {
            // Rough estimation of memory usage
            var entryCount = _cache.Count;
            var avgEmailLength = 50; // bytes
            var avgCapabilitiesSize = 1024; // bytes (rough estimate)
            var entryOverhead = 200; // bytes (object overhead, timestamps, etc.)

            return entryCount * (avgEmailLength + avgCapabilitiesSize + entryOverhead);
        }

        private void CleanupExpiredEntries(object? state)
        {
            var now = DateTimeOffset.UtcNow;
            var expiredKeys = new List<string>();

            foreach (var kvp in _cache)
            {
                if (kvp.Value.ExpiresAt <= now)
                {
                    expiredKeys.Add(kvp.Key);
                }
            }

            foreach (var key in expiredKeys)
            {
                _cache.TryRemove(key, out _);
            }

            lock (_statsLock)
            {
                _stats.LastCleanup = DateTime.UtcNow;
            }
        }

        private static string NormalizeEmailAddress(string emailAddress)
        {
            // Normalize email address for consistent caching
            return emailAddress.Trim().ToLowerInvariant();
        }

        public void Dispose()
        {
            _cleanupTimer?.Dispose();
        }

        /// <summary>
        /// Internal cache entry structure
        /// </summary>
        private class CacheEntry
        {
            public RecipientCapabilities Capabilities { get; set; } = null!;
            public DateTimeOffset CreatedAt { get; set; }
            public DateTimeOffset ExpiresAt { get; set; }
            public DateTimeOffset LastAccessed { get; set; }
            public int AccessCount { get; set; }
        }
    }

    /// <summary>
    /// Redis-based capability cache for distributed scenarios
    /// </summary>
    public class RedisCapabilityCache : ICapabilityCache
    {
        private readonly string _connectionString;
        private readonly string _keyPrefix;

        public RedisCapabilityCache(string connectionString, string keyPrefix = "pqc:capabilities:")
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
            _keyPrefix = keyPrefix;
        }

        public async Task<RecipientCapabilities?> GetAsync(string emailAddress, CancellationToken cancellationToken = default)
        {
            // Placeholder for Redis implementation
            // Would use StackExchange.Redis or similar library
            await Task.Delay(1, cancellationToken);
            throw new NotImplementedException("Redis cache implementation requires StackExchange.Redis dependency");
        }

        public async Task SetAsync(string emailAddress, RecipientCapabilities capabilities, TimeSpan ttl, CancellationToken cancellationToken = default)
        {
            // Placeholder for Redis implementation
            await Task.Delay(1, cancellationToken);
            throw new NotImplementedException("Redis cache implementation requires StackExchange.Redis dependency");
        }

        public async Task RemoveAsync(string emailAddress, CancellationToken cancellationToken = default)
        {
            await Task.Delay(1, cancellationToken);
            throw new NotImplementedException("Redis cache implementation requires StackExchange.Redis dependency");
        }

        public async Task ClearAsync(CancellationToken cancellationToken = default)
        {
            await Task.Delay(1, cancellationToken);
            throw new NotImplementedException("Redis cache implementation requires StackExchange.Redis dependency");
        }

        public async Task<CacheStats> GetStatsAsync(CancellationToken cancellationToken = default)
        {
            await Task.Delay(1, cancellationToken);
            throw new NotImplementedException("Redis cache implementation requires StackExchange.Redis dependency");
        }
    }
}