using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Interfaces
{
    /// <summary>
    /// Service for discovering recipient cryptographic capabilities
    /// </summary>
    public interface ICapabilityDiscoveryService
    {
        /// <summary>
        /// Discovers capabilities for a single recipient
        /// </summary>
        /// <param name="emailAddress">Email address to discover capabilities for</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Discovery result with capabilities or error</returns>
        Task<CapabilityDiscoveryResult> DiscoverCapabilitiesAsync(string emailAddress, CancellationToken cancellationToken = default);

        /// <summary>
        /// Discovers capabilities for multiple recipients in parallel
        /// </summary>
        /// <param name="emailAddresses">Email addresses to discover capabilities for</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Dictionary of email addresses to discovery results</returns>
        Task<Dictionary<string, CapabilityDiscoveryResult>> DiscoverCapabilitiesAsync(IEnumerable<string> emailAddresses, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets cached capabilities for a recipient if available
        /// </summary>
        /// <param name="emailAddress">Email address to get capabilities for</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Cached capabilities or null if not found/expired</returns>
        Task<RecipientCapabilities?> GetCachedCapabilitiesAsync(string emailAddress, CancellationToken cancellationToken = default);

        /// <summary>
        /// Manually sets capabilities for a recipient (overrides discovery)
        /// </summary>
        /// <param name="emailAddress">Email address</param>
        /// <param name="capabilities">Capabilities to set</param>
        /// <param name="cancellationToken">Cancellation token</param>
        Task SetCapabilitiesAsync(string emailAddress, RecipientCapabilities capabilities, CancellationToken cancellationToken = default);

        /// <summary>
        /// Clears cached capabilities for a recipient (forces fresh discovery)
        /// </summary>
        /// <param name="emailAddress">Email address to clear cache for</param>
        /// <param name="cancellationToken">Cancellation token</param>
        Task ClearCacheAsync(string emailAddress, CancellationToken cancellationToken = default);

        /// <summary>
        /// Clears all cached capabilities
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        Task ClearAllCacheAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets discovery statistics
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Discovery statistics</returns>
        Task<CapabilityDiscoveryStats> GetStatsAsync(CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// DNS resolver for SMIMEA records
    /// </summary>
    public interface ISmimeaDnsResolver
    {
        /// <summary>
        /// Queries DNS for SMIMEA records for the given email address
        /// </summary>
        /// <param name="emailAddress">Email address to query</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>DNS query result with SMIMEA records</returns>
        Task<DnsQueryResult> QuerySmimeaRecordsAsync(string emailAddress, CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates DNSSEC signatures for SMIMEA records
        /// </summary>
        /// <param name="domainName">Domain name to validate</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if DNSSEC validation passes</returns>
        Task<bool> ValidateDnssecAsync(string domainName, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Cache for storing discovered capabilities
    /// </summary>
    public interface ICapabilityCache
    {
        /// <summary>
        /// Gets cached capabilities for an email address
        /// </summary>
        /// <param name="emailAddress">Email address</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Cached capabilities or null if not found/expired</returns>
        Task<RecipientCapabilities?> GetAsync(string emailAddress, CancellationToken cancellationToken = default);

        /// <summary>
        /// Sets capabilities in cache with TTL
        /// </summary>
        /// <param name="emailAddress">Email address</param>
        /// <param name="capabilities">Capabilities to cache</param>
        /// <param name="ttl">Time to live for cache entry</param>
        /// <param name="cancellationToken">Cancellation token</param>
        Task SetAsync(string emailAddress, RecipientCapabilities capabilities, TimeSpan ttl, CancellationToken cancellationToken = default);

        /// <summary>
        /// Removes capabilities from cache
        /// </summary>
        /// <param name="emailAddress">Email address</param>
        /// <param name="cancellationToken">Cancellation token</param>
        Task RemoveAsync(string emailAddress, CancellationToken cancellationToken = default);

        /// <summary>
        /// Clears all cached capabilities
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        Task ClearAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets cache statistics
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Cache statistics</returns>
        Task<CacheStats> GetStatsAsync(CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Active Directory integration for internal recipient capabilities
    /// </summary>
    public interface IActiveDirectoryCapabilityProvider
    {
        /// <summary>
        /// Queries Active Directory for recipient capabilities
        /// </summary>
        /// <param name="emailAddress">Email address to query</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Capabilities discovered from AD or null if not found</returns>
        Task<RecipientCapabilities?> QueryCapabilitiesAsync(string emailAddress, CancellationToken cancellationToken = default);

        /// <summary>
        /// Checks if an email address is internal (in the organization)
        /// </summary>
        /// <param name="emailAddress">Email address to check</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if email address is internal</returns>
        Task<bool> IsInternalRecipientAsync(string emailAddress, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets certificate information from Active Directory for a user
        /// </summary>
        /// <param name="emailAddress">Email address</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Certificate information or null if not found</returns>
        Task<CertificateInfo?> GetUserCertificateAsync(string emailAddress, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Database for storing recipient capability information
    /// </summary>
    public interface IRecipientCapabilityRepository
    {
        /// <summary>
        /// Gets stored capabilities for a recipient
        /// </summary>
        /// <param name="emailAddress">Email address</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Stored capabilities or null if not found</returns>
        Task<RecipientCapabilities?> GetCapabilitiesAsync(string emailAddress, CancellationToken cancellationToken = default);

        /// <summary>
        /// Stores or updates capabilities for a recipient
        /// </summary>
        /// <param name="capabilities">Capabilities to store</param>
        /// <param name="cancellationToken">Cancellation token</param>
        Task StoreCapabilitiesAsync(RecipientCapabilities capabilities, CancellationToken cancellationToken = default);

        /// <summary>
        /// Deletes stored capabilities for a recipient
        /// </summary>
        /// <param name="emailAddress">Email address</param>
        /// <param name="cancellationToken">Cancellation token</param>
        Task DeleteCapabilitiesAsync(string emailAddress, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets capabilities for multiple recipients in batch
        /// </summary>
        /// <param name="emailAddresses">Email addresses to query</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Dictionary of email addresses to capabilities</returns>
        Task<Dictionary<string, RecipientCapabilities>> GetBatchCapabilitiesAsync(IEnumerable<string> emailAddresses, CancellationToken cancellationToken = default);

        /// <summary>
        /// Cleans up expired capability records
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Number of records cleaned up</returns>
        Task<int> CleanupExpiredAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets repository statistics
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Repository statistics</returns>
        Task<RepositoryStats> GetStatsAsync(CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Statistics for capability discovery operations
    /// </summary>
    public class CapabilityDiscoveryStats
    {
        public int TotalQueries { get; set; }
        public int SuccessfulQueries { get; set; }
        public int CacheHits { get; set; }
        public int CacheMisses { get; set; }
        public int DnsQueries { get; set; }
        public int ActiveDirectoryQueries { get; set; }
        public TimeSpan AverageDiscoveryTime { get; set; }
        public DateTime LastResetTime { get; set; } = DateTime.UtcNow;

        public double SuccessRate => TotalQueries > 0 ? (double)SuccessfulQueries / TotalQueries : 0;
        public double CacheHitRate => (CacheHits + CacheMisses) > 0 ? (double)CacheHits / (CacheHits + CacheMisses) : 0;
    }

    /// <summary>
    /// Statistics for cache operations
    /// </summary>
    public class CacheStats
    {
        public int TotalEntries { get; set; }
        public int ExpiredEntries { get; set; }
        public int Hits { get; set; }
        public int Misses { get; set; }
        public long MemoryUsage { get; set; }
        public DateTime LastCleanup { get; set; }

        public double HitRate => (Hits + Misses) > 0 ? (double)Hits / (Hits + Misses) : 0;
    }

    /// <summary>
    /// Statistics for repository operations
    /// </summary>
    public class RepositoryStats
    {
        public int TotalRecords { get; set; }
        public int ExpiredRecords { get; set; }
        public int RecentQueries { get; set; }
        public TimeSpan AverageQueryTime { get; set; }
        public DateTime LastCleanup { get; set; }
    }
}