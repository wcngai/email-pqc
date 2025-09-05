using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Discovery
{
    /// <summary>
    /// SQLite-based repository for storing recipient capability information
    /// </summary>
    public class RecipientCapabilityRepository : IRecipientCapabilityRepository, IDisposable
    {
        private readonly string _connectionString;
        private readonly SemaphoreSlim _connectionSemaphore;
        private bool _disposed = false;

        public RecipientCapabilityRepository(string databasePath = "capabilities.db")
        {
            if (string.IsNullOrWhiteSpace(databasePath))
                throw new ArgumentException("Database path cannot be null or empty", nameof(databasePath));

            // Create directory if it doesn't exist
            var directory = Path.GetDirectoryName(Path.GetFullPath(databasePath));
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            _connectionString = $"Data Source={databasePath};Version=3;Journal Mode=WAL;";
            _connectionSemaphore = new SemaphoreSlim(10, 10); // Allow up to 10 concurrent connections

            InitializeDatabase().GetAwaiter().GetResult();
        }

        /// <summary>
        /// Gets stored capabilities for a recipient
        /// </summary>
        public async Task<RecipientCapabilities?> GetCapabilitiesAsync(string emailAddress, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                throw new ArgumentException("Email address cannot be null or empty", nameof(emailAddress));

            var normalizedEmail = NormalizeEmailAddress(emailAddress);

            await _connectionSemaphore.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SQLiteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                const string sql = @"
                    SELECT email_address, supported_kem_algorithms, supported_signature_algorithms, 
                           supported_classical_algorithms, supported_modes, source, discovered_at, 
                           expires_at, confidence_level, metadata
                    FROM recipient_capabilities 
                    WHERE email_address = @email AND expires_at > @now";

                using var command = new SQLiteCommand(sql, connection);
                command.Parameters.AddWithValue("@email", normalizedEmail);
                command.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));

                using var reader = await command.ExecuteReaderAsync(cancellationToken);
                
                if (await reader.ReadAsync(cancellationToken))
                {
                    return ReadCapabilitiesFromDatabase(reader);
                }

                return null;
            }
            finally
            {
                _connectionSemaphore.Release();
            }
        }

        /// <summary>
        /// Stores or updates capabilities for a recipient
        /// </summary>
        public async Task StoreCapabilitiesAsync(RecipientCapabilities capabilities, CancellationToken cancellationToken = default)
        {
            if (capabilities == null)
                throw new ArgumentNullException(nameof(capabilities));

            if (string.IsNullOrWhiteSpace(capabilities.EmailAddress))
                throw new ArgumentException("Capabilities must have an email address", nameof(capabilities));

            var normalizedEmail = NormalizeEmailAddress(capabilities.EmailAddress);

            await _connectionSemaphore.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SQLiteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                const string sql = @"
                    INSERT OR REPLACE INTO recipient_capabilities 
                    (email_address, supported_kem_algorithms, supported_signature_algorithms, 
                     supported_classical_algorithms, supported_modes, source, discovered_at, 
                     expires_at, confidence_level, metadata, created_at, updated_at)
                    VALUES (@email, @kem_algos, @sig_algos, @classical_algos, @modes, @source, 
                            @discovered_at, @expires_at, @confidence, @metadata, @created_at, @updated_at)";

                using var command = new SQLiteCommand(sql, connection);
                command.Parameters.AddWithValue("@email", normalizedEmail);
                command.Parameters.AddWithValue("@kem_algos", JsonSerializer.Serialize(capabilities.SupportedKemAlgorithms));
                command.Parameters.AddWithValue("@sig_algos", JsonSerializer.Serialize(capabilities.SupportedSignatureAlgorithms));
                command.Parameters.AddWithValue("@classical_algos", JsonSerializer.Serialize(capabilities.SupportedClassicalAlgorithms));
                command.Parameters.AddWithValue("@modes", JsonSerializer.Serialize(capabilities.SupportedModes.Select(m => m.ToString()).ToList()));
                command.Parameters.AddWithValue("@source", capabilities.Source.ToString());
                command.Parameters.AddWithValue("@discovered_at", capabilities.DiscoveredAt.ToString("O"));
                command.Parameters.AddWithValue("@expires_at", capabilities.ExpiresAt.ToString("O"));
                command.Parameters.AddWithValue("@confidence", capabilities.ConfidenceLevel);
                command.Parameters.AddWithValue("@metadata", JsonSerializer.Serialize(capabilities.Metadata));
                command.Parameters.AddWithValue("@created_at", DateTimeOffset.UtcNow.ToString("O"));
                command.Parameters.AddWithValue("@updated_at", DateTimeOffset.UtcNow.ToString("O"));

                await command.ExecuteNonQueryAsync(cancellationToken);
            }
            finally
            {
                _connectionSemaphore.Release();
            }
        }

        /// <summary>
        /// Deletes stored capabilities for a recipient
        /// </summary>
        public async Task DeleteCapabilitiesAsync(string emailAddress, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                throw new ArgumentException("Email address cannot be null or empty", nameof(emailAddress));

            var normalizedEmail = NormalizeEmailAddress(emailAddress);

            await _connectionSemaphore.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SQLiteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                const string sql = "DELETE FROM recipient_capabilities WHERE email_address = @email";

                using var command = new SQLiteCommand(sql, connection);
                command.Parameters.AddWithValue("@email", normalizedEmail);

                await command.ExecuteNonQueryAsync(cancellationToken);
            }
            finally
            {
                _connectionSemaphore.Release();
            }
        }

        /// <summary>
        /// Gets capabilities for multiple recipients in batch
        /// </summary>
        public async Task<Dictionary<string, RecipientCapabilities>> GetBatchCapabilitiesAsync(IEnumerable<string> emailAddresses, CancellationToken cancellationToken = default)
        {
            if (emailAddresses == null)
                throw new ArgumentNullException(nameof(emailAddresses));

            var result = new Dictionary<string, RecipientCapabilities>(StringComparer.OrdinalIgnoreCase);
            var normalizedEmails = emailAddresses.Select(NormalizeEmailAddress).Distinct().ToList();

            if (normalizedEmails.Count == 0)
                return result;

            await _connectionSemaphore.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SQLiteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                // Build parameterized query for batch lookup
                var parameters = normalizedEmails.Select((email, index) => $"@email{index}").ToList();
                var sql = $@"
                    SELECT email_address, supported_kem_algorithms, supported_signature_algorithms, 
                           supported_classical_algorithms, supported_modes, source, discovered_at, 
                           expires_at, confidence_level, metadata
                    FROM recipient_capabilities 
                    WHERE email_address IN ({string.Join(",", parameters)}) AND expires_at > @now";

                using var command = new SQLiteCommand(sql, connection);
                command.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
                
                for (int i = 0; i < normalizedEmails.Count; i++)
                {
                    command.Parameters.AddWithValue($"@email{i}", normalizedEmails[i]);
                }

                using var reader = await command.ExecuteReaderAsync(cancellationToken);
                
                while (await reader.ReadAsync(cancellationToken))
                {
                    var capabilities = ReadCapabilitiesFromDatabase(reader);
                    if (capabilities != null)
                    {
                        result[capabilities.EmailAddress] = capabilities;
                    }
                }
            }
            finally
            {
                _connectionSemaphore.Release();
            }

            return result;
        }

        /// <summary>
        /// Cleans up expired capability records
        /// </summary>
        public async Task<int> CleanupExpiredAsync(CancellationToken cancellationToken = default)
        {
            await _connectionSemaphore.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SQLiteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                const string sql = "DELETE FROM recipient_capabilities WHERE expires_at <= @now";

                using var command = new SQLiteCommand(sql, connection);
                command.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));

                return await command.ExecuteNonQueryAsync(cancellationToken);
            }
            finally
            {
                _connectionSemaphore.Release();
            }
        }

        /// <summary>
        /// Gets repository statistics
        /// </summary>
        public async Task<RepositoryStats> GetStatsAsync(CancellationToken cancellationToken = default)
        {
            await _connectionSemaphore.WaitAsync(cancellationToken);
            try
            {
                using var connection = new SQLiteConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);

                var stats = new RepositoryStats();

                // Get total record count
                using (var command = new SQLiteCommand("SELECT COUNT(*) FROM recipient_capabilities", connection))
                {
                    var result = await command.ExecuteScalarAsync(cancellationToken);
                    stats.TotalRecords = Convert.ToInt32(result);
                }

                // Get expired record count
                using (var command = new SQLiteCommand("SELECT COUNT(*) FROM recipient_capabilities WHERE expires_at <= @now", connection))
                {
                    command.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
                    var result = await command.ExecuteScalarAsync(cancellationToken);
                    stats.ExpiredRecords = Convert.ToInt32(result);
                }

                // Get recent queries (last 24 hours)
                using (var command = new SQLiteCommand("SELECT COUNT(*) FROM recipient_capabilities WHERE updated_at > @cutoff", connection))
                {
                    command.Parameters.AddWithValue("@cutoff", DateTimeOffset.UtcNow.AddDays(-1).ToString("O"));
                    var result = await command.ExecuteScalarAsync(cancellationToken);
                    stats.RecentQueries = Convert.ToInt32(result);
                }

                // Set default values for other stats
                stats.AverageQueryTime = TimeSpan.FromMilliseconds(10); // Estimate
                stats.LastCleanup = DateTime.UtcNow.AddHours(-1); // Estimate

                return stats;
            }
            finally
            {
                _connectionSemaphore.Release();
            }
        }

        private async Task InitializeDatabase()
        {
            using var connection = new SQLiteConnection(_connectionString);
            await connection.OpenAsync();

            const string createTableSql = @"
                CREATE TABLE IF NOT EXISTS recipient_capabilities (
                    email_address TEXT PRIMARY KEY,
                    supported_kem_algorithms TEXT NOT NULL,
                    supported_signature_algorithms TEXT NOT NULL,
                    supported_classical_algorithms TEXT NOT NULL,
                    supported_modes TEXT NOT NULL,
                    source TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    confidence_level REAL NOT NULL,
                    metadata TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_recipient_capabilities_expires_at 
                ON recipient_capabilities(expires_at);

                CREATE INDEX IF NOT EXISTS idx_recipient_capabilities_updated_at 
                ON recipient_capabilities(updated_at);

                CREATE INDEX IF NOT EXISTS idx_recipient_capabilities_source 
                ON recipient_capabilities(source);";

            using var command = new SQLiteCommand(createTableSql, connection);
            await command.ExecuteNonQueryAsync();
        }

        private RecipientCapabilities? ReadCapabilitiesFromDatabase(SQLiteDataReader reader)
        {
            try
            {
                var capabilities = new RecipientCapabilities
                {
                    EmailAddress = reader.GetString("email_address"),
                    SupportedKemAlgorithms = JsonSerializer.Deserialize<List<string>>(reader.GetString("supported_kem_algorithms")) ?? new List<string>(),
                    SupportedSignatureAlgorithms = JsonSerializer.Deserialize<List<string>>(reader.GetString("supported_signature_algorithms")) ?? new List<string>(),
                    SupportedClassicalAlgorithms = JsonSerializer.Deserialize<List<string>>(reader.GetString("supported_classical_algorithms")) ?? new List<string>(),
                    Source = Enum.Parse<CapabilitySource>(reader.GetString("source")),
                    DiscoveredAt = DateTimeOffset.Parse(reader.GetString("discovered_at")),
                    ExpiresAt = DateTimeOffset.Parse(reader.GetString("expires_at")),
                    ConfidenceLevel = reader.GetDouble("confidence_level"),
                    Metadata = JsonSerializer.Deserialize<Dictionary<string, object>>(reader.GetString("metadata")) ?? new Dictionary<string, object>()
                };

                // Parse supported modes
                var modesJson = reader.GetString("supported_modes");
                var modeStrings = JsonSerializer.Deserialize<List<string>>(modesJson) ?? new List<string>();
                capabilities.SupportedModes = modeStrings.Select(m => Enum.Parse<CryptographicMode>(m)).ToList();

                return capabilities;
            }
            catch (Exception)
            {
                // If parsing fails, return null rather than throwing
                return null;
            }
        }

        private static string NormalizeEmailAddress(string emailAddress)
        {
            return emailAddress.Trim().ToLowerInvariant();
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _connectionSemaphore?.Dispose();
                _disposed = true;
            }
        }
    }
}