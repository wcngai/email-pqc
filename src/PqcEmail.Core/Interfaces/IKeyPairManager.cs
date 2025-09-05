using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Interfaces
{
    /// <summary>
    /// Interface for managing dual keypair architecture (separate signing and encryption keys)
    /// </summary>
    public interface IKeyPairManager
    {
        /// <summary>
        /// Generates a new keypair for the specified algorithm and usage
        /// </summary>
        /// <param name="algorithm">Cryptographic algorithm (ML-KEM-768, ML-DSA-65, etc.)</param>
        /// <param name="usage">Key usage type (signing or encryption)</param>
        /// <param name="keySize">Optional key size parameter</param>
        /// <returns>Generated keypair information</returns>
        Task<KeyPairInfo> GenerateKeyPairAsync(string algorithm, KeyUsage usage, int? keySize = null);

        /// <summary>
        /// Stores a keypair securely in Windows CNG or HSM
        /// </summary>
        /// <param name="keyPair">Keypair to store</param>
        /// <param name="containerName">Key container name</param>
        /// <param name="useHsm">Whether to use HSM storage</param>
        /// <returns>Storage result with container information</returns>
        Task<KeyStorageResult> StoreKeyPairAsync(KeyPairInfo keyPair, string containerName, bool useHsm = false);

        /// <summary>
        /// Retrieves a keypair from secure storage
        /// </summary>
        /// <param name="containerName">Key container name</param>
        /// <param name="usage">Key usage type</param>
        /// <returns>Retrieved keypair or null if not found</returns>
        Task<KeyPairInfo?> RetrieveKeyPairAsync(string containerName, KeyUsage usage);

        /// <summary>
        /// Deletes a keypair from secure storage
        /// </summary>
        /// <param name="containerName">Key container name</param>
        /// <param name="usage">Key usage type</param>
        /// <returns>Deletion success status</returns>
        Task<bool> DeleteKeyPairAsync(string containerName, KeyUsage usage);

        /// <summary>
        /// Lists all stored keypairs for a specific identity
        /// </summary>
        /// <param name="identity">Identity (email address)</param>
        /// <returns>Collection of keypair metadata</returns>
        Task<IEnumerable<KeyPairInfo>> ListKeyPairsAsync(string identity);

        /// <summary>
        /// Rotates an existing keypair (creates new, marks old for archival)
        /// </summary>
        /// <param name="containerName">Current key container name</param>
        /// <param name="usage">Key usage type</param>
        /// <returns>New keypair information</returns>
        Task<KeyPairInfo> RotateKeyPairAsync(string containerName, KeyUsage usage);

        /// <summary>
        /// Archives old keypairs for historical decryption capability
        /// </summary>
        /// <param name="keyPair">Keypair to archive</param>
        /// <param name="archivalReason">Reason for archival</param>
        /// <returns>Archival operation result</returns>
        Task<KeyArchivalResult> ArchiveKeyPairAsync(KeyPairInfo keyPair, string archivalReason);

        /// <summary>
        /// Retrieves archived keypairs for historical email decryption
        /// </summary>
        /// <param name="identity">Identity (email address)</param>
        /// <param name="timeRange">Optional time range filter</param>
        /// <returns>Collection of archived keypairs</returns>
        Task<IEnumerable<KeyPairInfo>> GetArchivedKeyPairsAsync(string identity, DateTimeOffset? timeRange = null);

        /// <summary>
        /// Exports keypair to PKCS#12 format with password protection
        /// </summary>
        /// <param name="keyPair">Keypair to export</param>
        /// <param name="password">Export password</param>
        /// <returns>Encrypted PKCS#12 data</returns>
        Task<byte[]> ExportKeyPairAsync(KeyPairInfo keyPair, string password);

        /// <summary>
        /// Imports keypair from PKCS#12 format
        /// </summary>
        /// <param name="pkcs12Data">Encrypted PKCS#12 data</param>
        /// <param name="password">Import password</param>
        /// <param name="containerName">Target container name</param>
        /// <returns>Imported keypair information</returns>
        Task<KeyPairInfo> ImportKeyPairAsync(byte[] pkcs12Data, string password, string containerName);
    }
}