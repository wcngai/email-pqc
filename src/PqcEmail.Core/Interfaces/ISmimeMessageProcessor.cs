using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Interfaces
{
    /// <summary>
    /// Defines the contract for S/MIME message processing operations.
    /// </summary>
    public interface ISmimeMessageProcessor
    {
        /// <summary>
        /// Encrypts an email message using S/MIME with hybrid algorithms.
        /// </summary>
        /// <param name="message">The email message to encrypt</param>
        /// <param name="recipients">The recipient information with their capabilities</param>
        /// <returns>A task that represents the asynchronous S/MIME encryption operation</returns>
        Task<CryptographicResult<SmimeEncryptedMessage>> EncryptMessageAsync(
            EmailMessage message, 
            IEnumerable<SmimeRecipient> recipients);

        /// <summary>
        /// Decrypts an S/MIME encrypted email message.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted S/MIME message</param>
        /// <param name="recipientPrivateKeys">The recipient's private keys for decryption</param>
        /// <returns>A task that represents the asynchronous S/MIME decryption operation</returns>
        Task<CryptographicResult<EmailMessage>> DecryptMessageAsync(
            SmimeEncryptedMessage encryptedMessage,
            SmimePrivateKeys recipientPrivateKeys);

        /// <summary>
        /// Signs an email message using S/MIME with hybrid algorithms.
        /// </summary>
        /// <param name="message">The email message to sign</param>
        /// <param name="signingKeys">The private keys for signing</param>
        /// <returns>A task that represents the asynchronous S/MIME signing operation</returns>
        Task<CryptographicResult<SmimeSignedMessage>> SignMessageAsync(
            EmailMessage message,
            SmimePrivateKeys signingKeys);

        /// <summary>
        /// Verifies the signature of an S/MIME signed message.
        /// </summary>
        /// <param name="signedMessage">The signed S/MIME message</param>
        /// <param name="senderPublicKeys">The sender's public keys for verification</param>
        /// <returns>A task that represents the asynchronous S/MIME signature verification operation</returns>
        Task<CryptographicResult<SmimeSignatureVerificationResult>> VerifySignatureAsync(
            SmimeSignedMessage signedMessage,
            SmimePublicKeys senderPublicKeys);

        /// <summary>
        /// Determines the recipient capabilities by examining their certificates.
        /// </summary>
        /// <param name="recipientCertificates">The recipient's certificates</param>
        /// <returns>The recipient's cryptographic capabilities</returns>
        RecipientCapabilities DetermineRecipientCapabilities(IEnumerable<CertificateInfo> recipientCertificates);

        /// <summary>
        /// Negotiates the optimal encryption algorithm based on all recipients' capabilities.
        /// </summary>
        /// <param name="recipients">The recipients with their capabilities</param>
        /// <returns>The negotiated encryption strategy and algorithms</returns>
        SmimeAlgorithmNegotiation NegotiateEncryptionAlgorithms(IEnumerable<SmimeRecipient> recipients);
    }

    /// <summary>
    /// Defines the contract for KEMRecipientInfo structure handling as per CMS/S/MIME 4.0.
    /// </summary>
    public interface IKemRecipientInfoProcessor
    {
        /// <summary>
        /// Creates a KEMRecipientInfo structure for a recipient using PQC algorithms.
        /// </summary>
        /// <param name="recipientCertificate">The recipient's certificate containing PQC public key</param>
        /// <param name="keyEncapsulationKey">The key encapsulation key to be wrapped</param>
        /// <param name="kemAlgorithm">The KEM algorithm to use</param>
        /// <returns>A task that represents the asynchronous KEMRecipientInfo creation</returns>
        Task<CryptographicResult<KemRecipientInfo>> CreateKemRecipientInfoAsync(
            CertificateInfo recipientCertificate,
            byte[] keyEncapsulationKey,
            string kemAlgorithm);

        /// <summary>
        /// Processes a KEMRecipientInfo structure to recover the key encapsulation key.
        /// </summary>
        /// <param name="kemRecipientInfo">The KEMRecipientInfo structure</param>
        /// <param name="recipientPrivateKey">The recipient's private key</param>
        /// <returns>A task that represents the asynchronous key recovery operation</returns>
        Task<CryptographicResult<byte[]>> ProcessKemRecipientInfoAsync(
            KemRecipientInfo kemRecipientInfo,
            byte[] recipientPrivateKey);

        /// <summary>
        /// Encodes a KEMRecipientInfo structure to ASN.1 DER format.
        /// </summary>
        /// <param name="kemRecipientInfo">The KEMRecipientInfo structure</param>
        /// <returns>The ASN.1 DER encoded bytes</returns>
        byte[] EncodeKemRecipientInfo(KemRecipientInfo kemRecipientInfo);

        /// <summary>
        /// Decodes a KEMRecipientInfo structure from ASN.1 DER format.
        /// </summary>
        /// <param name="encodedData">The ASN.1 DER encoded bytes</param>
        /// <returns>The decoded KEMRecipientInfo structure</returns>
        KemRecipientInfo DecodeKemRecipientInfo(byte[] encodedData);
    }
}