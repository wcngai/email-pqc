using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Interfaces
{
    /// <summary>
    /// Interface for certificate enrollment and renewal operations
    /// </summary>
    public interface ICertificateEnrollmentService
    {
        /// <summary>
        /// Generates a self-signed certificate for development/testing
        /// </summary>
        /// <param name="subject">Certificate subject information</param>
        /// <param name="keyPair">Associated keypair</param>
        /// <param name="validityPeriod">Certificate validity period</param>
        /// <returns>Generated self-signed certificate</returns>
        Task<X509Certificate2> GenerateSelfSignedCertificateAsync(X500DistinguishedName subject, KeyPairInfo keyPair, TimeSpan validityPeriod);

        /// <summary>
        /// Creates a certificate signing request (CSR) for CA enrollment
        /// </summary>
        /// <param name="subject">Certificate subject information</param>
        /// <param name="keyPair">Associated keypair</param>
        /// <param name="extensions">Optional certificate extensions</param>
        /// <returns>PKCS#10 certificate request</returns>
        Task<CertificateRequest> CreateCertificateRequestAsync(X500DistinguishedName subject, KeyPairInfo keyPair, X509ExtensionCollection? extensions = null);

        /// <summary>
        /// Submits certificate request to Microsoft Certificate Services
        /// </summary>
        /// <param name="certificateRequest">CSR to submit</param>
        /// <param name="caServerName">CA server name</param>
        /// <param name="templateName">Certificate template name</param>
        /// <returns>Enrollment result with certificate or request ID</returns>
        Task<EnrollmentResult> SubmitToMicrosoftCAAsync(CertificateRequest certificateRequest, string caServerName, string templateName);

        /// <summary>
        /// Submits certificate request to third-party CA
        /// </summary>
        /// <param name="certificateRequest">CSR to submit</param>
        /// <param name="caEndpoint">CA API endpoint</param>
        /// <param name="credentials">CA authentication credentials</param>
        /// <returns>Enrollment result</returns>
        Task<EnrollmentResult> SubmitToThirdPartyCAAsync(CertificateRequest certificateRequest, string caEndpoint, CaCredentials credentials);

        /// <summary>
        /// Retrieves a certificate from pending enrollment
        /// </summary>
        /// <param name="requestId">Request ID from enrollment</param>
        /// <param name="caServerName">CA server name</param>
        /// <returns>Retrieved certificate or null if still pending</returns>
        Task<X509Certificate2?> RetrieveCertificateAsync(string requestId, string caServerName);

        /// <summary>
        /// Checks if a certificate needs renewal
        /// </summary>
        /// <param name="certificate">Certificate to check</param>
        /// <param name="renewalThresholdDays">Days before expiration to renew</param>
        /// <returns>True if renewal is needed</returns>
        bool ShouldRenewCertificate(X509Certificate2 certificate, int renewalThresholdDays = 30);

        /// <summary>
        /// Initiates certificate renewal process
        /// </summary>
        /// <param name="existingCertificate">Certificate to renew</param>
        /// <param name="reuseKeyPair">Whether to reuse existing keypair</param>
        /// <returns>Renewal result</returns>
        Task<EnrollmentResult> RenewCertificateAsync(X509Certificate2 existingCertificate, bool reuseKeyPair = false);

        /// <summary>
        /// Revokes a certificate through the issuing CA
        /// </summary>
        /// <param name="certificate">Certificate to revoke</param>
        /// <param name="reason">Revocation reason</param>
        /// <returns>Revocation operation result</returns>
        Task<RevocationResult> RevokeCertificateAsync(X509Certificate2 certificate, CrlReason reason);

        /// <summary>
        /// Validates certificate enrollment configuration
        /// </summary>
        /// <param name="caServerName">CA server name</param>
        /// <param name="templateName">Certificate template name</param>
        /// <returns>Configuration validation result</returns>
        Task<EnrollmentConfigurationValidationResult> ValidateEnrollmentConfigurationAsync(string caServerName, string templateName);
    }
}