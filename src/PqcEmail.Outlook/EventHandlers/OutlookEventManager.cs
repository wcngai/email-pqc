using System;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using Outlook = Microsoft.Office.Interop.Outlook;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;
using PqcEmail.Outlook.COM;

namespace PqcEmail.Outlook.EventHandlers
{
    /// <summary>
    /// Manages all Outlook event handling for PQC email operations.
    /// This class coordinates email lifecycle events with cryptographic operations.
    /// </summary>
    public class OutlookEventManager : IDisposable
    {
        private readonly Outlook.Application _outlookApp;
        private readonly IHybridEncryptionEngine _encryptionEngine;
        private readonly OutlookComInterop _comInterop;
        private readonly Dictionary<string, EmailCryptoState> _emailStates = new();
        private readonly object _lockObject = new object();

        // Event handlers
        private Outlook.Inspectors? _inspectors;
        private bool _disposed = false;

        /// <summary>
        /// Event raised when the crypto state of an email changes.
        /// </summary>
        public event EventHandler<EmailCryptoStateChangedEventArgs>? CryptoStateChanged;

        /// <summary>
        /// Initializes a new instance of the <see cref="OutlookEventManager"/> class.
        /// </summary>
        /// <param name="outlookApp">The Outlook application instance.</param>
        /// <param name="encryptionEngine">The hybrid encryption engine.</param>
        /// <param name="comInterop">The COM interop helper.</param>
        public OutlookEventManager(
            Outlook.Application outlookApp,
            IHybridEncryptionEngine encryptionEngine,
            OutlookComInterop comInterop)
        {
            _outlookApp = outlookApp ?? throw new ArgumentNullException(nameof(outlookApp));
            _encryptionEngine = encryptionEngine ?? throw new ArgumentNullException(nameof(encryptionEngine));
            _comInterop = comInterop ?? throw new ArgumentNullException(nameof(comInterop));
        }

        /// <summary>
        /// Initializes the event manager and registers for Outlook events.
        /// </summary>
        /// <returns>A task representing the asynchronous initialization operation.</returns>
        public async Task InitializeAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    // Register for inspector events (compose/read windows)
                    _inspectors = _outlookApp.Inspectors;
                    _inspectors.NewInspector += OnNewInspector;

                    System.Diagnostics.Debug.WriteLine("Outlook event handlers registered successfully");
                }
                catch (COMException ex)
                {
                    throw new InvalidOperationException("Failed to register Outlook event handlers", ex);
                }
            });
        }

        /// <summary>
        /// Handles new inspector (email window) creation.
        /// </summary>
        /// <param name="inspector">The new inspector instance.</param>
        private async void OnNewInspector(Outlook.Inspector inspector)
        {
            try
            {
                var mailItem = await _comInterop.GetMailItemFromInspectorAsync(inspector);
                if (mailItem != null)
                {
                    await RegisterMailItemEventsAsync(mailItem, inspector);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error handling new inspector: {ex.Message}");
            }
        }

        /// <summary>
        /// Registers events for a specific mail item.
        /// </summary>
        /// <param name="mailItem">The mail item to monitor.</param>
        /// <param name="inspector">The associated inspector window.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task RegisterMailItemEventsAsync(Outlook.MailItem mailItem, Outlook.Inspector inspector)
        {
            try
            {
                // Create crypto state for this email
                var emailId = mailItem.EntryID ?? Guid.NewGuid().ToString();
                var cryptoState = new EmailCryptoState(emailId, EmailCryptoStatus.Analyzing);
                
                lock (_lockObject)
                {
                    _emailStates[emailId] = cryptoState;
                }

                // Register for mail item events
                mailItem.Send += async (ref bool cancel) => await OnMailItemSendAsync(mailItem, ref cancel);
                mailItem.Open += async (ref bool cancel) => await OnMailItemOpenAsync(mailItem, ref cancel);
                mailItem.BeforeRead += () => _ = OnMailItemBeforeReadAsync(mailItem);
                mailItem.Write += async (ref bool cancel) => await OnMailItemWriteAsync(mailItem, ref cancel);

                // Analyze current state
                await AnalyzeEmailCryptoStateAsync(mailItem);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error registering mail item events: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the Send event for mail items.
        /// This is where we intercept outgoing emails for encryption.
        /// </summary>
        /// <param name="mailItem">The mail item being sent.</param>
        /// <param name="cancel">Reference to the cancellation flag.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task OnMailItemSendAsync(Outlook.MailItem mailItem, ref bool cancel)
        {
            try
            {
                var emailId = mailItem.EntryID ?? Guid.NewGuid().ToString();
                await UpdateCryptoStateAsync(emailId, EmailCryptoStatus.Encrypting);

                // Get recipients and determine encryption strategy
                var recipients = await _comInterop.GetRecipientsAsync(mailItem);
                var recipientCapabilities = await DetermineRecipientCapabilitiesAsync(recipients);

                // Encrypt the email if needed
                var strategy = _encryptionEngine.DetermineEncryptionStrategy(recipientCapabilities);
                
                if (strategy != EncryptionStrategy.ClassicalOnly)
                {
                    var success = await EncryptOutgoingEmailAsync(mailItem, recipientCapabilities, strategy);
                    if (!success)
                    {
                        cancel = true;
                        await UpdateCryptoStateAsync(emailId, EmailCryptoStatus.Error, "Encryption failed");
                        return;
                    }
                }

                await UpdateCryptoStateAsync(emailId, EmailCryptoStatus.Encrypted);
                await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_Status", "Encrypted");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error during email send: {ex.Message}");
                cancel = true;
                
                var emailId = mailItem.EntryID ?? Guid.NewGuid().ToString();
                await UpdateCryptoStateAsync(emailId, EmailCryptoStatus.Error, ex.Message);
            }
        }

        /// <summary>
        /// Handles the Open event for mail items.
        /// This is where we decrypt incoming emails.
        /// </summary>
        /// <param name="mailItem">The mail item being opened.</param>
        /// <param name="cancel">Reference to the cancellation flag.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task OnMailItemOpenAsync(Outlook.MailItem mailItem, ref bool cancel)
        {
            try
            {
                var emailId = mailItem.EntryID ?? Guid.NewGuid().ToString();
                
                // Check if this email is PQC encrypted
                var pqcStatus = await _comInterop.GetCustomPropertyAsync(mailItem, "PQC_Status");
                
                if (!string.IsNullOrEmpty(pqcStatus))
                {
                    await UpdateCryptoStateAsync(emailId, EmailCryptoStatus.Decrypting);
                    
                    var success = await DecryptIncomingEmailAsync(mailItem);
                    if (success)
                    {
                        await UpdateCryptoStateAsync(emailId, EmailCryptoStatus.Decrypted);
                    }
                    else
                    {
                        await UpdateCryptoStateAsync(emailId, EmailCryptoStatus.Error, "Decryption failed");
                    }
                }
                else
                {
                    await UpdateCryptoStateAsync(emailId, EmailCryptoStatus.Unencrypted);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error during email open: {ex.Message}");
                
                var emailId = mailItem.EntryID ?? Guid.NewGuid().ToString();
                await UpdateCryptoStateAsync(emailId, EmailCryptoStatus.Error, ex.Message);
            }
        }

        /// <summary>
        /// Handles the BeforeRead event for mail items.
        /// </summary>
        /// <param name="mailItem">The mail item being read.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task OnMailItemBeforeReadAsync(Outlook.MailItem mailItem)
        {
            await AnalyzeEmailCryptoStateAsync(mailItem);
        }

        /// <summary>
        /// Handles the Write event for mail items (during composition).
        /// </summary>
        /// <param name="mailItem">The mail item being written.</param>
        /// <param name="cancel">Reference to the cancellation flag.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task OnMailItemWriteAsync(Outlook.MailItem mailItem, ref bool cancel)
        {
            try
            {
                // Update crypto state as user composes
                await AnalyzeEmailCryptoStateAsync(mailItem);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error during email write: {ex.Message}");
            }
        }

        /// <summary>
        /// Analyzes the cryptographic state of an email.
        /// </summary>
        /// <param name="mailItem">The mail item to analyze.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task AnalyzeEmailCryptoStateAsync(Outlook.MailItem mailItem)
        {
            try
            {
                var emailId = mailItem.EntryID ?? Guid.NewGuid().ToString();
                var recipients = await _comInterop.GetRecipientsAsync(mailItem);
                
                var status = EmailCryptoStatus.Unencrypted;
                var details = "Standard email - no encryption";

                if (recipients.Any())
                {
                    var capabilities = await DetermineRecipientCapabilitiesAsync(recipients);
                    var strategy = _encryptionEngine.DetermineEncryptionStrategy(capabilities);
                    
                    switch (strategy)
                    {
                        case EncryptionStrategy.Hybrid:
                            status = EmailCryptoStatus.QuantumSafeReady;
                            details = "Ready for quantum-safe encryption";
                            break;
                        case EncryptionStrategy.PostQuantumOnly:
                            status = EmailCryptoStatus.QuantumSafeReady;
                            details = "Ready for post-quantum encryption";
                            break;
                        case EncryptionStrategy.ClassicalOnly:
                            status = EmailCryptoStatus.ClassicalEncryption;
                            details = "Classical encryption only";
                            break;
                    }
                }

                await UpdateCryptoStateAsync(emailId, status, details);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error analyzing crypto state: {ex.Message}");
            }
        }

        /// <summary>
        /// Determines the cryptographic capabilities of recipients.
        /// </summary>
        /// <param name="recipients">The list of recipient email addresses.</param>
        /// <returns>The combined recipient capabilities.</returns>
        private async Task<RecipientCapabilities> DetermineRecipientCapabilitiesAsync(List<string> recipients)
        {
            // For MVP, assume all internal recipients support PQC
            // In production, this would query a capability discovery service
            
            await Task.Delay(10); // Simulate async operation
            
            var internalDomains = new[] { "company.com", "internal.org" }; // TODO: Configure
            var hasInternalRecipients = recipients.Any(r => internalDomains.Any(d => r.EndsWith(d, StringComparison.OrdinalIgnoreCase)));
            
            return new RecipientCapabilities(
                supportsPostQuantum: hasInternalRecipients,
                supportedPqcKemAlgorithms: hasInternalRecipients ? new[] { "ML-KEM-768" } : new string[0],
                supportedPqcSignatureAlgorithms: hasInternalRecipients ? new[] { "ML-DSA-65" } : new string[0],
                supportedClassicalAlgorithms: new[] { "RSA-2048", "ECDSA-P256" },
                supportsHybrid: hasInternalRecipients
            );
        }

        /// <summary>
        /// Encrypts an outgoing email using the determined strategy.
        /// </summary>
        /// <param name="mailItem">The mail item to encrypt.</param>
        /// <param name="recipientCapabilities">The recipient capabilities.</param>
        /// <param name="strategy">The encryption strategy to use.</param>
        /// <returns>True if encryption succeeded, false otherwise.</returns>
        private async Task<bool> EncryptOutgoingEmailAsync(
            Outlook.MailItem mailItem, 
            RecipientCapabilities recipientCapabilities, 
            EncryptionStrategy strategy)
        {
            try
            {
                // For MVP, this is a placeholder that adds encryption metadata
                // In production, this would integrate with the actual encryption engine
                
                var originalBody = mailItem.Body;
                var encryptedMarker = $"[PQC-ENCRYPTED:{strategy}:{DateTime.UtcNow:O}]";
                
                await _comInterop.UpdateMailBodyAsync(mailItem, $"{encryptedMarker}\n{originalBody}");
                await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_Strategy", strategy.ToString());
                
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Encryption failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Decrypts an incoming email.
        /// </summary>
        /// <param name="mailItem">The mail item to decrypt.</param>
        /// <returns>True if decryption succeeded, false otherwise.</returns>
        private async Task<bool> DecryptIncomingEmailAsync(Outlook.MailItem mailItem)
        {
            try
            {
                // For MVP, this is a placeholder that recognizes encrypted emails
                // In production, this would integrate with the actual decryption engine
                
                var body = mailItem.Body;
                if (body.Contains("[PQC-ENCRYPTED:"))
                {
                    // Simulate decryption by removing the marker
                    var markerEnd = body.IndexOf("]") + 1;
                    if (markerEnd > 0 && body.Length > markerEnd)
                    {
                        var decryptedBody = body.Substring(markerEnd).TrimStart('\n', '\r');
                        await _comInterop.UpdateMailBodyAsync(mailItem, decryptedBody);
                        await _comInterop.AddCustomPropertyAsync(mailItem, "PQC_Decrypted", "True");
                    }
                }
                
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Decryption failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Updates the cryptographic state of an email and notifies listeners.
        /// </summary>
        /// <param name="emailId">The email identifier.</param>
        /// <param name="status">The new status.</param>
        /// <param name="details">Optional details about the status.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        private async Task UpdateCryptoStateAsync(string emailId, EmailCryptoStatus status, string? details = null)
        {
            await Task.Run(() =>
            {
                lock (_lockObject)
                {
                    if (_emailStates.TryGetValue(emailId, out var state))
                    {
                        state.Status = status;
                        state.Details = details;
                        state.LastUpdated = DateTime.UtcNow;
                    }
                    else
                    {
                        _emailStates[emailId] = new EmailCryptoState(emailId, status, details);
                    }
                }

                // Notify listeners
                CryptoStateChanged?.Invoke(this, new EmailCryptoStateChangedEventArgs(emailId, status, details));
            });
        }

        /// <summary>
        /// Gets the current cryptographic state of an email.
        /// </summary>
        /// <param name="emailId">The email identifier.</param>
        /// <returns>The crypto state, or null if not found.</returns>
        public EmailCryptoState? GetEmailCryptoState(string emailId)
        {
            lock (_lockObject)
            {
                return _emailStates.TryGetValue(emailId, out var state) ? state : null;
            }
        }

        /// <summary>
        /// Disposes of managed resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Protected dispose implementation.
        /// </summary>
        /// <param name="disposing">Whether called from Dispose() method.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    try
                    {
                        // Unregister event handlers
                        if (_inspectors != null)
                        {
                            _inspectors.NewInspector -= OnNewInspector;
                            Marshal.ReleaseComObject(_inspectors);
                            _inspectors = null;
                        }

                        lock (_lockObject)
                        {
                            _emailStates.Clear();
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Error during EventManager disposal: {ex.Message}");
                    }
                }

                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Represents the cryptographic state of an email.
    /// </summary>
    public class EmailCryptoState
    {
        /// <summary>
        /// Gets the email identifier.
        /// </summary>
        public string EmailId { get; }

        /// <summary>
        /// Gets or sets the current crypto status.
        /// </summary>
        public EmailCryptoStatus Status { get; set; }

        /// <summary>
        /// Gets or sets additional details about the status.
        /// </summary>
        public string? Details { get; set; }

        /// <summary>
        /// Gets or sets the timestamp when the state was last updated.
        /// </summary>
        public DateTime LastUpdated { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="EmailCryptoState"/> class.
        /// </summary>
        /// <param name="emailId">The email identifier.</param>
        /// <param name="status">The initial status.</param>
        /// <param name="details">Optional details.</param>
        public EmailCryptoState(string emailId, EmailCryptoStatus status, string? details = null)
        {
            EmailId = emailId;
            Status = status;
            Details = details;
            LastUpdated = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Defines the possible cryptographic states of an email.
    /// </summary>
    public enum EmailCryptoStatus
    {
        /// <summary>
        /// The email is being analyzed for crypto capabilities.
        /// </summary>
        Analyzing,

        /// <summary>
        /// The email is not encrypted.
        /// </summary>
        Unencrypted,

        /// <summary>
        /// The email is ready for quantum-safe encryption.
        /// </summary>
        QuantumSafeReady,

        /// <summary>
        /// The email will use classical encryption only.
        /// </summary>
        ClassicalEncryption,

        /// <summary>
        /// The email is being encrypted.
        /// </summary>
        Encrypting,

        /// <summary>
        /// The email has been encrypted.
        /// </summary>
        Encrypted,

        /// <summary>
        /// The email is being decrypted.
        /// </summary>
        Decrypting,

        /// <summary>
        /// The email has been decrypted.
        /// </summary>
        Decrypted,

        /// <summary>
        /// An error occurred during cryptographic operations.
        /// </summary>
        Error
    }

    /// <summary>
    /// Event arguments for crypto state changes.
    /// </summary>
    public class EmailCryptoStateChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the email identifier.
        /// </summary>
        public string EmailId { get; }

        /// <summary>
        /// Gets the new status.
        /// </summary>
        public EmailCryptoStatus Status { get; }

        /// <summary>
        /// Gets the status details.
        /// </summary>
        public string? Details { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="EmailCryptoStateChangedEventArgs"/> class.
        /// </summary>
        /// <param name="emailId">The email identifier.</param>
        /// <param name="status">The new status.</param>
        /// <param name="details">Optional status details.</param>
        public EmailCryptoStateChangedEventArgs(string emailId, EmailCryptoStatus status, string? details = null)
        {
            EmailId = emailId;
            Status = status;
            Details = details;
        }
    }
}