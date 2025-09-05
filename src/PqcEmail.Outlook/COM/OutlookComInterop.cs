using System;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;
using Outlook = Microsoft.Office.Interop.Outlook;
using PqcEmail.Core.Models;

namespace PqcEmail.Outlook.COM
{
    /// <summary>
    /// Provides COM interop functionality for accessing Outlook's native object model.
    /// This class handles thread-safe operations and manages COM object lifecycle.
    /// </summary>
    public class OutlookComInterop : IDisposable
    {
        private readonly Outlook.Application _outlookApp;
        private readonly object _lockObject = new object();
        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="OutlookComInterop"/> class.
        /// </summary>
        /// <param name="outlookApplication">The Outlook application instance.</param>
        public OutlookComInterop(Outlook.Application outlookApplication)
        {
            _outlookApp = outlookApplication ?? throw new ArgumentNullException(nameof(outlookApplication));
        }

        /// <summary>
        /// Initializes the COM interop layer asynchronously.
        /// </summary>
        /// <returns>A task representing the asynchronous initialization operation.</returns>
        public async Task InitializeAsync()
        {
            await Task.Run(() =>
            {
                // Ensure Outlook is ready for COM operations
                lock (_lockObject)
                {
                    try
                    {
                        // Test basic COM access
                        var version = _outlookApp.Version;
                        System.Diagnostics.Debug.WriteLine($"Outlook version: {version}");
                    }
                    catch (COMException ex)
                    {
                        throw new InvalidOperationException("Failed to initialize COM interop with Outlook", ex);
                    }
                }
            });
        }

        /// <summary>
        /// Gets a mail item by its Entry ID safely.
        /// </summary>
        /// <param name="entryId">The entry ID of the mail item.</param>
        /// <returns>The mail item, or null if not found.</returns>
        public async Task<Outlook.MailItem?> GetMailItemByEntryIdAsync(string entryId)
        {
            if (string.IsNullOrEmpty(entryId))
                return null;

            return await Task.Run(() =>
            {
                lock (_lockObject)
                {
                    try
                    {
                        var item = _outlookApp.Session.GetItemFromID(entryId) as Outlook.MailItem;
                        return item;
                    }
                    catch (COMException)
                    {
                        return null;
                    }
                }
            });
        }

        /// <summary>
        /// Gets the current active inspector (email compose/read window).
        /// </summary>
        /// <returns>The active inspector, or null if none is active.</returns>
        public async Task<Outlook.Inspector?> GetActiveInspectorAsync()
        {
            return await Task.Run(() =>
            {
                lock (_lockObject)
                {
                    try
                    {
                        return _outlookApp.ActiveInspector();
                    }
                    catch (COMException)
                    {
                        return null;
                    }
                }
            });
        }

        /// <summary>
        /// Gets the mail item from an inspector window.
        /// </summary>
        /// <param name="inspector">The inspector window.</param>
        /// <returns>The mail item, or null if not a mail item.</returns>
        public async Task<Outlook.MailItem?> GetMailItemFromInspectorAsync(Outlook.Inspector inspector)
        {
            if (inspector == null)
                return null;

            return await Task.Run(() =>
            {
                lock (_lockObject)
                {
                    try
                    {
                        return inspector.CurrentItem as Outlook.MailItem;
                    }
                    catch (COMException)
                    {
                        return null;
                    }
                }
            });
        }

        /// <summary>
        /// Safely adds a custom property to a mail item for PQC metadata.
        /// </summary>
        /// <param name="mailItem">The mail item to modify.</param>
        /// <param name="propertyName">The name of the custom property.</param>
        /// <param name="propertyValue">The value of the custom property.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task AddCustomPropertyAsync(Outlook.MailItem mailItem, string propertyName, string propertyValue)
        {
            if (mailItem == null || string.IsNullOrEmpty(propertyName))
                return;

            await Task.Run(() =>
            {
                lock (_lockObject)
                {
                    try
                    {
                        var properties = mailItem.UserProperties;
                        var property = properties.Find(propertyName);
                        
                        if (property == null)
                        {
                            property = properties.Add(propertyName, Outlook.OlUserPropertyType.olText);
                        }
                        
                        property.Value = propertyValue ?? string.Empty;
                        
                        // Release COM objects
                        if (property != null) Marshal.ReleaseComObject(property);
                        if (properties != null) Marshal.ReleaseComObject(properties);
                    }
                    catch (COMException ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Failed to add custom property '{propertyName}': {ex.Message}");
                    }
                }
            });
        }

        /// <summary>
        /// Safely gets a custom property from a mail item.
        /// </summary>
        /// <param name="mailItem">The mail item to read from.</param>
        /// <param name="propertyName">The name of the custom property.</param>
        /// <returns>The property value, or null if not found.</returns>
        public async Task<string?> GetCustomPropertyAsync(Outlook.MailItem mailItem, string propertyName)
        {
            if (mailItem == null || string.IsNullOrEmpty(propertyName))
                return null;

            return await Task.Run(() =>
            {
                lock (_lockObject)
                {
                    try
                    {
                        var properties = mailItem.UserProperties;
                        var property = properties.Find(propertyName);
                        
                        var value = property?.Value as string;
                        
                        // Release COM objects
                        if (property != null) Marshal.ReleaseComObject(property);
                        if (properties != null) Marshal.ReleaseComObject(properties);
                        
                        return value;
                    }
                    catch (COMException)
                    {
                        return null;
                    }
                }
            });
        }

        /// <summary>
        /// Gets all recipients of a mail item safely.
        /// </summary>
        /// <param name="mailItem">The mail item to analyze.</param>
        /// <returns>A list of recipient email addresses.</returns>
        public async Task<List<string>> GetRecipientsAsync(Outlook.MailItem mailItem)
        {
            if (mailItem == null)
                return new List<string>();

            return await Task.Run(() =>
            {
                var recipients = new List<string>();
                
                lock (_lockObject)
                {
                    try
                    {
                        var outlookRecipients = mailItem.Recipients;
                        
                        for (int i = 1; i <= outlookRecipients.Count; i++)
                        {
                            var recipient = outlookRecipients[i];
                            try
                            {
                                var address = GetRecipientSmtpAddress(recipient);
                                if (!string.IsNullOrEmpty(address))
                                {
                                    recipients.Add(address);
                                }
                            }
                            finally
                            {
                                if (recipient != null) Marshal.ReleaseComObject(recipient);
                            }
                        }
                        
                        if (outlookRecipients != null) Marshal.ReleaseComObject(outlookRecipients);
                    }
                    catch (COMException ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Failed to get recipients: {ex.Message}");
                    }
                }
                
                return recipients;
            });
        }

        /// <summary>
        /// Gets the SMTP address from a recipient object.
        /// </summary>
        /// <param name="recipient">The recipient object.</param>
        /// <returns>The SMTP address, or null if not available.</returns>
        private string? GetRecipientSmtpAddress(Outlook.Recipient recipient)
        {
            try
            {
                if (recipient.AddressEntry?.Type == "SMTP")
                {
                    return recipient.AddressEntry.Address;
                }
                
                // Try to resolve Exchange address to SMTP
                var exchangeUser = recipient.AddressEntry?.GetExchangeUser();
                if (exchangeUser != null)
                {
                    var smtpAddress = exchangeUser.PrimarySmtpAddress;
                    if (exchangeUser != null) Marshal.ReleaseComObject(exchangeUser);
                    return smtpAddress;
                }
                
                return recipient.Address;
            }
            catch (COMException)
            {
                return recipient.Address;
            }
        }

        /// <summary>
        /// Safely updates the body of a mail item.
        /// This is used for adding/removing PQC encryption.
        /// </summary>
        /// <param name="mailItem">The mail item to modify.</param>
        /// <param name="newBody">The new body content.</param>
        /// <param name="bodyFormat">The body format (HTML, RTF, or Plain Text).</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task UpdateMailBodyAsync(Outlook.MailItem mailItem, string newBody, Outlook.OlBodyFormat bodyFormat = Outlook.OlBodyFormat.olFormatHTML)
        {
            if (mailItem == null)
                return;

            await Task.Run(() =>
            {
                lock (_lockObject)
                {
                    try
                    {
                        mailItem.BodyFormat = bodyFormat;
                        
                        switch (bodyFormat)
                        {
                            case Outlook.OlBodyFormat.olFormatHTML:
                                mailItem.HTMLBody = newBody ?? string.Empty;
                                break;
                            case Outlook.OlBodyFormat.olFormatRTF:
                                mailItem.RTFBody = System.Text.Encoding.UTF8.GetBytes(newBody ?? string.Empty);
                                break;
                            default:
                                mailItem.Body = newBody ?? string.Empty;
                                break;
                        }
                    }
                    catch (COMException ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Failed to update mail body: {ex.Message}");
                    }
                }
            });
        }

        /// <summary>
        /// Thread-safe disposal of COM objects.
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
                    lock (_lockObject)
                    {
                        // Cleanup managed resources
                        // Note: We don't release _outlookApp as it's owned by the VSTO runtime
                    }
                }
                
                _disposed = true;
            }
        }
    }
}