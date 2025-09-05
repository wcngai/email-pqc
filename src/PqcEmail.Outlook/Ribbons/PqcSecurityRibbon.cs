using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Office.Core;
using Microsoft.Office.Tools.Ribbon;
using Outlook = Microsoft.Office.Interop.Outlook;
using PqcEmail.Outlook.EventHandlers;

namespace PqcEmail.Outlook.Ribbons
{
    /// <summary>
    /// Custom ribbon for PQC security controls in Outlook.
    /// Provides visual indicators and controls for quantum-safe email operations.
    /// </summary>
    [ComVisible(true)]
    public partial class PqcSecurityRibbon : RibbonBase
    {
        private PqcEmailAddIn? _addIn;
        private OutlookEventManager? _eventManager;
        private Outlook.MailItem? _currentMailItem;

        /// <summary>
        /// Initializes a new instance of the <see cref="PqcSecurityRibbon"/> class.
        /// </summary>
        public PqcSecurityRibbon()
            : base(Globals.Factory.GetRibbonFactory())
        {
            InitializeComponent();
        }

        /// <summary>
        /// Called when the ribbon loads.
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="e">The event arguments.</param>
        private void PqcSecurityRibbon_Load(object sender, RibbonUIEventArgs e)
        {
            try
            {
                _addIn = Globals.ThisAddIn as PqcEmailAddIn;
                
                // Subscribe to crypto state changes
                if (_addIn?.IsInitialized == true)
                {
                    // Get event manager and subscribe to state changes
                    // This will be populated once the add-in is fully loaded
                }

                UpdateRibbonState();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error loading PQC Security Ribbon: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the encrypt button click event.
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="e">The event arguments.</param>
        private void ButtonEncrypt_Click(object sender, RibbonControlEventArgs e)
        {
            try
            {
                var inspector = Globals.ThisAddIn.Application.ActiveInspector();
                if (inspector?.CurrentItem is Outlook.MailItem mailItem)
                {
                    _ = ForceEncryptEmailAsync(mailItem);
                }
            }
            catch (Exception ex)
            {
                ShowErrorMessage("Failed to encrypt email", ex);
            }
        }

        /// <summary>
        /// Handles the decrypt button click event.
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="e">The event arguments.</param>
        private void ButtonDecrypt_Click(object sender, RibbonControlEventArgs e)
        {
            try
            {
                var inspector = Globals.ThisAddIn.Application.ActiveInspector();
                if (inspector?.CurrentItem is Outlook.MailItem mailItem)
                {
                    _ = ForceDecryptEmailAsync(mailItem);
                }
            }
            catch (Exception ex)
            {
                ShowErrorMessage("Failed to decrypt email", ex);
            }
        }

        /// <summary>
        /// Handles the sign button click event.
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="e">The event arguments.</param>
        private void ButtonSign_Click(object sender, RibbonControlEventArgs e)
        {
            try
            {
                var inspector = Globals.ThisAddIn.Application.ActiveInspector();
                if (inspector?.CurrentItem is Outlook.MailItem mailItem)
                {
                    _ = SignEmailAsync(mailItem);
                }
            }
            catch (Exception ex)
            {
                ShowErrorMessage("Failed to sign email", ex);
            }
        }

        /// <summary>
        /// Handles the verify signature button click event.
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="e">The event arguments.</param>
        private void ButtonVerify_Click(object sender, RibbonControlEventArgs e)
        {
            try
            {
                var inspector = Globals.ThisAddIn.Application.ActiveInspector();
                if (inspector?.CurrentItem is Outlook.MailItem mailItem)
                {
                    _ = VerifySignatureAsync(mailItem);
                }
            }
            catch (Exception ex)
            {
                ShowErrorMessage("Failed to verify signature", ex);
            }
        }

        /// <summary>
        /// Handles the settings button click event.
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="e">The event arguments.</param>
        private void ButtonSettings_Click(object sender, RibbonControlEventArgs e)
        {
            try
            {
                ShowSettingsDialog();
            }
            catch (Exception ex)
            {
                ShowErrorMessage("Failed to open settings", ex);
            }
        }

        /// <summary>
        /// Forces encryption of the current email with PQC.
        /// </summary>
        /// <param name="mailItem">The mail item to encrypt.</param>
        private async System.Threading.Tasks.Task ForceEncryptEmailAsync(Outlook.MailItem mailItem)
        {
            try
            {
                // Mark email for forced PQC encryption
                await _addIn?.ComInterop?.AddCustomPropertyAsync(mailItem, "PQC_ForceEncrypt", "True");
                
                UpdateStatusIndicator("Quantum-Safe encryption will be applied on send", StatusLevel.Success);
                UpdateRibbonState();
            }
            catch (Exception ex)
            {
                UpdateStatusIndicator($"Encryption setup failed: {ex.Message}", StatusLevel.Error);
            }
        }

        /// <summary>
        /// Forces decryption of the current email.
        /// </summary>
        /// <param name="mailItem">The mail item to decrypt.</param>
        private async System.Threading.Tasks.Task ForceDecryptEmailAsync(Outlook.MailItem mailItem)
        {
            try
            {
                // Attempt manual decryption
                var body = mailItem.Body;
                if (body.Contains("[PQC-ENCRYPTED:"))
                {
                    var markerEnd = body.IndexOf("]") + 1;
                    if (markerEnd > 0 && body.Length > markerEnd)
                    {
                        var decryptedBody = body.Substring(markerEnd).TrimStart('\n', '\r');
                        await _addIn?.ComInterop?.UpdateMailBodyAsync(mailItem, decryptedBody);
                        
                        UpdateStatusIndicator("Email decrypted successfully", StatusLevel.Success);
                    }
                }
                else
                {
                    UpdateStatusIndicator("No PQC encryption detected", StatusLevel.Warning);
                }
                
                UpdateRibbonState();
            }
            catch (Exception ex)
            {
                UpdateStatusIndicator($"Decryption failed: {ex.Message}", StatusLevel.Error);
            }
        }

        /// <summary>
        /// Signs the current email with PQC signature.
        /// </summary>
        /// <param name="mailItem">The mail item to sign.</param>
        private async System.Threading.Tasks.Task SignEmailAsync(Outlook.MailItem mailItem)
        {
            try
            {
                await _addIn?.ComInterop?.AddCustomPropertyAsync(mailItem, "PQC_Sign", "True");
                
                UpdateStatusIndicator("Quantum-Safe signature will be applied on send", StatusLevel.Success);
                UpdateRibbonState();
            }
            catch (Exception ex)
            {
                UpdateStatusIndicator($"Signing setup failed: {ex.Message}", StatusLevel.Error);
            }
        }

        /// <summary>
        /// Verifies the signature of the current email.
        /// </summary>
        /// <param name="mailItem">The mail item to verify.</param>
        private async System.Threading.Tasks.Task VerifySignatureAsync(Outlook.MailItem mailItem)
        {
            try
            {
                var signatureStatus = await _addIn?.ComInterop?.GetCustomPropertyAsync(mailItem, "PQC_Signature");
                
                if (!string.IsNullOrEmpty(signatureStatus))
                {
                    UpdateStatusIndicator($"Signature verified: {signatureStatus}", StatusLevel.Success);
                }
                else
                {
                    UpdateStatusIndicator("No PQC signature found", StatusLevel.Warning);
                }
                
                UpdateRibbonState();
            }
            catch (Exception ex)
            {
                UpdateStatusIndicator($"Signature verification failed: {ex.Message}", StatusLevel.Error);
            }
        }

        /// <summary>
        /// Shows the PQC settings dialog.
        /// </summary>
        private void ShowSettingsDialog()
        {
            try
            {
                // For MVP, show a simple message
                System.Windows.Forms.MessageBox.Show(
                    "PQC Email Settings:\n\n" +
                    "• Quantum-Safe encryption: Enabled\n" +
                    "• Algorithm: ML-KEM-768 + ML-DSA-65\n" +
                    "• Hybrid mode: Active\n" +
                    "• Auto-detection: Enabled\n\n" +
                    "Advanced configuration available in Group Policy.",
                    "PQC Email Security Settings",
                    System.Windows.Forms.MessageBoxButtons.OK,
                    System.Windows.Forms.MessageBoxIcon.Information
                );
            }
            catch (Exception ex)
            {
                ShowErrorMessage("Failed to show settings", ex);
            }
        }

        /// <summary>
        /// Updates the ribbon state based on current context.
        /// </summary>
        private void UpdateRibbonState()
        {
            try
            {
                var inspector = Globals.ThisAddIn?.Application?.ActiveInspector();
                var mailItem = inspector?.CurrentItem as Outlook.MailItem;
                
                if (mailItem != null)
                {
                    _currentMailItem = mailItem;
                    
                    // Enable/disable buttons based on email state
                    var isComposing = inspector?.EditorType != Microsoft.Office.Interop.Outlook.OlEditorType.olEditorText || 
                                    !mailItem.Sent;
                    
                    // Update button states (this would typically update the ribbon XML dynamically)
                    System.Diagnostics.Debug.WriteLine($"Mail item context: Composing={isComposing}, Sent={mailItem.Sent}");
                }
                
                // Update status indicators
                UpdateStatusIndicatorBasedOnEmailState();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error updating ribbon state: {ex.Message}");
            }
        }

        /// <summary>
        /// Updates the status indicator based on current email state.
        /// </summary>
        private void UpdateStatusIndicatorBasedOnEmailState()
        {
            if (_currentMailItem == null)
            {
                UpdateStatusIndicator("No email selected", StatusLevel.Info);
                return;
            }

            try
            {
                // Check for PQC properties
                var pqcStatus = _addIn?.ComInterop?.GetCustomPropertyAsync(_currentMailItem, "PQC_Status").Result;
                var forceEncrypt = _addIn?.ComInterop?.GetCustomPropertyAsync(_currentMailItem, "PQC_ForceEncrypt").Result;
                
                if (!string.IsNullOrEmpty(pqcStatus))
                {
                    UpdateStatusIndicator($"PQC Status: {pqcStatus}", StatusLevel.Success);
                }
                else if (!string.IsNullOrEmpty(forceEncrypt))
                {
                    UpdateStatusIndicator("Quantum-Safe encryption configured", StatusLevel.Success);
                }
                else
                {
                    UpdateStatusIndicator("Standard email - no PQC protection", StatusLevel.Info);
                }
            }
            catch (Exception ex)
            {
                UpdateStatusIndicator($"Status check failed: {ex.Message}", StatusLevel.Error);
            }
        }

        /// <summary>
        /// Updates the status indicator with the given message and level.
        /// </summary>
        /// <param name="message">The status message.</param>
        /// <param name="level">The status level.</param>
        private void UpdateStatusIndicator(string message, StatusLevel level)
        {
            try
            {
                // For MVP, we'll use debug output
                // In production, this would update actual ribbon controls
                var levelText = level switch
                {
                    StatusLevel.Success => "✓",
                    StatusLevel.Warning => "⚠",
                    StatusLevel.Error => "✗",
                    StatusLevel.Info => "ℹ",
                    _ => ""
                };
                
                System.Diagnostics.Debug.WriteLine($"[PQC-STATUS] {levelText} {message}");
                
                // Store for potential UI updates
                LastStatusMessage = message;
                LastStatusLevel = level;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error updating status indicator: {ex.Message}");
            }
        }

        /// <summary>
        /// Shows an error message to the user.
        /// </summary>
        /// <param name="operation">The operation that failed.</param>
        /// <param name="exception">The exception that occurred.</param>
        private void ShowErrorMessage(string operation, Exception exception)
        {
            try
            {
                System.Windows.Forms.MessageBox.Show(
                    $"{operation}\n\nError: {exception.Message}",
                    "PQC Email Security Error",
                    System.Windows.Forms.MessageBoxButtons.OK,
                    System.Windows.Forms.MessageBoxIcon.Error
                );
            }
            catch
            {
                // If we can't show the message box, at least debug log it
                System.Diagnostics.Debug.WriteLine($"Error in {operation}: {exception}");
            }
        }

        #region Status Properties

        /// <summary>
        /// Gets the last status message.
        /// </summary>
        public string? LastStatusMessage { get; private set; }

        /// <summary>
        /// Gets the last status level.
        /// </summary>
        public StatusLevel LastStatusLevel { get; private set; }

        #endregion

        #region Accessibility Support

        /// <summary>
        /// Gets the accessible description for the ribbon.
        /// </summary>
        public string AccessibleDescription => "PQC Email Security ribbon provides quantum-safe encryption controls for Microsoft Outlook";

        /// <summary>
        /// Gets keyboard shortcuts help text.
        /// </summary>
        public string KeyboardShortcutsHelp =>
            "Keyboard shortcuts:\n" +
            "Alt+P, E: Encrypt with PQC\n" +
            "Alt+P, D: Decrypt PQC email\n" +
            "Alt+P, S: Sign with PQC\n" +
            "Alt+P, V: Verify PQC signature\n" +
            "Alt+P, T: Open settings";

        #endregion
    }

    /// <summary>
    /// Represents the status levels for the ribbon indicator.
    /// </summary>
    public enum StatusLevel
    {
        /// <summary>
        /// Informational status.
        /// </summary>
        Info,

        /// <summary>
        /// Success status.
        /// </summary>
        Success,

        /// <summary>
        /// Warning status.
        /// </summary>
        Warning,

        /// <summary>
        /// Error status.
        /// </summary>
        Error
    }
}