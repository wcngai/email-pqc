using System;
using System.Drawing;
using System.Windows.Forms;
using PqcEmail.Core.Models;

namespace PqcEmail.Outlook.Forms
{
    /// <summary>
    /// Configuration form for PQC email settings.
    /// Provides user interface for managing post-quantum cryptography preferences.
    /// </summary>
    public partial class PqcSettingsForm : Form
    {
        private readonly PqcSettings _settings;
        private bool _hasChanges = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="PqcSettingsForm"/> class.
        /// </summary>
        /// <param name="currentSettings">The current PQC settings.</param>
        public PqcSettingsForm(PqcSettings currentSettings)
        {
            _settings = currentSettings ?? new PqcSettings();
            InitializeComponent();
            LoadSettings();
            this.FormClosing += PqcSettingsForm_FormClosing;
        }

        /// <summary>
        /// Gets the updated settings after user modifications.
        /// </summary>
        public PqcSettings UpdatedSettings => _settings;

        /// <summary>
        /// Gets a value indicating whether settings were changed by the user.
        /// </summary>
        public bool HasChanges => _hasChanges;

        /// <summary>
        /// Loads current settings into the form controls.
        /// </summary>
        private void LoadSettings()
        {
            try
            {
                // Encryption Strategy
                comboEncryptionStrategy.Items.Clear();
                comboEncryptionStrategy.Items.AddRange(new object[]
                {
                    "Auto - Detect recipient capabilities",
                    "Hybrid - PQC + Classical (Recommended)",
                    "Post-Quantum Only - Maximum security",
                    "Classical Only - Legacy compatibility"
                });

                comboEncryptionStrategy.SelectedIndex = _settings.DefaultEncryptionStrategy switch
                {
                    EncryptionStrategy.Auto => 0,
                    EncryptionStrategy.Hybrid => 1,
                    EncryptionStrategy.PostQuantumOnly => 2,
                    EncryptionStrategy.ClassicalOnly => 3,
                    _ => 1 // Default to Hybrid
                };

                // Algorithm Preferences
                checkEnableHybrid.Checked = _settings.EnableHybridMode;
                checkAutoDetectCapabilities.Checked = _settings.AutoDetectRecipientCapabilities;
                checkRequirePqcForInternal.Checked = _settings.RequirePqcForInternalEmails;

                // Visual Indicators
                checkShowSecurityBadges.Checked = _settings.ShowSecurityBadges;
                checkShowEncryptionStatus.Checked = _settings.ShowEncryptionStatusInSubject;
                comboIndicatorStyle.SelectedIndex = (int)_settings.SecurityIndicatorStyle;

                // Performance Settings
                numericCacheTimeout.Value = Math.Min(Math.Max(_settings.CapabilityCacheTimeoutMinutes, 1), 1440);
                checkEnableBackgroundProcessing.Checked = _settings.EnableBackgroundProcessing;

                // Advanced Options
                textInternalDomains.Text = string.Join(", ", _settings.InternalDomains);
                checkEnableLogging.Checked = _settings.EnableDetailedLogging;
                checkForceValidation.Checked = _settings.ForceSignatureValidation;

                _hasChanges = false;
            }
            catch (Exception ex)
            {
                ShowError("Failed to load settings", ex);
            }
        }

        /// <summary>
        /// Saves form settings to the settings object.
        /// </summary>
        private void SaveSettings()
        {
            try
            {
                // Encryption Strategy
                _settings.DefaultEncryptionStrategy = comboEncryptionStrategy.SelectedIndex switch
                {
                    0 => EncryptionStrategy.Auto,
                    1 => EncryptionStrategy.Hybrid,
                    2 => EncryptionStrategy.PostQuantumOnly,
                    3 => EncryptionStrategy.ClassicalOnly,
                    _ => EncryptionStrategy.Hybrid
                };

                // Algorithm Preferences
                _settings.EnableHybridMode = checkEnableHybrid.Checked;
                _settings.AutoDetectRecipientCapabilities = checkAutoDetectCapabilities.Checked;
                _settings.RequirePqcForInternalEmails = checkRequirePqcForInternal.Checked;

                // Visual Indicators
                _settings.ShowSecurityBadges = checkShowSecurityBadges.Checked;
                _settings.ShowEncryptionStatusInSubject = checkShowEncryptionStatus.Checked;
                _settings.SecurityIndicatorStyle = (SecurityIndicatorStyle)comboIndicatorStyle.SelectedIndex;

                // Performance Settings
                _settings.CapabilityCacheTimeoutMinutes = (int)numericCacheTimeout.Value;
                _settings.EnableBackgroundProcessing = checkEnableBackgroundProcessing.Checked;

                // Advanced Options
                var domains = textInternalDomains.Text.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
                _settings.InternalDomains = Array.ConvertAll(domains, d => d.Trim());
                _settings.EnableDetailedLogging = checkEnableLogging.Checked;
                _settings.ForceSignatureValidation = checkForceValidation.Checked;

                _hasChanges = true;
            }
            catch (Exception ex)
            {
                ShowError("Failed to save settings", ex);
            }
        }

        /// <summary>
        /// Handles the OK button click.
        /// </summary>
        private void ButtonOk_Click(object sender, EventArgs e)
        {
            if (ValidateSettings())
            {
                SaveSettings();
                this.DialogResult = DialogResult.OK;
                this.Close();
            }
        }

        /// <summary>
        /// Handles the Cancel button click.
        /// </summary>
        private void ButtonCancel_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.Cancel;
            this.Close();
        }

        /// <summary>
        /// Handles the Reset to Defaults button click.
        /// </summary>
        private void ButtonDefaults_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show(
                "Reset all settings to default values?\n\nThis will undo any customizations you have made.",
                "Reset to Defaults",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question) == DialogResult.Yes)
            {
                var defaultSettings = new PqcSettings();
                _settings.CopyFrom(defaultSettings);
                LoadSettings();
            }
        }

        /// <summary>
        /// Handles form closing event to warn about unsaved changes.
        /// </summary>
        private void PqcSettingsForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (this.DialogResult == DialogResult.None && HasUnsavedChanges())
            {
                var result = MessageBox.Show(
                    "You have unsaved changes. Do you want to save them before closing?",
                    "Unsaved Changes",
                    MessageBoxButtons.YesNoCancel,
                    MessageBoxIcon.Question);

                switch (result)
                {
                    case DialogResult.Yes:
                        if (ValidateSettings())
                        {
                            SaveSettings();
                            this.DialogResult = DialogResult.OK;
                        }
                        else
                        {
                            e.Cancel = true;
                        }
                        break;
                    case DialogResult.Cancel:
                        e.Cancel = true;
                        break;
                    // DialogResult.No - continue closing without saving
                }
            }
        }

        /// <summary>
        /// Validates the current form settings.
        /// </summary>
        /// <returns>True if settings are valid, false otherwise.</returns>
        private bool ValidateSettings()
        {
            try
            {
                // Validate internal domains
                var domains = textInternalDomains.Text.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var domain in domains)
                {
                    var trimmedDomain = domain.Trim();
                    if (!IsValidDomainName(trimmedDomain))
                    {
                        ShowError($"Invalid domain name: {trimmedDomain}", null);
                        textInternalDomains.Focus();
                        return false;
                    }
                }

                // Validate cache timeout
                if (numericCacheTimeout.Value < 1 || numericCacheTimeout.Value > 1440)
                {
                    ShowError("Cache timeout must be between 1 and 1440 minutes.", null);
                    numericCacheTimeout.Focus();
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                ShowError("Validation failed", ex);
                return false;
            }
        }

        /// <summary>
        /// Checks if there are unsaved changes in the form.
        /// </summary>
        /// <returns>True if there are unsaved changes, false otherwise.</returns>
        private bool HasUnsavedChanges()
        {
            // Simple check - in production this would be more sophisticated
            return true; // For MVP, always prompt to be safe
        }

        /// <summary>
        /// Validates a domain name format.
        /// </summary>
        /// <param name="domain">The domain name to validate.</param>
        /// <returns>True if the domain name is valid, false otherwise.</returns>
        private bool IsValidDomainName(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return false;

            try
            {
                // Basic domain name validation
                var parts = domain.Split('.');
                if (parts.Length < 2)
                    return false;

                foreach (var part in parts)
                {
                    if (string.IsNullOrEmpty(part) || part.Length > 63)
                        return false;

                    foreach (var c in part)
                    {
                        if (!char.IsLetterOrDigit(c) && c != '-')
                            return false;
                    }

                    if (part.StartsWith("-") || part.EndsWith("-"))
                        return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Shows an error message to the user.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="exception">Optional exception details.</param>
        private void ShowError(string message, Exception? exception)
        {
            var fullMessage = exception != null ? $"{message}\n\nDetails: {exception.Message}" : message;
            
            MessageBox.Show(
                fullMessage,
                "PQC Settings Error",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }

        /// <summary>
        /// Handles help button click.
        /// </summary>
        private void ButtonHelp_Click(object sender, EventArgs e)
        {
            var helpText = 
                "PQC Email Settings Help\n\n" +
                
                "Encryption Strategy:\n" +
                "• Auto: Automatically selects the best encryption method based on recipient capabilities\n" +
                "• Hybrid: Uses both post-quantum and classical encryption (recommended)\n" +
                "• Post-Quantum Only: Maximum security but may not be compatible with all recipients\n" +
                "• Classical Only: Legacy mode for compatibility\n\n" +
                
                "Algorithm Preferences:\n" +
                "• Hybrid Mode: Enables dual-encryption with PQC and classical algorithms\n" +
                "• Auto-Detect Capabilities: Automatically determines what recipients support\n" +
                "• Require PQC for Internal: Forces quantum-safe encryption for internal emails\n\n" +
                
                "Visual Indicators:\n" +
                "• Security Badges: Shows encryption status icons in the ribbon\n" +
                "• Subject Line Status: Adds encryption indicators to email subjects\n" +
                "• Indicator Style: Choose how security status is displayed\n\n" +
                
                "Performance:\n" +
                "• Cache Timeout: How long to remember recipient capabilities (1-1440 minutes)\n" +
                "• Background Processing: Enables asynchronous encryption operations\n\n" +
                
                "Advanced Options:\n" +
                "• Internal Domains: Domains considered internal (comma-separated)\n" +
                "• Detailed Logging: Enables comprehensive audit logs\n" +
                "• Force Validation: Always validate signatures even if sender is trusted";

            MessageBox.Show(
                helpText,
                "PQC Settings Help",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        #region Control Declarations
        // These would normally be generated by Visual Studio designer
        
        private ComboBox comboEncryptionStrategy = new ComboBox();
        private CheckBox checkEnableHybrid = new CheckBox();
        private CheckBox checkAutoDetectCapabilities = new CheckBox();
        private CheckBox checkRequirePqcForInternal = new CheckBox();
        private CheckBox checkShowSecurityBadges = new CheckBox();
        private CheckBox checkShowEncryptionStatus = new CheckBox();
        private ComboBox comboIndicatorStyle = new ComboBox();
        private NumericUpDown numericCacheTimeout = new NumericUpDown();
        private CheckBox checkEnableBackgroundProcessing = new CheckBox();
        private TextBox textInternalDomains = new TextBox();
        private CheckBox checkEnableLogging = new CheckBox();
        private CheckBox checkForceValidation = new CheckBox();

        #endregion
    }

    /// <summary>
    /// Configuration settings for PQC email operations.
    /// </summary>
    public class PqcSettings
    {
        public EncryptionStrategy DefaultEncryptionStrategy { get; set; } = EncryptionStrategy.Hybrid;
        public bool EnableHybridMode { get; set; } = true;
        public bool AutoDetectRecipientCapabilities { get; set; } = true;
        public bool RequirePqcForInternalEmails { get; set; } = true;
        public bool ShowSecurityBadges { get; set; } = true;
        public bool ShowEncryptionStatusInSubject { get; set; } = false;
        public SecurityIndicatorStyle SecurityIndicatorStyle { get; set; } = SecurityIndicatorStyle.IconAndText;
        public int CapabilityCacheTimeoutMinutes { get; set; } = 60;
        public bool EnableBackgroundProcessing { get; set; } = true;
        public string[] InternalDomains { get; set; } = new[] { "company.com" };
        public bool EnableDetailedLogging { get; set; } = false;
        public bool ForceSignatureValidation { get; set; } = true;

        /// <summary>
        /// Copies settings from another instance.
        /// </summary>
        /// <param name="other">The other settings instance.</param>
        public void CopyFrom(PqcSettings other)
        {
            if (other == null) return;

            DefaultEncryptionStrategy = other.DefaultEncryptionStrategy;
            EnableHybridMode = other.EnableHybridMode;
            AutoDetectRecipientCapabilities = other.AutoDetectRecipientCapabilities;
            RequirePqcForInternalEmails = other.RequirePqcForInternalEmails;
            ShowSecurityBadges = other.ShowSecurityBadges;
            ShowEncryptionStatusInSubject = other.ShowEncryptionStatusInSubject;
            SecurityIndicatorStyle = other.SecurityIndicatorStyle;
            CapabilityCacheTimeoutMinutes = other.CapabilityCacheTimeoutMinutes;
            EnableBackgroundProcessing = other.EnableBackgroundProcessing;
            InternalDomains = (string[])other.InternalDomains.Clone();
            EnableDetailedLogging = other.EnableDetailedLogging;
            ForceSignatureValidation = other.ForceSignatureValidation;
        }
    }

    /// <summary>
    /// Defines the styles for security indicators.
    /// </summary>
    public enum SecurityIndicatorStyle
    {
        /// <summary>
        /// Show icon only.
        /// </summary>
        IconOnly,

        /// <summary>
        /// Show text only.
        /// </summary>
        TextOnly,

        /// <summary>
        /// Show both icon and text.
        /// </summary>
        IconAndText,

        /// <summary>
        /// Minimal indicators.
        /// </summary>
        Minimal
    }
}