using System;
using System.Drawing;
using System.Windows.Forms;

namespace PqcEmail.Outlook.Forms
{
    partial class PqcSettingsForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            
            // Form setup
            this.SuspendLayout();
            this.Text = "PQC Email Security Settings";
            this.Size = new Size(600, 700);
            this.StartPosition = FormStartPosition.CenterParent;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.ShowInTaskbar = false;
            this.Font = SystemFonts.MessageBoxFont;
            this.BackColor = SystemColors.Control;
            
            // WCAG 2.1 Compliance: High contrast support
            this.ForeColor = SystemColors.ControlText;
            
            // Tab control for organizing settings
            var tabControl = new TabControl
            {
                Location = new Point(12, 12),
                Size = new Size(560, 600),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom,
                TabIndex = 0
            };
            this.Controls.Add(tabControl);

            // Tab 1: Encryption Settings
            var tabEncryption = new TabPage("Encryption");
            tabEncryption.UseVisualStyleBackColor = true;
            tabControl.TabPages.Add(tabEncryption);

            var groupEncryption = CreateGroupBox("Default Encryption Strategy", 10, 10, 520, 140, tabEncryption);
            
            var lblStrategy = CreateLabel("Encryption Strategy:", 15, 30, groupEncryption);
            lblStrategy.AccessibleDescription = "Select the default encryption strategy for outgoing emails";
            
            comboEncryptionStrategy = CreateComboBox(15, 50, 480, groupEncryption);
            comboEncryptionStrategy.DropDownStyle = ComboBoxStyle.DropDownList;
            comboEncryptionStrategy.AccessibleName = "Encryption Strategy";
            comboEncryptionStrategy.AccessibleDescription = "Choose how emails should be encrypted by default";
            
            var lblStrategyHelp = CreateHelpLabel(
                "Auto mode detects recipient capabilities automatically. Hybrid mode is recommended for maximum compatibility.",
                15, 80, 480, groupEncryption);

            checkEnableHybrid = CreateCheckBox(
                "&Hybrid Mode - Combine PQC with classical encryption",
                15, 110, 480, groupEncryption);
            checkEnableHybrid.AccessibleDescription = "Enable hybrid encryption using both post-quantum and classical algorithms";

            var groupCapabilities = CreateGroupBox("Recipient Capabilities", 10, 160, 520, 120, tabEncryption);
            
            checkAutoDetectCapabilities = CreateCheckBox(
                "&Auto-detect recipient PQC capabilities",
                15, 30, 480, groupCapabilities);
            checkAutoDetectCapabilities.AccessibleDescription = "Automatically determine what encryption methods recipients support";
            
            checkRequirePqcForInternal = CreateCheckBox(
                "&Require PQC encryption for internal emails",
                15, 60, 480, groupCapabilities);
            checkRequirePqcForInternal.AccessibleDescription = "Force quantum-safe encryption for emails within your organization";

            // Tab 2: Visual Settings
            var tabVisual = new TabPage("Visual");
            tabVisual.UseVisualStyleBackColor = true;
            tabControl.TabPages.Add(tabVisual);

            var groupIndicators = CreateGroupBox("Security Indicators", 10, 10, 520, 180, tabVisual);
            
            checkShowSecurityBadges = CreateCheckBox(
                "&Show security badges in ribbon",
                15, 30, 480, groupIndicators);
            checkShowSecurityBadges.AccessibleDescription = "Display visual security status indicators in the Outlook ribbon";
            
            checkShowEncryptionStatus = CreateCheckBox(
                "Show encryption status in &subject line",
                15, 60, 480, groupIndicators);
            checkShowEncryptionStatus.AccessibleDescription = "Add encryption status indicators to email subject lines";
            
            var lblIndicatorStyle = CreateLabel("Indicator Style:", 15, 95, groupIndicators);
            lblIndicatorStyle.AccessibleDescription = "Choose how security indicators are displayed";
            
            comboIndicatorStyle = CreateComboBox(15, 115, 200, groupIndicators);
            comboIndicatorStyle.DropDownStyle = ComboBoxStyle.DropDownList;
            comboIndicatorStyle.Items.AddRange(new object[]
            {
                "Icon Only",
                "Text Only", 
                "Icon and Text",
                "Minimal"
            });
            comboIndicatorStyle.SelectedIndex = 2; // Icon and Text
            comboIndicatorStyle.AccessibleName = "Indicator Style";
            comboIndicatorStyle.AccessibleDescription = "Select how security status should be visually displayed";

            var lblStyleHelp = CreateHelpLabel(
                "Icon and Text provides the best accessibility. Minimal mode reduces visual clutter.",
                15, 145, 480, groupIndicators);

            // Tab 3: Performance
            var tabPerformance = new TabPage("Performance");
            tabPerformance.UseVisualStyleBackColor = true;
            tabControl.TabPages.Add(tabPerformance);

            var groupCache = CreateGroupBox("Capability Caching", 10, 10, 520, 120, tabPerformance);
            
            var lblCacheTimeout = CreateLabel("Cache timeout (minutes):", 15, 30, groupCache);
            lblCacheTimeout.AccessibleDescription = "How long to remember recipient encryption capabilities";
            
            numericCacheTimeout = new NumericUpDown
            {
                Location = new Point(15, 50),
                Size = new Size(100, 23),
                Minimum = 1,
                Maximum = 1440,
                Value = 60,
                TabIndex = GetNextTabIndex(),
                AccessibleName = "Cache Timeout",
                AccessibleDescription = "Number of minutes to cache recipient capabilities (1-1440)"
            };
            groupCache.Controls.Add(numericCacheTimeout);
            
            var lblCacheHelp = CreateHelpLabel(
                "Longer cache times improve performance but may miss capability updates. 60 minutes is recommended.",
                15, 80, 480, groupCache);

            var groupProcessing = CreateGroupBox("Processing Options", 10, 140, 520, 80, tabPerformance);
            
            checkEnableBackgroundProcessing = CreateCheckBox(
                "&Enable background processing for better responsiveness",
                15, 30, 480, groupProcessing);
            checkEnableBackgroundProcessing.AccessibleDescription = "Process encryption operations in the background to keep Outlook responsive";

            // Tab 4: Advanced
            var tabAdvanced = new TabPage("Advanced");
            tabAdvanced.UseVisualStyleBackColor = true;
            tabControl.TabPages.Add(tabAdvanced);

            var groupDomains = CreateGroupBox("Internal Domains", 10, 10, 520, 120, tabAdvanced);
            
            var lblDomains = CreateLabel("Internal domain names (comma-separated):", 15, 30, groupDomains);
            lblDomains.AccessibleDescription = "List of email domains considered internal to your organization";
            
            textInternalDomains = new TextBox
            {
                Location = new Point(15, 50),
                Size = new Size(480, 23),
                TabIndex = GetNextTabIndex(),
                AccessibleName = "Internal Domains",
                AccessibleDescription = "Enter domain names separated by commas, e.g., company.com, subsidiary.com"
            };
            groupDomains.Controls.Add(textInternalDomains);
            
            var lblDomainsHelp = CreateHelpLabel(
                "Emails to these domains will be treated as internal and may require PQC encryption.",
                15, 80, 480, groupDomains);

            var groupSecurity = CreateGroupBox("Security Options", 10, 140, 520, 100, tabAdvanced);
            
            checkEnableLogging = CreateCheckBox(
                "Enable &detailed audit logging",
                15, 30, 480, groupSecurity);
            checkEnableLogging.AccessibleDescription = "Log detailed information about encryption operations for compliance audits";
            
            checkForceValidation = CreateCheckBox(
                "&Force signature validation (recommended)",
                15, 60, 480, groupSecurity);
            checkForceValidation.AccessibleDescription = "Always validate digital signatures even from trusted senders";

            // Button panel with WCAG compliant layout
            var buttonPanel = new Panel
            {
                Location = new Point(12, 620),
                Size = new Size(560, 40),
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
            };
            this.Controls.Add(buttonPanel);

            var buttonOk = CreateButton("&OK", 370, 8, 80, 25, buttonPanel, ButtonOk_Click);
            buttonOk.AccessibleDescription = "Save settings and close dialog";
            this.AcceptButton = buttonOk;
            
            var buttonCancel = CreateButton("&Cancel", 460, 8, 80, 25, buttonPanel, ButtonCancel_Click);
            buttonCancel.AccessibleDescription = "Close dialog without saving changes";
            this.CancelButton = buttonCancel;
            
            var buttonDefaults = CreateButton("&Defaults", 260, 8, 80, 25, buttonPanel, ButtonDefaults_Click);
            buttonDefaults.AccessibleDescription = "Reset all settings to default values";
            
            var buttonHelp = CreateButton("&Help", 10, 8, 80, 25, buttonPanel, ButtonHelp_Click);
            buttonHelp.AccessibleDescription = "Show help information about these settings";

            // Set initial focus and tab order
            comboEncryptionStrategy.Select();
            
            this.ResumeLayout(false);
            this.PerformLayout();
        }

        #endregion

        #region Helper Methods for WCAG 2.1 Compliance

        private int _currentTabIndex = 1;
        
        private int GetNextTabIndex()
        {
            return _currentTabIndex++;
        }

        /// <summary>
        /// Creates an accessible group box with proper contrast and sizing.
        /// </summary>
        private GroupBox CreateGroupBox(string text, int x, int y, int width, int height, Control parent)
        {
            var groupBox = new GroupBox
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(width, height),
                TabIndex = GetNextTabIndex(),
                ForeColor = SystemColors.ControlText,
                AccessibleRole = AccessibleRole.Grouping
            };
            
            parent.Controls.Add(groupBox);
            return groupBox;
        }

        /// <summary>
        /// Creates an accessible label with proper contrast.
        /// </summary>
        private Label CreateLabel(string text, int x, int y, Control parent)
        {
            var label = new Label
            {
                Text = text,
                Location = new Point(x, y),
                AutoSize = true,
                ForeColor = SystemColors.ControlText,
                AccessibleRole = AccessibleRole.StaticText
            };
            
            parent.Controls.Add(label);
            return label;
        }

        /// <summary>
        /// Creates a help text label with muted appearance but accessible contrast.
        /// </summary>
        private Label CreateHelpLabel(string text, int x, int y, int width, Control parent)
        {
            var label = new Label
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(width, 30),
                ForeColor = SystemColors.GrayText,
                Font = new Font(SystemFonts.DefaultFont.FontFamily, SystemFonts.DefaultFont.Size - 0.5f),
                AccessibleRole = AccessibleRole.StaticText,
                AccessibleDescription = "Help text: " + text
            };
            
            parent.Controls.Add(label);
            return label;
        }

        /// <summary>
        /// Creates an accessible checkbox with proper labeling.
        /// </summary>
        private CheckBox CreateCheckBox(string text, int x, int y, int width, Control parent)
        {
            var checkBox = new CheckBox
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(width, 25),
                UseVisualStyleBackColor = true,
                TabIndex = GetNextTabIndex(),
                ForeColor = SystemColors.ControlText,
                AccessibleRole = AccessibleRole.CheckButton
            };
            
            parent.Controls.Add(checkBox);
            return checkBox;
        }

        /// <summary>
        /// Creates an accessible combo box.
        /// </summary>
        private ComboBox CreateComboBox(int x, int y, int width, Control parent)
        {
            var comboBox = new ComboBox
            {
                Location = new Point(x, y),
                Size = new Size(width, 23),
                TabIndex = GetNextTabIndex(),
                AccessibleRole = AccessibleRole.ComboBox
            };
            
            parent.Controls.Add(comboBox);
            return comboBox;
        }

        /// <summary>
        /// Creates an accessible button with proper sizing and events.
        /// </summary>
        private Button CreateButton(string text, int x, int y, int width, int height, Control parent, EventHandler clickHandler)
        {
            var button = new Button
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(width, height),
                UseVisualStyleBackColor = true,
                TabIndex = GetNextTabIndex(),
                AccessibleRole = AccessibleRole.PushButton
            };
            
            button.Click += clickHandler;
            parent.Controls.Add(button);
            return button;
        }

        #endregion

        #region Accessibility Properties

        /// <summary>
        /// Gets the accessible description for the form.
        /// </summary>
        public override string AccessibleDescription => 
            "Configuration dialog for Post-Quantum Cryptography email security settings. " +
            "Use Tab to navigate between controls, Space to toggle checkboxes, and Enter to activate buttons.";

        /// <summary>
        /// Gets the accessible name for the form.
        /// </summary>
        public override string AccessibleName => "PQC Email Security Settings";

        #endregion
    }
}