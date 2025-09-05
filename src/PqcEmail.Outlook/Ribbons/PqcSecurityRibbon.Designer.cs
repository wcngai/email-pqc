using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using Microsoft.Office.Tools.Ribbon;

namespace PqcEmail.Outlook.Ribbons
{
    partial class PqcSecurityRibbon
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

        #region Component Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            // This method will be populated by the Visual Studio designer
            // For now, we'll implement the basic ribbon structure programmatically
        }

        #endregion

        #region Ribbon Callbacks

        /// <summary>
        /// Gets the image for the encrypt button.
        /// </summary>
        /// <param name="control">The ribbon control.</param>
        /// <returns>The image for the button.</returns>
        public Image GetEncryptImage(RibbonControl control)
        {
            try
            {
                return CreateSecurityIcon(Color.Green, "🔒");
            }
            catch
            {
                return CreateDefaultIcon();
            }
        }

        /// <summary>
        /// Gets the image for the decrypt button.
        /// </summary>
        /// <param name="control">The ribbon control.</param>
        /// <returns>The image for the button.</returns>
        public Image GetDecryptImage(RibbonControl control)
        {
            try
            {
                return CreateSecurityIcon(Color.Orange, "🔓");
            }
            catch
            {
                return CreateDefaultIcon();
            }
        }

        /// <summary>
        /// Gets the image for the sign button.
        /// </summary>
        /// <param name="control">The ribbon control.</param>
        /// <returns>The image for the button.</returns>
        public Image GetSignImage(RibbonControl control)
        {
            try
            {
                return CreateSecurityIcon(Color.Blue, "🖊️");
            }
            catch
            {
                return CreateDefaultIcon();
            }
        }

        /// <summary>
        /// Gets the image for the verify button.
        /// </summary>
        /// <param name="control">The ribbon control.</param>
        /// <returns>The image for the button.</returns>
        public Image GetVerifyImage(RibbonControl control)
        {
            try
            {
                return CreateSecurityIcon(Color.Purple, "✓");
            }
            catch
            {
                return CreateDefaultIcon();
            }
        }

        /// <summary>
        /// Gets the image for the settings button.
        /// </summary>
        /// <param name="control">The ribbon control.</param>
        /// <returns>The image for the button.</returns>
        public Image GetSettingsImage(RibbonControl control)
        {
            try
            {
                return CreateSecurityIcon(Color.Gray, "⚙️");
            }
            catch
            {
                return CreateDefaultIcon();
            }
        }

        /// <summary>
        /// Gets the image for the help button.
        /// </summary>
        /// <param name="control">The ribbon control.</param>
        /// <returns>The image for the button.</returns>
        public Image GetHelpImage(RibbonControl control)
        {
            try
            {
                return CreateSecurityIcon(Color.DarkBlue, "?");
            }
            catch
            {
                return CreateDefaultIcon();
            }
        }

        /// <summary>
        /// Gets the current status text.
        /// </summary>
        /// <param name="control">The ribbon control.</param>
        /// <returns>The status text.</returns>
        public string GetStatusText(RibbonControl control)
        {
            try
            {
                if (!string.IsNullOrEmpty(LastStatusMessage))
                {
                    var indicator = LastStatusLevel switch
                    {
                        StatusLevel.Success => "✓",
                        StatusLevel.Warning => "⚠",
                        StatusLevel.Error => "✗",
                        StatusLevel.Info => "ℹ",
                        _ => ""
                    };
                    
                    return $"{indicator} {LastStatusMessage}";
                }
                
                return "Ready";
            }
            catch
            {
                return "Status Unknown";
            }
        }

        /// <summary>
        /// Handles the help button click.
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="e">The event arguments.</param>
        private void ButtonHelp_Click(object sender, RibbonControlEventArgs e)
        {
            try
            {
                ShowHelpDialog();
            }
            catch (Exception ex)
            {
                ShowErrorMessage("Failed to show help", ex);
            }
        }

        /// <summary>
        /// Shows the help dialog.
        /// </summary>
        private void ShowHelpDialog()
        {
            var helpText = 
                "PQC Email Security Help\n\n" +
                "Post-Quantum Cryptography (PQC) protects your emails against future quantum computer attacks.\n\n" +
                "Features:\n" +
                "• Quantum-Safe Encryption: Uses ML-KEM-768 algorithm\n" +
                "• Digital Signatures: Uses ML-DSA-65 algorithm\n" +
                "• Hybrid Mode: Combines PQC with classical encryption\n" +
                "• Auto-Detection: Automatically detects recipient capabilities\n\n" +
                $"Keyboard Shortcuts:\n{KeyboardShortcutsHelp}\n\n" +
                "Status Indicators:\n" +
                "✓ Success: Operation completed successfully\n" +
                "⚠ Warning: Attention required\n" +
                "✗ Error: Operation failed\n" +
                "ℹ Info: General information\n\n" +
                "For technical support, contact your IT administrator.";

            System.Windows.Forms.MessageBox.Show(
                helpText,
                "PQC Email Security Help",
                System.Windows.Forms.MessageBoxButtons.OK,
                System.Windows.Forms.MessageBoxIcon.Information
            );
        }

        #endregion

        #region Icon Generation

        /// <summary>
        /// Creates a security icon with the specified color and symbol.
        /// </summary>
        /// <param name="color">The icon color.</param>
        /// <param name="symbol">The symbol to display.</param>
        /// <returns>The generated icon image.</returns>
        private Image CreateSecurityIcon(Color color, string symbol)
        {
            try
            {
                var bitmap = new Bitmap(32, 32);
                using (var graphics = Graphics.FromImage(bitmap))
                {
                    graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                    graphics.Clear(Color.Transparent);

                    // Draw shield background
                    var shieldRect = new Rectangle(2, 2, 28, 28);
                    using (var brush = new SolidBrush(Color.FromArgb(200, color)))
                    {
                        graphics.FillEllipse(brush, shieldRect);
                    }

                    // Draw border
                    using (var pen = new Pen(color, 2))
                    {
                        graphics.DrawEllipse(pen, shieldRect);
                    }

                    // Draw symbol
                    using (var font = new Font("Segoe UI Symbol", 12, FontStyle.Bold))
                    using (var brush = new SolidBrush(Color.White))
                    {
                        var symbolSize = graphics.MeasureString(symbol, font);
                        var x = (bitmap.Width - symbolSize.Width) / 2;
                        var y = (bitmap.Height - symbolSize.Height) / 2;
                        graphics.DrawString(symbol, font, brush, x, y);
                    }
                }
                return bitmap;
            }
            catch
            {
                return CreateDefaultIcon();
            }
        }

        /// <summary>
        /// Creates a default fallback icon.
        /// </summary>
        /// <returns>The default icon image.</returns>
        private Image CreateDefaultIcon()
        {
            try
            {
                var bitmap = new Bitmap(32, 32);
                using (var graphics = Graphics.FromImage(bitmap))
                {
                    graphics.Clear(Color.Transparent);
                    using (var brush = new SolidBrush(Color.Gray))
                    {
                        graphics.FillRectangle(brush, 0, 0, 32, 32);
                    }
                }
                return bitmap;
            }
            catch
            {
                // If even this fails, return a 1x1 transparent image
                return new Bitmap(1, 1);
            }
        }

        #endregion
    }
}