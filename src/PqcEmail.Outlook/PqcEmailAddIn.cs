using System;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Office.Tools;
using Outlook = Microsoft.Office.Interop.Outlook;
using Office = Microsoft.Office.Core;
using PqcEmail.Core.Interfaces;
using PqcEmail.Outlook.EventHandlers;
using PqcEmail.Outlook.COM;

namespace PqcEmail.Outlook
{
    /// <summary>
    /// Main VSTO Add-in class for PQC Email integration with Microsoft Outlook.
    /// This class handles the add-in lifecycle and orchestrates all PQC functionality.
    /// </summary>
    [ComVisible(true)]
    public partial class PqcEmailAddIn
    {
        private IHybridEncryptionEngine? _encryptionEngine;
        private OutlookEventManager? _eventManager;
        private OutlookComInterop? _comInterop;
        private bool _isInitialized = false;

        /// <summary>
        /// Gets the current Outlook application instance.
        /// </summary>
        public Outlook.Application OutlookApplication => Application;

        /// <summary>
        /// Gets the hybrid encryption engine instance.
        /// </summary>
        public IHybridEncryptionEngine? EncryptionEngine => _encryptionEngine;

        /// <summary>
        /// Gets a value indicating whether the add-in is fully initialized.
        /// </summary>
        public bool IsInitialized => _isInitialized;

        /// <summary>
        /// Called when the add-in is loaded.
        /// This is the main initialization point for the PQC functionality.
        /// </summary>
        private async void ThisAddIn_Startup(object sender, System.EventArgs e)
        {
            try
            {
                await InitializeAddInAsync();
            }
            catch (Exception ex)
            {
                // Log error and show user-friendly message
                await LogErrorAsync("Failed to initialize PQC Email Add-in", ex);
                ShowUserError("PQC Email Add-in failed to initialize. Some features may not be available.");
            }
        }

        /// <summary>
        /// Called when the add-in is unloaded.
        /// This handles cleanup of resources and event handlers.
        /// </summary>
        private void ThisAddIn_Shutdown(object sender, System.EventArgs e)
        {
            try
            {
                CleanupResources();
            }
            catch (Exception ex)
            {
                // Log error but don't show to user during shutdown
                _ = LogErrorAsync("Error during add-in shutdown", ex);
            }
        }

        /// <summary>
        /// Initializes all add-in components asynchronously.
        /// </summary>
        /// <returns>A task representing the asynchronous initialization operation.</returns>
        private async Task InitializeAddInAsync()
        {
            // Initialize COM interop layer
            _comInterop = new OutlookComInterop(Application);
            await _comInterop.InitializeAsync();

            // Initialize encryption engine (from PqcEmail.Core)
            _encryptionEngine = await InitializeEncryptionEngineAsync();

            // Initialize event manager
            _eventManager = new OutlookEventManager(Application, _encryptionEngine, _comInterop);
            await _eventManager.InitializeAsync();

            // Mark as initialized
            _isInitialized = true;

            await LogInfoAsync("PQC Email Add-in initialized successfully");
        }

        /// <summary>
        /// Initializes the hybrid encryption engine from the Core library.
        /// </summary>
        /// <returns>A task representing the asynchronous initialization operation.</returns>
        private async Task<IHybridEncryptionEngine> InitializeEncryptionEngineAsync()
        {
            // This will be injected from the Core library
            // For now, we'll create a placeholder that integrates with the actual implementation
            return await Task.FromResult<IHybridEncryptionEngine>(
                new PqcEmail.Core.Cryptography.HybridEncryptionEngine(
                    new PqcEmail.Core.Cryptography.BouncyCastleCryptographicProvider(),
                    new PqcEmail.Core.Cryptography.AlgorithmSelector()
                )
            );
        }

        /// <summary>
        /// Cleans up resources when the add-in is shutting down.
        /// </summary>
        private void CleanupResources()
        {
            try
            {
                _eventManager?.Dispose();
                _eventManager = null;

                _comInterop?.Dispose();
                _comInterop = null;

                _encryptionEngine = null;

                _isInitialized = false;
            }
            catch (Exception ex)
            {
                // Best effort cleanup
                System.Diagnostics.Debug.WriteLine($"Error during resource cleanup: {ex}");
            }
        }

        /// <summary>
        /// Logs an informational message asynchronously.
        /// </summary>
        /// <param name="message">The message to log.</param>
        /// <returns>A task representing the asynchronous logging operation.</returns>
        private async Task LogInfoAsync(string message)
        {
            await Task.Run(() =>
            {
                System.Diagnostics.Debug.WriteLine($"[PQC-INFO] {DateTime.Now:yyyy-MM-dd HH:mm:ss}: {message}");
                // TODO: Implement proper logging infrastructure
            });
        }

        /// <summary>
        /// Logs an error message asynchronously.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="exception">The exception that occurred.</param>
        /// <returns>A task representing the asynchronous logging operation.</returns>
        private async Task LogErrorAsync(string message, Exception exception)
        {
            await Task.Run(() =>
            {
                System.Diagnostics.Debug.WriteLine($"[PQC-ERROR] {DateTime.Now:yyyy-MM-dd HH:mm:ss}: {message}");
                System.Diagnostics.Debug.WriteLine($"[PQC-ERROR] Exception: {exception}");
                // TODO: Implement proper logging infrastructure with error reporting
            });
        }

        /// <summary>
        /// Shows a user-friendly error message to the user.
        /// </summary>
        /// <param name="message">The message to display.</param>
        private void ShowUserError(string message)
        {
            try
            {
                System.Windows.Forms.MessageBox.Show(
                    message,
                    "PQC Email Security",
                    System.Windows.Forms.MessageBoxButtons.OK,
                    System.Windows.Forms.MessageBoxIcon.Warning
                );
            }
            catch
            {
                // If we can't show the message box, fail silently
                // Error is already logged in the calling method
            }
        }

        #region VSTO generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InternalStartup()
        {
            Startup += ThisAddIn_Startup;
            Shutdown += ThisAddIn_Shutdown;
        }

        #endregion
    }
}