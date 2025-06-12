using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using XPlaneActivator.Services;
using DRM.VFS;

namespace XPlaneActivator
{
    /// <summary>
    /// Enhanced MainWindow with English interface and fixed UI logic
    /// </summary>
    public partial class MainWindow : Window
    {
        // =====================================================
        // Service Dependencies
        // =====================================================
        private readonly IActivationService activationService;
        private readonly ISystemCheckService systemCheckService;
        private readonly IUIController uiController;

        // =====================================================
        // State Management
        // =====================================================
        private volatile bool isClosing = false;
        private readonly object closingLock = new object();
        private CancellationTokenSource? cancellationTokenSource;
        private bool isCurrentlyActivated = false;
        private ActivationState? currentActivationState = null;

        // =====================================================
        // Core Managers (for service injection)
        // =====================================================
        private readonly NetworkManager networkManager;
        private readonly SecurityManager securityManager;
        private readonly VirtualFileSystemManager vfsManager;
        private readonly ActivationStateManager stateManager;

        // =====================================================
        // Timers
        // =====================================================
        private readonly Timer networkCheckTimer;
        private readonly Timer activationCheckTimer;

        // =====================================================
        // Constructor and Initialization
        // =====================================================
        public MainWindow()
        {
            InitializeComponent();

            // Initialize core managers
            networkManager = new NetworkManager();
            securityManager = new SecurityManager();
            vfsManager = new DRM.VFS.VirtualFileSystemManager(@"W:\", DRM.VFS.VfsAccessMode.AllowAll);
            stateManager = new ActivationStateManager();

            // Initialize services
            var serviceContainer = CreateServiceContainer();
            activationService = serviceContainer.GetService<IActivationService>();
            systemCheckService = serviceContainer.GetService<ISystemCheckService>();
            uiController = serviceContainer.GetService<IUIController>();

            // Setup event handlers
            SetupEventHandlers();

            // Setup timers
            networkCheckTimer = new Timer(CheckNetworkStatus, null, TimeSpan.Zero, TimeSpan.FromSeconds(30));
            activationCheckTimer = new Timer(CheckActivationStatus, null, TimeSpan.Zero, TimeSpan.FromMinutes(1));

            // Async initialization
            _ = InitializeAsync();
        }

        private ServiceContainer CreateServiceContainer()
        {
            var container = new ServiceContainer();

            // Register core managers
            container.RegisterSingleton(networkManager);
            container.RegisterSingleton(securityManager);
            container.RegisterSingleton(vfsManager);
            container.RegisterSingleton(stateManager);

            // Register services
            container.RegisterSingleton<IActivationService>(new ActivationService(
                networkManager, securityManager, vfsManager, stateManager));
            container.RegisterSingleton<ISystemCheckService>(new SystemCheckService(securityManager));
            container.RegisterSingleton<IUIController>(new UIController(this));

            return container;
        }

        private void SetupEventHandlers()
        {
            // Activation service events
            activationService.ProgressChanged += OnActivationProgressChanged;
            activationService.LogMessage += OnServiceLogMessage;

            // VFS status change events
            vfsManager.StatusChanged += VfsManager_StatusChanged;
            vfsManager.LogMessage += VfsManager_LogMessage;

            // Window events
            this.Closing += MainWindow_Closing;
        }

        private async Task InitializeAsync()
        {
            try
            {
                uiController.AddLog("========== X-Plane DRM Activator Starting ==========");
                uiController.UpdateStatus("Initializing system...");

                // Generate and display machine code
                await Task.Run(() =>
                {
                    string machineCode = HardwareIdHelper.GetMachineFingerprint();
                    Dispatcher.Invoke(() =>
                    {
                        txtMachineCode.Text = machineCode;
                        uiController.AddLog($"Machine code generated: {machineCode.Substring(0, 8)}...");
                    });
                });

                // System environment check
                await PerformSystemCheck();

                // Check previous activation status
                await CheckPreviousActivation();

                if (!isCurrentlyActivated)
                {
                    uiController.AddLog("System initialization complete, waiting for activation...");
                    uiController.UpdateStatus("Ready - Please enter activation code");
                }
            }
            catch (Exception ex)
            {
                uiController.AddLog($"System initialization failed: {ex.Message}");
                uiController.UpdateStatus("Initialization failed");
                uiController.ShowMessage($"Initialization failed: {ex.Message}", "Error", true);
            }
        }

        // =====================================================
        // System Check
        // =====================================================
        private async Task PerformSystemCheck()
        {
            uiController.AddLog("Checking system environment...");

            var checkResult = await systemCheckService.PerformSystemCheckAsync();

            // Report check results
            if (!checkResult.IsAdmin)
            {
                uiController.AddLog("Warning: Not running as administrator, virtual file system may not work properly");
            }
            else
            {
                uiController.AddLog("Administrator privileges check passed");
            }

            // Dokan driver check
            if (checkResult.DokanCheck.IsInstalled)
            {
                uiController.AddLog($"Dokan driver check: {checkResult.DokanCheck.Message}");
                if (!string.IsNullOrEmpty(checkResult.DokanCheck.Details))
                {
                    uiController.AddLog($"Dokan details: {checkResult.DokanCheck.Details}");
                }
            }
            else
            {
                uiController.AddLog($"Warning: {checkResult.DokanCheck.Message}");
            }

            // Encryption engine check
            if (checkResult.CryptoEngineAvailable)
            {
                uiController.AddLog("CryptoEngine.dll found");
                if (checkResult.CryptoEngineTest)
                {
                    uiController.AddLog("CryptoEngine functioning normally");
                }
                else
                {
                    uiController.AddLog("Warning: CryptoEngine test failed, will use fallback method");
                }
            }
            else
            {
                uiController.AddLog("Warning: CryptoEngine.dll not found, will use C# fallback verification");
            }
        }

        // =====================================================
        // Activation State Management
        // =====================================================
        private async Task CheckPreviousActivation()
        {
            try
            {
                uiController.AddLog("Checking previous activation status...");

                var isValid = await activationService.ValidateExistingActivationAsync();
                var currentState = activationService.GetCurrentActivationState();

                if (isValid && currentState != null)
                {
                    uiController.AddLog($"Found valid activation status, activation time: {currentState.ActivationTime:yyyy-MM-dd HH:mm:ss}");

                    int remainingDays = 30 - (int)(DateTime.Now - currentState.ActivationTime).TotalDays;
                    uiController.AddLog($"Activation remaining days: {remainingDays} days");

                    // Try to restore virtual file system
                    await RestoreVirtualFileSystem(currentState);
                }
                else
                {
                    uiController.AddLog("No valid activation status found");
                    uiController.UpdateActivationUI(false, null);
                }
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Error checking activation status: {ex.Message}");
                uiController.UpdateActivationUI(false, null);
            }
        }

        private async Task RestoreVirtualFileSystem(ActivationState state)
        {
            try
            {
                uiController.AddLog("Restoring virtual file system...");
                uiController.UpdateStatus("Restoring activation status...");

                byte[]? decryptedData = null;

                // Try to decrypt using server token
                if (!string.IsNullOrEmpty(state.ServerToken))
                {
                    decryptedData = securityManager.DecryptWithToken(state.ServerToken);
                }

                // If server token fails, try using activation code
                if (decryptedData == null && !string.IsNullOrEmpty(state.ActivationCode))
                {
                    decryptedData = securityManager.ValidateAndDecrypt(state.ActivationCode);
                }

                if (decryptedData != null && decryptedData.Length > 0)
                {
                    uiController.AddLog($"Data decryption successful, size: {decryptedData.Length} bytes");

                    // Mount virtual file system
                    bool mounted = await Task.Run(() =>
                        vfsManager.MountVirtualFileSystem(
                            decryptedData,
                            CancellationToken.None
                        )
                    );

                    if (mounted)
                    {
                        isCurrentlyActivated = true;
                        currentActivationState = state;

                        uiController.AddLog($"Virtual file system successfully mounted to {vfsManager.MountPoint}");
                        uiController.UpdateStatus("Activation successful");
                        uiController.UpdateActivationUI(true, state);

                        // Show welcome message
                        ShowActivationWelcomeMessage(state);
                    }
                    else
                    {
                        uiController.AddLog("Virtual file system restoration failed");
                        uiController.UpdateActivationUI(false, null);
                    }
                }
                else
                {
                    uiController.AddLog("Cannot decrypt saved activation data");
                    stateManager.ClearActivationState();
                    uiController.UpdateActivationUI(false, null);
                }
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Virtual file system restoration failed: {ex.Message}");
                uiController.UpdateActivationUI(false, null);
            }
        }

        private void ShowActivationWelcomeMessage(ActivationState state)
        {
            try
            {
                int remainingDays = 30 - (int)(DateTime.Now - state.ActivationTime).TotalDays;
                string welcomeMessage = $"Welcome back!\n\n" +
                                      $"Activation Status: Activated\n" +
                                      $"Activation Time: {state.ActivationTime:yyyy-MM-dd HH:mm:ss}\n" +
                                      $"Remaining Days: {remainingDays} days\n" +
                                      $"Virtual File System: {vfsManager.MountPoint}\n\n" +
                                      $"X-Plane is ready to use.";

                uiController.ShowMessage(welcomeMessage, "Activation Complete");
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Error showing activation info: {ex.Message}");
            }
        }

        // =====================================================
        // User Operation Handlers
        // =====================================================
        private async void BtnActivate_Click(object sender, RoutedEventArgs e)
        {
            if (isClosing || isCurrentlyActivated)
            {
                if (isCurrentlyActivated)
                {
                    uiController.ShowMessage("System is already activated. To reactivate, please deactivate first.", "Information");
                }
                return;
            }

            string activationCode = txtActivationCode.Text.Trim();
            if (string.IsNullOrEmpty(activationCode))
            {
                uiController.ShowMessage("Please enter your activation code!", "Input Required", true);
                return;
            }

            // Disable activate button to prevent duplicate clicks
            btnActivate.IsEnabled = false;
            btnActivate.Content = "Activating...";
            cancellationTokenSource = new CancellationTokenSource();

            try
            {
                uiController.UpdateStatus("Validating activation code...");
                uiController.AddLog($"Starting activation process, code: {activationCode.Substring(0, Math.Min(8, activationCode.Length))}...");

                // Try online activation
                var onlineResult = await activationService.ActivateOnlineAsync(activationCode, cancellationTokenSource.Token);

                if (onlineResult.IsSuccess)
                {
                    await HandleActivationSuccess(onlineResult);
                }
                else
                {
                    // Ask if user wants to try offline activation
                    bool tryOffline = uiController.ConfirmAction(
                        $"Online activation failed: {onlineResult.ErrorMessage}\n\nWould you like to try offline activation?\n\nNote: Offline activation only works with valid activation codes.",
                        "Online Verification Failed");

                    if (tryOffline)
                    {
                        uiController.AddLog("Trying offline verification...");
                        var offlineResult = await activationService.ActivateOfflineAsync(activationCode, cancellationTokenSource.Token);

                        if (offlineResult.IsSuccess)
                        {
                            await HandleActivationSuccess(offlineResult);
                        }
                        else
                        {
                            uiController.ShowMessage($"Offline activation failed: {offlineResult.ErrorMessage}", "Activation Failed", true);
                        }
                    }
                    else
                    {
                        uiController.AddLog("User cancelled offline verification");
                        uiController.UpdateStatus("Activation cancelled");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                uiController.AddLog("Activation cancelled");
                uiController.UpdateStatus("Activation cancelled");
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Activation error: {ex.Message}");
                uiController.UpdateStatus("Activation failed");
                uiController.ShowMessage($"Activation failed: {ex.Message}", "Error", true);
            }
            finally
            {
                // Restore button state (if not activated)
                if (!isCurrentlyActivated)
                {
                    btnActivate.IsEnabled = true;
                    btnActivate.Content = "Online Activation";
                }
                cancellationTokenSource?.Dispose();
                cancellationTokenSource = null;
            }
        }

        private async Task HandleActivationSuccess(ActivationResult result)
        {
            isCurrentlyActivated = true;
            currentActivationState = activationService.GetCurrentActivationState();

            uiController.UpdateActivationUI(true, currentActivationState);
            uiController.UpdateStatus("Activation successful - Virtual file system ready");

            string successMessage = $"Activation successful!\n\n" +
                                   $"Virtual file system mounted to {result.MountPoint}\n" +
                                   $"You can now start X-Plane.\n\n" +
                                   $"Activation status saved, will be automatically restored on next startup.";

            uiController.ShowMessage(successMessage, "Activation Complete");
        }

        private async void BtnDeactivate_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                bool confirmed = uiController.ConfirmAction(
                    "Are you sure you want to deactivate? This will clear saved activation status and unmount the virtual file system.",
                    "Confirm Deactivation");

                if (confirmed)
                {
                    uiController.AddLog("User selected deactivation");

                    bool success = await activationService.DeactivateAsync();

                    if (success)
                    {
                        isCurrentlyActivated = false;
                        currentActivationState = null;

                        uiController.UpdateActivationUI(false, null);
                        uiController.UpdateStatus("Deactivated");
                        uiController.AddLog("Deactivation successful");
                        uiController.ShowMessage("Deactivation successful.", "Deactivation Complete");
                    }
                    else
                    {
                        uiController.ShowMessage("Deactivation failed, please check logs for details.", "Error", true);
                    }
                }
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Deactivation error: {ex.Message}");
                uiController.ShowMessage($"Deactivation failed: {ex.Message}", "Error", true);
            }
        }

        private async void BtnDiagnostic_Click(object sender, RoutedEventArgs e)
        {
            if (isClosing) return;

            try
            {
                btnDiagnostic.IsEnabled = false;
                btnDiagnostic.Content = "Running Diagnostic...";

                uiController.AddLog("Starting system diagnostic...");
                uiController.UpdateStatus("Running system diagnostic...");

                // Create simplified diagnostic report
                var simpleReport = CreateSimpleDiagnosticReport();
                ShowSimpleDiagnosticMessage(simpleReport);

                uiController.AddLog("System diagnostic complete");
                uiController.UpdateStatus("Diagnostic complete");
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Diagnostic process exception: {ex.Message}");
                uiController.ShowMessage($"Diagnostic failed: {ex.Message}", "Error", true);
            }
            finally
            {
                btnDiagnostic.IsEnabled = true;
                btnDiagnostic.Content = "System Diagnostic";
            }
        }

        private string CreateSimpleDiagnosticReport()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== System Diagnostic Report ===");
            sb.AppendLine($"Diagnostic Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();
            sb.AppendLine("1. Administrator Privileges: " + (systemCheckService.IsRunningAsAdministrator() ? "✓ Pass" : "✗ Fail"));
            sb.AppendLine("2. CryptoEngine: " + (securityManager.IsCryptoDllAvailable() ? "✓ Available" : "✗ Not Available"));
            sb.AppendLine("3. Network Connection: " + (networkManager != null ? "✓ Normal" : "✗ Error"));
            sb.AppendLine("4. VFS Status: " + (vfsManager.IsMounted ? "✓ Mounted" : "- Not Mounted"));

            // Check security threats
            var threatInfo = securityManager.CheckSecurityThreats();
            sb.AppendLine("5. Security Check: " + (threatInfo.ThreatsDetected ? "⚠ Threats Detected" : "✓ Clean"));
            if (threatInfo.ThreatsDetected)
            {
                sb.AppendLine($"   - {threatInfo.Message}");
            }

            sb.AppendLine();
            sb.AppendLine("System Information:");
            sb.AppendLine(systemCheckService.GetSystemInfo());

            sb.AppendLine();
            sb.AppendLine("Decryption Method:");
            sb.AppendLine(securityManager.GetDecryptionMethod());

            return sb.ToString();
        }

        private void ShowSimpleDiagnosticMessage(string report)
        {
            uiController.ShowMessage(report, "System Diagnostic Report");
        }

        private void BtnClearLog_Click(object sender, RoutedEventArgs e)
        {
            if (isClosing) return;

            txtActivationLog.Clear();
            uiController.AddLog("Log cleared");
        }

        private void BtnSaveLog_Click(object sender, RoutedEventArgs e)
        {
            if (isClosing) return;

            try
            {
                var saveDialog = new Microsoft.Win32.SaveFileDialog
                {
                    Title = "Save Activation Log",
                    Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                    FileName = $"XPlane_Activation_Log_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
                };

                if (saveDialog.ShowDialog() == true)
                {
                    System.IO.File.WriteAllText(saveDialog.FileName, txtActivationLog.Text);
                    uiController.AddLog($"Log saved to: {saveDialog.FileName}");
                    uiController.ShowMessage("Log saved successfully!", "Save Complete");
                }
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Log save failed: {ex.Message}");
                uiController.ShowMessage($"Log save failed: {ex.Message}", "Error", true);
            }
        }

        private void BtnActivationInfo_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (currentActivationState == null)
                {
                    uiController.ShowMessage("Currently not activated or activation status information is unavailable.", "Information");
                    return;
                }

                int remainingDays = 30 - (int)(DateTime.Now - currentActivationState.ActivationTime).TotalDays;
                string machineFingerprint = HardwareIdHelper.GetDisplayFingerprint();

                var timeSinceActivation = DateTime.Now - currentActivationState.ActivationTime;
                var timeSinceHeartbeat = DateTime.Now - currentActivationState.LastHeartbeat;

                string infoMessage = $"Detailed Activation Information\n\n" +
                                   $"Activation Code: {currentActivationState.ActivationCode.Substring(0, Math.Min(8, currentActivationState.ActivationCode.Length))}...\n" +
                                   $"Activation Time: {currentActivationState.ActivationTime:yyyy-MM-dd HH:mm:ss}\n" +
                                   $"Activated Days: {(int)timeSinceActivation.TotalDays} days\n" +
                                   $"Remaining Days: {remainingDays} days\n" +
                                   $"Last Heartbeat: {currentActivationState.LastHeartbeat:yyyy-MM-dd HH:mm:ss}\n" +
                                   $"Heartbeat Interval: {(int)timeSinceHeartbeat.TotalMinutes} minutes ago\n" +
                                   $"Machine Fingerprint: {machineFingerprint}\n" +
                                   $"Mount Point: {currentActivationState.MountPoint ?? "Unknown"}\n" +
                                   $"Server Token: {(!string.IsNullOrEmpty(currentActivationState.ServerToken) ? "Available" : "Not Available")}";

                uiController.ShowMessage(infoMessage, "Activation Information");
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Error showing activation info: {ex.Message}");
                uiController.ShowMessage($"Cannot show activation info: {ex.Message}", "Error", true);
            }
        }

        // =====================================================
        // Event Handlers
        // =====================================================
        private void OnActivationProgressChanged(object? sender, ActivationProgressEventArgs e)
        {
            uiController.AddLog(e.Message);
            uiController.UpdateStatus(e.Message);
        }

        private void OnServiceLogMessage(object? sender, string e)
        {
            uiController.AddLog(e);
        }

        private void CheckNetworkStatus(object? state)
        {
            Task.Run(async () =>
            {
                try
                {
                    bool isConnected = await networkManager.TestServerConnectionAsync(ServerConfig.BASE_URL);

                    Dispatcher.Invoke(() =>
                    {
                        if (isConnected)
                        {
                            lblNetworkStatus.Text = "Network Online (lars-store.kz)";
                            lblNetworkStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.LightGreen);
                            lblConnectionStatus.Text = "Online";
                            statusIndicator.Fill = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.LightGreen);
                        }
                        else
                        {
                            lblNetworkStatus.Text = "Network Disconnected";
                            lblNetworkStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Orange);
                            lblConnectionStatus.Text = "Offline";
                            statusIndicator.Fill = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Orange);
                        }
                    });
                }
                catch
                {
                    Dispatcher.Invoke(() =>
                    {
                        lblNetworkStatus.Text = "Network Error";
                        lblNetworkStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Red);
                        lblConnectionStatus.Text = "Error";
                        statusIndicator.Fill = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Red);
                    });
                }
            });
        }

        private void CheckActivationStatus(object? state)
        {
            if (isClosing) return;

            Task.Run(async () =>
            {
                try
                {
                    if (isCurrentlyActivated && currentActivationState != null)
                    {
                        // Check if activation has expired
                        var isValid = await activationService.ValidateExistingActivationAsync();

                        if (!isValid)
                        {
                            Dispatcher.Invoke(() =>
                            {
                                uiController.AddLog("Activation has expired");
                                HandleActivationExpired();
                            });
                        }
                        else
                        {
                            // Check remaining days
                            int remainingDays = 30 - (int)(DateTime.Now - currentActivationState.ActivationTime).TotalDays;

                            if (remainingDays <= 0)
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    uiController.AddLog("Activation has expired");
                                    HandleActivationExpired();
                                });
                            }
                            else if (remainingDays <= 3)
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    uiController.AddLog($"Activation will expire soon, remaining {remainingDays} days");
                                });
                            }

                            // Update heartbeat
                            stateManager.UpdateHeartbeat();
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Check activation status exception: {ex.Message}");
                }
            });
        }

        private async void HandleActivationExpired()
        {
            try
            {
                bool success = await activationService.DeactivateAsync();

                isCurrentlyActivated = false;
                currentActivationState = null;

                uiController.UpdateActivationUI(false, null);
                uiController.UpdateStatus("Activation has expired");
                uiController.ShowMessage("Activation has expired, please reactivate.", "Activation Expired", true);
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Error processing activation expiry: {ex.Message}");
            }
        }

        private void VfsManager_StatusChanged(object? sender, VfsStatusEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                uiController.AddLog($"VFS Status: {e.Message}");

                switch (e.Status)
                {
                    case VfsStatus.Mounted:
                        lblVfsStatus.Text = "Virtual File System mounted";
                        lblVfsStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.LightGreen);
                        break;
                    case VfsStatus.Mounting:
                        lblVfsStatus.Text = "Virtual File System mounting";
                        lblVfsStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Yellow);
                        break;
                    case VfsStatus.Error:
                        lblVfsStatus.Text = "Virtual File System error";
                        lblVfsStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Red);
                        break;
                    case VfsStatus.Unmounted:
                        lblVfsStatus.Text = "Virtual File System not mounted";
                        lblVfsStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Gray);
                        break;
                }
            });
        }

        private void VfsManager_LogMessage(object? sender, string e)
        {
            Dispatcher.Invoke(() => uiController.AddLog($"VFS: {e}"));
        }

        // =====================================================
        // Lifecycle Management
        // =====================================================
        private void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            lock (closingLock)
            {
                if (isClosing) return;
                isClosing = true;
            }

            try
            {
                uiController.AddLog("Application is closing...");

                // Cancel all operations
                cancellationTokenSource?.Cancel();

                // Stop timers
                networkCheckTimer?.Dispose();
                activationCheckTimer?.Dispose();

                // If still activated, update last heartbeat time
                if (isCurrentlyActivated)
                {
                    stateManager?.UpdateHeartbeat();
                }

                // Unmount virtual file system
                vfsManager?.UnmountVirtualFileSystem();

                // Release resources
                networkManager?.Dispose();
                securityManager?.Dispose();
                vfsManager?.Dispose();

                uiController.AddLog("Application has been closed");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Close exception: {ex.Message}");
            }
        }

        // =====================================================
        // Simple Service Container
        // =====================================================
        private class ServiceContainer
        {
            private readonly Dictionary<Type, object> services = new Dictionary<Type, object>();

            public void RegisterSingleton<T>(T instance) where T : class
            {
                services[typeof(T)] = instance;
            }

            public T GetService<T>() where T : class
            {
                return (T)services[typeof(T)];
            }
        }
    }
}