using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess; // 现在应该可以正常使用了

namespace XPlaneActivator
{
    public partial class MainWindow : Window
    {
        private readonly NetworkManager networkManager;
        private readonly SecurityManager securityManager;
        private readonly VirtualFileSystemManager vfsManager;
        private readonly ActivationStateManager stateManager;
        private readonly Timer networkCheckTimer;
        private readonly Timer activationCheckTimer;
        private CancellationTokenSource? cancellationTokenSource;

        // Close related fields
        private volatile bool isClosing = false;
        private readonly object closingLock = new object();

        // Activation state related fields
        private bool isCurrentlyActivated = false;
        private ActivationState? currentActivationState = null;

        public MainWindow()
        {
            InitializeComponent();

            // Initialize managers
            networkManager = new NetworkManager();
            securityManager = new SecurityManager();
            vfsManager = new VirtualFileSystemManager();
            stateManager = new ActivationStateManager();

            // Setup event handlers
            SetupEventHandlers();

            // Initialize UI
            InitializeUI();

            // Setup timer to check network status
            networkCheckTimer = new Timer(CheckNetworkStatus, null, TimeSpan.Zero, TimeSpan.FromSeconds(30));

            // Setup timer to check activation status (every minute)
            activationCheckTimer = new Timer(CheckActivationStatus, null, TimeSpan.Zero, TimeSpan.FromMinutes(1));
        }

        private void SetupEventHandlers()
        {
            // VFS status change events
            vfsManager.StatusChanged += VfsManager_StatusChanged;
            vfsManager.LogMessage += VfsManager_LogMessage;

            // Window close event
            this.Closing += MainWindow_Closing;
        }

        private async void InitializeUI()
        {
            try
            {
                AddLog(R.Get("InitializingSystem"));

                // Generate and display machine code
                await Task.Run(() =>
                {
                    string machineCode = HardwareIdHelper.GetMachineFingerprint();
                    Dispatcher.Invoke(() =>
                    {
                        txtMachineCode.Text = machineCode;
                        AddLog(R.MachineCodeGenerated(machineCode.Substring(0, 8)));
                    });
                });

                // Check system environment
                await CheckSystemEnvironment();

                // Check previous activation state
                await CheckPreviousActivationState();

                if (!isCurrentlyActivated)
                {
                    AddLog(R.Get("SystemInitializationComplete"));
                    UpdateStatus(R.Get("StatusReady"));
                }
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("SystemInitializationFailed", ex.Message));
                UpdateStatus(R.Get("InitializationFailed"));
            }
        }

        /// <summary>
        /// Check previous activation state
        /// </summary>
        private async Task CheckPreviousActivationState()
        {
            try
            {
                AddLog(R.Get("CheckingPreviousActivation"));

                // Get saved activation state
                var savedState = stateManager.GetCurrentState();

                if (savedState != null)
                {
                    AddLog(R.GetFormatted("FoundValidActivation", savedState.ActivationTime.ToString("yyyy-MM-dd HH:mm:ss")));

                    int remainingDays = stateManager.GetRemainingDays();
                    AddLog(R.GetFormatted("ActivationRemainingDays", remainingDays));

                    // Check if revalidation is needed
                    if (stateManager.ShouldRevalidate())
                    {
                        AddLog(R.Get("RevalidationNeeded"));

                        if (await PerformRevalidation(savedState))
                        {
                            AddLog(R.Get("RevalidationSuccess"));
                        }
                        else
                        {
                            AddLog(R.Get("RevalidationFailed"));
                            stateManager.ClearActivationState();
                            return;
                        }
                    }

                    // Try to restore virtual file system
                    await RestoreVirtualFileSystem(savedState);
                }
                else
                {
                    AddLog(R.Get("NoValidActivation"));
                    UpdateActivationUI(false, null);
                }
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("ActivationCheckError", ex.Message));
                UpdateActivationUI(false, null);
            }
        }

        /// <summary>
        /// Revalidate activation state
        /// </summary>
        private async Task<bool> PerformRevalidation(ActivationState state)
        {
            try
            {
                // Update heartbeat time
                stateManager.UpdateHeartbeat();

                // If has server token, try online validation
                if (!string.IsNullOrEmpty(state.ServerToken))
                {
                    // Server-side validation logic can be added here
                    AddLog(R.Get("PerformingOnlineRevalidation"));

                    // 添加实际的异步操作
                    await Task.Delay(100); // 模拟异步操作
                    // For now, return success. In actual project, should call server API for validation
                    return true;
                }

                // Offline validation: re-decrypt activation code
                if (!string.IsNullOrEmpty(state.ActivationCode))
                {
                    AddLog(R.Get("PerformingOfflineRevalidation"));

                    // 将同步操作包装为异步
                    return await Task.Run(() =>
                    {
                        byte[]? data = securityManager.ValidateAndDecrypt(state.ActivationCode);
                        return data != null && data.Length > 0;
                    });
                }

                return false;
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("RevalidationFailed", ex.Message));
                return false;
            }
        }

        /// <summary>
        /// Restore virtual file system
        /// </summary>
        private async Task RestoreVirtualFileSystem(ActivationState state)
        {
            try
            {
                AddLog(R.Get("RestoringVirtualFileSystem"));
                UpdateStatus(R.Get("StatusRestoring"));

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
                    AddLog(R.DataDecryptionSuccess(decryptedData.Length));

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

                        AddLog(R.VFSMountedSuccess(vfsManager.MountPoint));
                        UpdateStatus(R.Get("ActivationSuccessful"));
                        UpdateActivationUI(true, state);

                        // Show welcome message
                        ShowActivationWelcomeMessage(state);
                    }
                    else
                    {
                        AddLog(R.Get("VFSRestorationFailed"));
                        UpdateActivationUI(false, null);
                    }
                }
                else
                {
                    AddLog(R.Get("CannotDecryptSavedData"));
                    stateManager.ClearActivationState();
                    UpdateActivationUI(false, null);
                }
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("VFSRestorationFailed", ex.Message));
                UpdateActivationUI(false, null);
            }
        }

        /// <summary>
        /// Show activation welcome message
        /// </summary>
        private void ShowActivationWelcomeMessage(ActivationState state)
        {
            try
            {
                int remainingDays = stateManager.GetRemainingDays();
                string welcomeMessage = $"{R.Get("WelcomeBack")}\n\n" +
                                      $"{R.Get("ActivationStatusActive")}\n" +
                                      $"{R.GetFormatted("ActivationTimeLabel", state.ActivationTime.ToString("yyyy-MM-dd HH:mm:ss"))}\n" +
                                      $"{R.GetFormatted("RemainingDaysLabel", remainingDays)}\n" +
                                      $"{R.GetFormatted("VirtualFileSystemLabel", vfsManager.MountPoint)}\n\n" +
                                      $"{R.Get("XPlaneReadyMessage")}";

                MessageBox.Show(welcomeMessage, R.Get("ActivationComplete"),
                               MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("ShowingActivationInfoError", ex.Message));
            }
        }

        /// <summary>
        /// Update activation related UI
        /// </summary>
        private void UpdateActivationUI(bool isActivated, ActivationState? state)
        {
            Dispatcher.Invoke(() =>
            {
                if (isActivated && state != null)
                {
                    // Activated state
                    btnActivate.Content = R.Get("AlreadyActivated");
                    btnActivate.IsEnabled = false;

                    // Show activation info
                    int remainingDays = stateManager.GetRemainingDays();
                    txtActivationCode.Text = $"{R.Get("AlreadyActivated")} - {R.GetFormatted("RemainingDaysLabel", remainingDays)}";
                    txtActivationCode.IsEnabled = false;

                    // Show deactivate button
                    if (btnDeactivate != null)
                    {
                        btnDeactivate.IsEnabled = true;
                        btnDeactivate.Visibility = Visibility.Visible;
                    }

                    // Show activation info button
                    if (btnActivationInfo != null)
                    {
                        btnActivationInfo.IsEnabled = true;
                        btnActivationInfo.Visibility = Visibility.Visible;
                    }

                    // Update detailed activation info
                    UpdateDetailedActivationInfo(state);

                    lblVfsStatus.Text = R.GetFormatted("VFSMountedSuccess", vfsManager.MountPoint);
                    lblVfsStatus.Foreground = new SolidColorBrush(Colors.LightGreen);
                }
                else
                {
                    // Not activated state
                    btnActivate.Content = R.Get("ActivateButton");
                    btnActivate.IsEnabled = true;

                    txtActivationCode.Text = "";
                    txtActivationCode.IsEnabled = true;
                    txtActivationCode.Focus();

                    // Hide deactivate button
                    if (btnDeactivate != null)
                    {
                        btnDeactivate.IsEnabled = false;
                        btnDeactivate.Visibility = Visibility.Collapsed;
                    }

                    // Hide activation info button
                    if (btnActivationInfo != null)
                    {
                        btnActivationInfo.IsEnabled = false;
                        btnActivationInfo.Visibility = Visibility.Collapsed;
                    }

                    // Hide detailed activation info
                    HideDetailedActivationInfo();

                    lblVfsStatus.Text = R.Get("VFSNotMounted");
                    lblVfsStatus.Foreground = new SolidColorBrush(Colors.Gray);
                }
            });
        }

        /// <summary>
        /// Update detailed activation info
        /// </summary>
        private void UpdateDetailedActivationInfo(ActivationState state)
        {
            try
            {
                int remainingDays = stateManager.GetRemainingDays();

                // Show activation status title
                if (lblActivationStatusTitle != null)
                {
                    lblActivationStatusTitle.Visibility = Visibility.Visible;
                }

                // Show activation info panel
                if (spActivationInfo != null)
                {
                    spActivationInfo.Visibility = Visibility.Visible;
                }

                // Update various info
                if (lblActivationTime != null)
                {
                    lblActivationTime.Text = R.GetFormatted("ActivationTimeLabel", state.ActivationTime.ToString("yyyy-MM-dd HH:mm:ss"));
                }

                if (lblRemainingDays != null)
                {
                    var brush = remainingDays > 7 ? new SolidColorBrush(Colors.LightGreen) :
                               remainingDays > 3 ? new SolidColorBrush(Colors.Orange) :
                               new SolidColorBrush(Colors.Red);

                    lblRemainingDays.Text = R.GetFormatted("RemainingDaysLabel", remainingDays);
                    lblRemainingDays.Foreground = brush;
                }

                if (lblLastHeartbeat != null)
                {
                    var timeSinceHeartbeat = DateTime.Now - state.LastHeartbeat;
                    string heartbeatText;

                    if (timeSinceHeartbeat.TotalMinutes < 60)
                    {
                        heartbeatText = R.GetFormatted("LastHeartbeatLabel", R.GetFormatted("MinutesAgo", (int)timeSinceHeartbeat.TotalMinutes));
                    }
                    else if (timeSinceHeartbeat.TotalHours < 24)
                    {
                        heartbeatText = R.GetFormatted("LastHeartbeatLabel", R.GetFormatted("HoursAgo", (int)timeSinceHeartbeat.TotalHours));
                    }
                    else
                    {
                        heartbeatText = R.GetFormatted("LastHeartbeatLabel", R.GetFormatted("DaysAgo", (int)timeSinceHeartbeat.TotalDays));
                    }

                    lblLastHeartbeat.Text = heartbeatText;
                }
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("ShowingActivationInfoError", ex.Message));
            }
        }

        /// <summary>
        /// Hide detailed activation info
        /// </summary>
        private void HideDetailedActivationInfo()
        {
            if (lblActivationStatusTitle != null)
            {
                lblActivationStatusTitle.Visibility = Visibility.Collapsed;
            }

            if (spActivationInfo != null)
            {
                spActivationInfo.Visibility = Visibility.Collapsed;
            }
        }

        /// <summary>
        /// Activation info button event
        /// </summary>
        private void BtnActivationInfo_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (currentActivationState == null)
                {
                    MessageBox.Show(R.Get("CurrentlyNotActivated"), R.Get("Information"),
                                   MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                int remainingDays = stateManager.GetRemainingDays();
                string machineFingerprint = HardwareIdHelper.GetDisplayFingerprint();

                var timeSinceActivation = DateTime.Now - currentActivationState.ActivationTime;
                var timeSinceHeartbeat = DateTime.Now - currentActivationState.LastHeartbeat;

                string infoMessage = $"{R.Get("DetailedActivationInfo")}\n\n" +
                                   $"{R.GetFormatted("ActivationCodeLabel", currentActivationState.ActivationCode.Substring(0, Math.Min(8, currentActivationState.ActivationCode.Length)))}\n" +
                                   $"{R.GetFormatted("ActivationTimeLabel", currentActivationState.ActivationTime.ToString("yyyy-MM-dd HH:mm:ss"))}\n" +
                                   $"{R.GetFormatted("ActivatedDaysLabel", (int)timeSinceActivation.TotalDays)}\n" +
                                   $"{R.GetFormatted("RemainingDaysLabel", remainingDays)}\n" +
                                   $"{R.GetFormatted("LastHeartbeatLabel", currentActivationState.LastHeartbeat.ToString("yyyy-MM-dd HH:mm:ss"))}\n" +
                                   $"{R.GetFormatted("HeartbeatIntervalLabel", (int)timeSinceHeartbeat.TotalMinutes)}\n" +
                                   $"{R.GetFormatted("MachineFingerprintLabel", machineFingerprint)}\n" +
                                   $"{R.GetFormatted("MountPointLabel", currentActivationState.MountPoint ?? R.Get("Unknown"))}\n" +
                                   $"{R.GetFormatted("ServerTokenLabel", (!string.IsNullOrEmpty(currentActivationState.ServerToken) ? R.Get("ServerTokenAvailable") : R.Get("ServerTokenNotAvailable")))}";

                MessageBox.Show(infoMessage, R.Get("ActivationInfo"),
                               MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("ShowingActivationInfoError", ex.Message));
                MessageBox.Show(R.GetFormatted("CannotShowActivationInfo", ex.Message), R.Get("ErrorMessage"),
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Timer check activation status
        /// </summary>
        private void CheckActivationStatus(object? state)
        {
            if (isClosing) return;

            Task.Run(() =>
            {
                try
                {
                    if (isCurrentlyActivated && currentActivationState != null)
                    {
                        // Check if activation has expired
                        int remainingDays = stateManager.GetRemainingDays();

                        if (remainingDays <= 0)
                        {
                            Dispatcher.Invoke(() =>
                            {
                                AddLog(R.Get("ActivationExpired"));
                                HandleActivationExpired();
                            });
                        }
                        else if (remainingDays <= 3)
                        {
                            Dispatcher.Invoke(() =>
                            {
                                AddLog(R.GetFormatted("ActivationExpiredWarning", remainingDays));
                            });
                        }

                        // Update heartbeat
                        stateManager.UpdateHeartbeat();
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Check activation status exception: {ex.Message}");
                }
            });
        }

        /// <summary>
        /// Handle activation expired
        /// </summary>
        private void HandleActivationExpired()
        {
            try
            {
                // Clear activation state
                stateManager.ClearActivationState();
                isCurrentlyActivated = false;
                currentActivationState = null;

                // Unmount virtual file system
                vfsManager.UnmountVirtualFileSystem();

                // Update UI
                UpdateActivationUI(false, null);
                UpdateStatus(R.Get("StatusExpired"));

                // Show expiry prompt
                MessageBox.Show(R.Get("ActivationExpired"), R.Get("ActivationComplete"),
                               MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("ProcessActivationExpiredError", ex.Message));
            }
        }

        /// <summary>
        /// Deactivate button event
        /// </summary>
        private void BtnDeactivate_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var result = MessageBox.Show(
                    R.Get("ConfirmDeactivationMessage"),
                    R.Get("ConfirmDeactivation"),
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    AddLog(R.Get("UserSelectedDeactivation"));

                    // Clear activation state
                    stateManager.ClearActivationState();
                    isCurrentlyActivated = false;
                    currentActivationState = null;

                    // Unmount virtual file system
                    vfsManager.UnmountVirtualFileSystem();

                    // Update UI
                    UpdateActivationUI(false, null);
                    UpdateStatus(R.Get("StatusDeactivated"));

                    AddLog(R.Get("ActivationCancelled"));
                    MessageBox.Show(R.Get("DeactivationCompleteMessage"), R.Get("DeactivationComplete"),
                                   MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("DeactivationError", ex.Message));
                MessageBox.Show(R.GetFormatted("DeactivationFailed", ex.Message), R.Get("ErrorMessage"),
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task CheckSystemEnvironment()
        {
            AddLog(R.Get("SystemEnvironmentCheck"));

            await Task.Run(() =>
            {
                // Check administrator privileges
                bool isAdmin = IsRunningAsAdministrator();
                if (!isAdmin)
                {
                    AddLog(R.Get("AdminPrivilegesWarning"));
                }
                else
                {
                    AddLog(R.Get("AdminPrivilegesCheck"));
                }

                // Check Dokan driver - 使用改进的检查方法
                var dokanResult = CheckDokanInstallation();
                AddLog(dokanResult.Message);
                if (!string.IsNullOrEmpty(dokanResult.Details))
                {
                    AddLog($"Dokan Details: {dokanResult.Details}");
                }

                // Check Dokan services using the new method
                var serviceResult = CheckDokanServiceWithWMI();
                if (serviceResult.ServicesFound)
                {
                    AddLog($"Found {serviceResult.ServiceCount} Dokan services");
                    foreach (var detail in serviceResult.ServiceDetails)
                    {
                        AddLog($"  {detail}");
                    }
                }
                else
                {
                    AddLog("No Dokan services found");
                    if (!string.IsNullOrEmpty(serviceResult.ErrorMessage))
                    {
                        AddLog($"Service check error: {serviceResult.ErrorMessage}");
                    }
                }

                // Check C++ DLL
                string dllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CryptoEngine.dll");
                if (File.Exists(dllPath))
                {
                    AddLog(R.Get("CryptoEngineDllFound"));

                    // Test DLL functionality
                    try
                    {
                        var testResult = securityManager.TestCryptoDll();
                        if (testResult)
                        {
                            AddLog(R.Get("CryptoEngineTestPassed"));
                        }
                        else
                        {
                            AddLog(R.Get("CryptoEngineTestFailed"));
                        }
                    }
                    catch (Exception ex)
                    {
                        AddLog(R.GetFormatted("CryptoEngineTestException", ex.Message));
                    }
                }
                else
                {
                    AddLog(R.Get("CryptoEngineDllNotFound"));
                }
            });
        }

        /// <summary>
        /// 检查 Dokan 服务（使用 WMI 方式）
        /// </summary>
        /// <returns>服务检查结果</returns>
        private DokanServiceCheckResult CheckDokanServiceWithWMI()
        {
            var result = new DokanServiceCheckResult
            {
                ServicesFound = false,
                ServiceCount = 0,
                ServiceDetails = new List<string>(),
                ErrorMessage = ""
            };

            try
            {
                // 使用 ServiceController 检查服务（更简单的方式）
                try
                {
                    var services = ServiceController.GetServices();
                    var dokanServices = services.Where(s =>
                        s.ServiceName.ToLower().Contains("dokan") ||
                        s.DisplayName.ToLower().Contains("dokan")).ToList();

                    if (dokanServices.Any())
                    {
                        result.ServicesFound = true;
                        result.ServiceCount = dokanServices.Count;

                        foreach (var service in dokanServices)
                        {
                            try
                            {
                                result.ServiceDetails.Add($"{service.ServiceName}: {service.Status} ({service.DisplayName})");
                            }
                            catch (Exception ex)
                            {
                                result.ServiceDetails.Add($"{service.ServiceName}: Status unavailable ({ex.Message})");
                            }
                        }
                    }

                    return result;
                }
                catch (Exception serviceEx)
                {
                    result.ErrorMessage = $"ServiceController error: {serviceEx.Message}";

                    // 如果 ServiceController 失败，尝试使用 WMI
                    return CheckDokanServiceWithWMIFallback();
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = $"Service check failed: {ex.Message}";
                return result;
            }
        }

        /// <summary>
        /// 使用 WMI 检查 Dokan 服务（备用方法）
        /// </summary>
        /// <returns>服务检查结果</returns>
        private DokanServiceCheckResult CheckDokanServiceWithWMIFallback()
        {
            var result = new DokanServiceCheckResult
            {
                ServicesFound = false,
                ServiceCount = 0,
                ServiceDetails = new List<string>(),
                ErrorMessage = ""
            };

            try
            {
                // 如果需要 WMI，可以添加 System.Management NuGet 包
                // 这里提供一个简化的检查方法
                using (var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT * FROM Win32_Service WHERE Name LIKE '%dokan%' OR DisplayName LIKE '%dokan%'"))
                {
                    var services = searcher.Get();

                    foreach (System.Management.ManagementObject service in services)
                    {
                        result.ServicesFound = true;
                        result.ServiceCount++;

                        string serviceName = service["Name"]?.ToString() ?? "Unknown";
                        string displayName = service["DisplayName"]?.ToString() ?? "Unknown";
                        string state = service["State"]?.ToString() ?? "Unknown";

                        result.ServiceDetails.Add($"{serviceName}: {state} ({displayName})");
                    }
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = $"WMI query failed: {ex.Message}";
            }

            return result;
        }

        /// <summary>
        /// 改进的Dokan安装检查
        /// </summary>
        /// <returns>检查结果</returns>
        private DokanCheckResult CheckDokanInstallation()
        {
            var result = new DokanCheckResult();

            try
            {
                // 方法1: 检查传统注册表位置
                bool registryCheck1 = false;
                try
                {
                    using var key1 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Dokan\DokanLibrary");
                    registryCheck1 = key1 != null;
                }
                catch { }

                // 方法2: 检查64位注册表位置
                bool registryCheck2 = false;
                try
                {
                    using var key2 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Dokan\DokanLibrary");
                    registryCheck2 = key2 != null;
                }
                catch { }

                // 方法3: 检查系统文件
                bool fileCheck = false;
                string[] dokanPaths = {
                    @"C:\Windows\System32\drivers\dokan2.sys",
                    @"C:\Windows\System32\drivers\dokan1.sys",
                    @"C:\Windows\System32\dokan2.dll",
                    @"C:\Windows\System32\dokan1.dll",
                    @"C:\Windows\SysWOW64\dokan2.dll",
                    @"C:\Windows\SysWOW64\dokan1.dll"
                };

                foreach (string path in dokanPaths)
                {
                    if (File.Exists(path))
                    {
                        fileCheck = true;
                        result.DetectedFiles.Add(path);
                    }
                }

                // 方法4: 检查服务
                bool serviceCheck = false;
                try
                {
                    var services = ServiceController.GetServices();
                    serviceCheck = services.Any(s =>
                        s.ServiceName.ToLower().Contains("dokan") ||
                        s.DisplayName.ToLower().Contains("dokan"));
                }
                catch { }

                // 方法5: 尝试加载DokanNet.dll
                bool dokanNetCheck = false;
                try
                {
                    // 检查当前程序目录中的DokanNet.dll
                    string dokanNetPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "DokanNet.dll");
                    dokanNetCheck = File.Exists(dokanNetPath);
                }
                catch { }

                // 综合判断
                result.RegistryFound = registryCheck1 || registryCheck2;
                result.FilesFound = fileCheck;
                result.ServiceFound = serviceCheck;
                result.DokanNetFound = dokanNetCheck;

                // 设置整体状态
                if (result.DokanNetFound && (result.RegistryFound || result.FilesFound || result.ServiceFound))
                {
                    result.IsInstalled = true;
                    result.Status = DokanStatus.FullyInstalled;
                    result.Message = R.Get("DokanDriverFullyInstalled");
                }
                else if (result.DokanNetFound)
                {
                    result.IsInstalled = true;
                    result.Status = DokanStatus.DokanNetOnly;
                    result.Message = R.Get("DokanNetFoundButDriverMissing");
                }
                else if (result.RegistryFound || result.FilesFound || result.ServiceFound)
                {
                    result.IsInstalled = false;
                    result.Status = DokanStatus.PartialInstallation;
                    result.Message = R.Get("DokanPartialInstallation");
                }
                else
                {
                    result.IsInstalled = false;
                    result.Status = DokanStatus.NotInstalled;
                    result.Message = R.Get("DokanDriverNotInstalled");
                }

                // 添加详细信息
                var details = new List<string>();
                if (result.RegistryFound) details.Add("Registry: Found");
                if (result.FilesFound) details.Add($"Files: Found ({result.DetectedFiles.Count})");
                if (result.ServiceFound) details.Add("Service: Found");
                if (result.DokanNetFound) details.Add("DokanNet.dll: Found");

                if (details.Any())
                {
                    result.Details = string.Join(", ", details);
                }
                else
                {
                    result.Details = "No Dokan components detected";
                }

                return result;
            }
            catch (Exception ex)
            {
                result.IsInstalled = false;
                result.Status = DokanStatus.CheckError;
                result.Message = R.GetFormatted("DokanCheckError", ex.Message);
                result.Details = ex.Message;
                return result;
            }
        }

        private async void BtnActivate_Click(object sender, RoutedEventArgs e)
        {
            // If closing, don't allow activation
            if (isClosing)
            {
                return;
            }

            // If already activated, prompt user
            if (isCurrentlyActivated)
            {
                MessageBox.Show(R.Get("SystemAlreadyActivated"), R.Get("Information"),
                               MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string activationCode = txtActivationCode.Text.Trim();
            if (string.IsNullOrEmpty(activationCode))
            {
                MessageBox.Show(R.Get("EnterActivationCodeMessage"), R.Get("InputRequired"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Disable activate button to prevent duplicate clicks
            btnActivate.IsEnabled = false;
            btnActivate.Content = R.Get("ActivatingButton");

            cancellationTokenSource = new CancellationTokenSource();

            try
            {
                UpdateStatus(R.Get("StatusValidating"));
                AddLog(R.GetFormatted("StartingActivation", activationCode.Substring(0, Math.Min(8, activationCode.Length))));

                // Step 1: Online verification
                bool onlineSuccess = await PerformOnlineActivation(activationCode);

                if (!onlineSuccess)
                {
                    // Online verification failed, ask user if try offline verification
                    var result = MessageBox.Show(
                        R.Get("OnlineActivationFailedMessage"),
                        R.Get("OnlineVerificationFailed"),
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question);

                    if (result == MessageBoxResult.Yes)
                    {
                        AddLog(R.Get("TryingOfflineVerification"));
                        await PerformOfflineActivation(activationCode);
                    }
                    else
                    {
                        AddLog(R.Get("UserCancelledOfflineVerification"));
                        UpdateStatus(R.Get("ActivationStatusCancelled"));
                    }
                }
            }
            catch (OperationCanceledException)
            {
                AddLog(R.Get("ActivationStatusCancelled"));
                UpdateStatus(R.Get("ActivationStatusCancelled"));
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("ActivationErrorMessage", ex.Message));
                UpdateStatus(R.Get("ActivationFailed"));
                MessageBox.Show(R.GetFormatted("ActivationErrorMessage", ex.Message), R.Get("ErrorMessage"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                // Restore button state (if not activated)
                if (!isCurrentlyActivated)
                {
                    btnActivate.IsEnabled = true;
                    btnActivate.Content = R.Get("ActivateButton");
                }
                cancellationTokenSource?.Dispose();
                cancellationTokenSource = null;
            }
        }

        private async Task<bool> PerformOnlineActivation(string activationCode)
        {
            try
            {
                AddLog(R.Get("ConnectingToServer"));

                // Generate machine code
                string machineCode = HardwareIdHelper.GetMachineFingerprint();

                // Construct request data (using ServerConfig)
                var requestData = ServerConfig.CreateActivationRequest(activationCode, machineCode);
                string requestJson = System.Text.Json.JsonSerializer.Serialize(requestData);

                AddLog(R.Get("SendingActivationRequest"));

                string response = "";
                bool requestSuccessful = false;

                // Get all available server URLs
                var serverUrls = ServerConfig.GetAllServerUrls();

                // Try each server in sequence
                foreach (string serverUrl in serverUrls)
                {
                    try
                    {
                        AddLog(R.GetFormatted("TryingServerConnection", serverUrl));

                        response = await networkManager.HttpPostAsync(
                            requestJson,
                            ServerConfig.ACTIVATION_ENDPOINT,
                            serverUrl
                        );

                        // If request successful, break loop
                        requestSuccessful = true;
                        AddLog(R.GetFormatted("ServerConnectionSuccess", serverUrl));
                        break;
                    }
                    catch (Exception ex)
                    {
                        AddLog(R.GetFormatted("ServerConnectionFailed", serverUrl, ex.Message));

                        // If not the last server, continue to next
                        if (serverUrl != serverUrls[serverUrls.Length - 1])
                        {
                            AddLog(R.Get("TryingNextServer"));
                            continue;
                        }
                    }
                }

                // If all servers failed
                if (!requestSuccessful)
                {
                    AddLog(R.Get("AllServersFailed"));
                    return false;
                }

                AddLog(R.Get("ProcessingServerResponse"));

                // Verify response format
                if (!ServerConfig.IsValidResponse(response))
                {
                    AddLog(R.Get("InvalidServerResponse"));
                    AddLog(R.GetFormatted("ServerResponseContent", response));
                    return false;
                }

                // Check if it's a success response
                if (!ServerConfig.IsSuccessResponse(response))
                {
                    // Activation failed, extract error info
                    string errorMessage = ServerConfig.ExtractErrorMessage(response);
                    AddLog(R.GetFormatted("OnlineActivationFailed", errorMessage));
                    MessageBox.Show(R.GetFormatted("ActivationErrorMessage", errorMessage), R.Get("ActivationFailed"),
                                   MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }

                // Parse success response
                var jsonDoc = System.Text.Json.JsonDocument.Parse(response);
                var root = jsonDoc.RootElement;

                // Try to get token
                string? serverToken = null;
                if (root.TryGetProperty("token", out var tokenProp))
                {
                    serverToken = tokenProp.GetString();
                }
                else if (root.TryGetProperty("activation_token", out var activationTokenProp))
                {
                    serverToken = activationTokenProp.GetString();
                }
                else if (root.TryGetProperty("access_token", out var accessTokenProp))
                {
                    serverToken = accessTokenProp.GetString();
                }
                else if (root.TryGetProperty("data", out var dataProp))
                {
                    if (dataProp.TryGetProperty("token", out var dataTokenProp))
                    {
                        serverToken = dataTokenProp.GetString();
                    }
                }

                // Handle successful activation
                if (!string.IsNullOrEmpty(serverToken))
                {
                    AddLog(R.Get("OnlineActivationSuccess"));

                    // Use server token to decrypt and save state
                    return await ProcessServerTokenAndSave(serverToken, activationCode);
                }
                else
                {
                    AddLog(R.Get("OnlineActivationSuccessNoToken"));
                    // If no token but activation successful, use activation code itself for decryption
                    return await ProcessActivationWithoutTokenAndSave(activationCode);
                }
            }
            catch (System.TimeoutException)
            {
                AddLog(R.Get("NetworkTimeout"));
                MessageBox.Show(R.Get("NetworkTimeoutMessage"), R.Get("NetworkTimeout"),
                               MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            catch (System.Net.Http.HttpRequestException ex)
            {
                AddLog(R.GetFormatted("NetworkErrorMessage", ex.Message));
                MessageBox.Show(R.GetFormatted("NetworkErrorMessage", ex.Message), R.Get("NetworkError"),
                               MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("OnlineActivationException", ex.Message));
                MessageBox.Show(R.GetFormatted("ActivationErrorMessage", ex.Message), R.Get("ActivationError"),
                               MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        private async Task<bool> ProcessServerTokenAndSave(string serverToken, string activationCode)
        {
            try
            {
                AddLog(R.Get("DecryptingData"));
                UpdateStatus(R.Get("StatusDecrypting"));

                // Use SecurityManager to decrypt server token
                byte[]? decryptedData = await Task.Run(() => securityManager.DecryptWithToken(serverToken));

                if (decryptedData != null && decryptedData.Length > 0)
                {
                    AddLog(R.DataDecryptionSuccess(decryptedData.Length));

                    // Verify decrypted data integrity
                    string content = System.Text.Encoding.UTF8.GetString(decryptedData);
                    if (content.Contains("# X-Plane") || content.Contains("v ") || content.Contains("f "))
                    {
                        AddLog(R.Get("DataIntegrityCheckPassed"));

                        // Mount virtual file system
                        bool mounted = await MountVirtualFileSystem(decryptedData);

                        if (mounted)
                        {
                            // Save activation state
                            bool saved = stateManager.SaveActivationState(activationCode, serverToken, vfsManager.MountPoint);
                            if (saved)
                            {
                                AddLog(R.Get("ActivationStateSaved"));
                                isCurrentlyActivated = true;
                                currentActivationState = stateManager.GetCurrentState();
                                UpdateActivationUI(true, currentActivationState);
                            }
                            else
                            {
                                AddLog(R.Get("ActivationStateSaveFailed"));
                            }
                            return true;
                        }
                        return false;
                    }
                    else
                    {
                        AddLog(R.Get("DataIntegrityCheckFailed"));
                        return false;
                    }
                }
                else
                {
                    AddLog(R.Get("DataDecryptionFailed"));
                    return false;
                }
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("TokenProcessingException", ex.Message));
                return false;
            }
        }

        /// <summary>
        /// Process activation without token and save state
        /// </summary>
        private async Task<bool> ProcessActivationWithoutTokenAndSave(string activationCode)
        {
            try
            {
                AddLog(R.Get("UsingActivationCodeDecryption"));
                UpdateStatus(R.Get("StatusDecrypting"));

                // Directly use activation code for decryption
                byte[]? decryptedData = await Task.Run(() => securityManager.ValidateAndDecrypt(activationCode));

                if (decryptedData != null && decryptedData.Length > 0)
                {
                    AddLog(R.DataDecryptionSuccess(decryptedData.Length));

                    // Verify decrypted data integrity
                    if (securityManager.ValidateDecryptedData(decryptedData))
                    {
                        AddLog(R.Get("DataIntegrityCheckPassed"));

                        // Mount virtual file system
                        bool mounted = await MountVirtualFileSystem(decryptedData);

                        if (mounted)
                        {
                            // Save activation state
                            bool saved = stateManager.SaveActivationState(activationCode, null, vfsManager.MountPoint);
                            if (saved)
                            {
                                AddLog(R.Get("ActivationStateSaved"));
                                isCurrentlyActivated = true;
                                currentActivationState = stateManager.GetCurrentState();
                                UpdateActivationUI(true, currentActivationState);
                            }
                            else
                            {
                                AddLog(R.Get("ActivationStateSaveFailed"));
                            }
                            return true;
                        }
                        return false;
                    }
                    else
                    {
                        AddLog(R.Get("DataIntegrityCheckFailed"));
                        return false;
                    }
                }
                else
                {
                    AddLog(R.Get("ActivationCodeDecryptionFailed"));
                    return false;
                }
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("ActivationCodeProcessingException", ex.Message));
                return false;
            }
        }

        private async Task PerformOfflineActivation(string activationCode)
        {
            try
            {
                AddLog(R.Get("TryingOfflineVerification"));
                UpdateStatus(R.Get("StatusValidating"));

                // Use local C# backup method for verification
                byte[]? decryptedData = await Task.Run(() => securityManager.ValidateAndDecrypt(activationCode));

                if (decryptedData != null && decryptedData.Length > 0)
                {
                    AddLog(R.Get("OfflineActivationSuccess"));

                    // Mount virtual file system
                    bool mounted = await MountVirtualFileSystem(decryptedData);
                    if (mounted)
                    {
                        // Save activation state
                        bool saved = stateManager.SaveActivationState(activationCode, null, vfsManager.MountPoint);
                        if (saved)
                        {
                            AddLog(R.Get("ActivationStateSaved"));
                            isCurrentlyActivated = true;
                            currentActivationState = stateManager.GetCurrentState();
                            UpdateActivationUI(true, currentActivationState);
                        }
                        else
                        {
                            AddLog(R.Get("ActivationStateSaveFailed"));
                        }
                    }
                    else
                    {
                        throw new Exception(R.Get("VFSMountFailed"));
                    }
                }
                else
                {
                    throw new Exception(R.Get("ActivationCodeDecryptionFailed"));
                }
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("OfflineActivationFailed", ex.Message));
                MessageBox.Show(R.GetFormatted("OfflineActivationFailedMessage", ex.Message), R.Get("ActivationFailed"),
                               MessageBoxButton.OK, MessageBoxImage.Error);
                throw;
            }
        }

        private async Task<bool> MountVirtualFileSystem(byte[] decryptedData)
        {
            try
            {
                AddLog(R.Get("StartingVirtualFileSystem"));
                UpdateStatus(R.Get("StatusMountingVFS"));

                // Use fixed VFS manager that correctly waits for mount completion
                bool mounted = await Task.Run(() =>
                    vfsManager.MountVirtualFileSystem(
                        decryptedData,
                        cancellationTokenSource?.Token ?? CancellationToken.None
                    )
                );

                if (mounted)
                {
                    AddLog(R.VFSMountedSuccess(vfsManager.MountPoint));
                    UpdateStatus(R.Get("ActivationSuccessful"));

                    Dispatcher.Invoke(() =>
                    {
                        lblVfsStatus.Text = R.VFSMountedSuccess(vfsManager.MountPoint);
                        lblVfsStatus.Foreground = new SolidColorBrush(Colors.LightGreen);
                    });

                    MessageBox.Show(R.ActivationSuccessMessageFormatted(vfsManager.MountPoint),
                                   R.Get("ActivationComplete"), MessageBoxButton.OK, MessageBoxImage.Information);
                    return true;
                }
                else
                {
                    AddLog(R.Get("VFSMountFailed"));
                    UpdateStatus(R.Get("VFSMountFailed"));
                    MessageBox.Show(R.Get("VFSMountFailedMessage"),
                                   R.Get("VFSMountFailed"), MessageBoxButton.OK, MessageBoxImage.Error);
                    return false;
                }
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("VFSMountException", ex.Message));
                UpdateStatus(R.Get("VFSMountFailed"));
                MessageBox.Show(R.GetFormatted("VFSMountException", ex.Message), R.Get("ErrorMessage"),
                               MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        private async void BtnDiagnostic_Click(object sender, RoutedEventArgs e)
        {
            if (isClosing) return;

            try
            {
                btnDiagnostic.IsEnabled = false;
                btnDiagnostic.Content = R.Get("RunningDiagnostic");

                AddLog(R.Get("StartingSystemDiagnostic"));
                UpdateStatus(R.Get("StartingSystemDiagnostic"));

                // Create diagnostics
                var diagnostics = new SystemDiagnostics(securityManager, vfsManager, networkManager);

                // Run diagnostics
                var report = await diagnostics.RunFullDiagnostics();

                // Show diagnostic results
                ShowDiagnosticReport(report);

                AddLog(R.Get("SystemDiagnosticComplete"));
                UpdateStatus(R.Get("DiagnosticCompleted"));
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("DiagnosticProcessException", ex.Message));
                MessageBox.Show(R.GetFormatted("DiagnosticFailed", ex.Message), R.Get("ErrorMessage"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                btnDiagnostic.IsEnabled = true;
                btnDiagnostic.Content = R.Get("DiagnosticButton");
            }
        }

        private void ShowDiagnosticReport(DiagnosticReport report)
        {
            var window = new DiagnosticWindow(report)
            {
                Owner = this
            };
            window.ShowDialog();
        }

        private void BtnClearLog_Click(object sender, RoutedEventArgs e)
        {
            if (isClosing) return;

            txtActivationLog.Clear();
            AddLog(R.Get("LogCleared"));
        }

        private void BtnSaveLog_Click(object sender, RoutedEventArgs e)
        {
            if (isClosing) return;

            try
            {
                var saveDialog = new SaveFileDialog
                {
                    Title = R.Get("SaveActivationLog"),
                    Filter = R.Get("TextFiles"),
                    FileName = $"XPlane_Activation_Log_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
                };

                if (saveDialog.ShowDialog() == true)
                {
                    File.WriteAllText(saveDialog.FileName, txtActivationLog.Text);
                    AddLog(R.GetFormatted("LogSaved", saveDialog.FileName));
                    MessageBox.Show(R.Get("LogSaveSuccess"), R.Get("LogSaveComplete"), MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                AddLog(R.GetFormatted("LogSaveFailed", ex.Message));
                MessageBox.Show(R.GetFormatted("LogSaveFailed", ex.Message), R.Get("ErrorMessage"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
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
                            lblNetworkStatus.Text = R.Get("NetworkOnline");
                            lblNetworkStatus.Foreground = new SolidColorBrush(Colors.LightGreen);
                            lblConnectionStatus.Text = R.Get("ConnectionOnline");
                            statusIndicator.Fill = new SolidColorBrush(Colors.LightGreen);
                        }
                        else
                        {
                            lblNetworkStatus.Text = R.Get("NetworkOffline");
                            lblNetworkStatus.Foreground = new SolidColorBrush(Colors.Orange);
                            lblConnectionStatus.Text = R.Get("ConnectionOffline");
                            statusIndicator.Fill = new SolidColorBrush(Colors.Orange);
                        }
                    });
                }
                catch
                {
                    Dispatcher.Invoke(() =>
                    {
                        lblNetworkStatus.Text = R.Get("NetworkError");
                        lblNetworkStatus.Foreground = new SolidColorBrush(Colors.Red);
                        lblConnectionStatus.Text = R.Get("ConnectionError");
                        statusIndicator.Fill = new SolidColorBrush(Colors.Red);
                    });
                }
            });
        }

        private void VfsManager_StatusChanged(object? sender, VfsStatusEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                AddLog(R.GetFormatted("VFSStatus", e.Message));

                switch (e.Status)
                {
                    case VfsStatus.Mounted:
                        lblVfsStatus.Text = R.Get("VFSMounted");
                        lblVfsStatus.Foreground = new SolidColorBrush(Colors.LightGreen);
                        break;
                    case VfsStatus.Mounting:
                        lblVfsStatus.Text = R.Get("VFSMounting");
                        lblVfsStatus.Foreground = new SolidColorBrush(Colors.Yellow);
                        break;
                    case VfsStatus.Error:
                        lblVfsStatus.Text = R.Get("VFSError");
                        lblVfsStatus.Foreground = new SolidColorBrush(Colors.Red);
                        break;
                    case VfsStatus.Unmounted:
                        lblVfsStatus.Text = R.Get("VFSNotMounted");
                        lblVfsStatus.Foreground = new SolidColorBrush(Colors.Gray);
                        break;
                }
            });
        }

        private void VfsManager_LogMessage(object? sender, string e)
        {
            Dispatcher.Invoke(() => AddLog($"VFS: {e}"));
        }

        private void AddLog(string message)
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            string logEntry = $"[{timestamp}] {message}\r\n";

            Dispatcher.Invoke(() =>
            {
                txtActivationLog.AppendText(logEntry);
                txtActivationLog.ScrollToEnd();
            });
        }

        private void UpdateStatus(string status)
        {
            Dispatcher.Invoke(() =>
            {
                lblStatus.Text = status;
            });
        }

        private bool IsRunningAsAdministrator()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 旧的方法保持兼容性
        /// </summary>
        private bool IsDokanInstalled()
        {
            var result = CheckDokanInstallation();
            return result.IsInstalled;
        }

        // ===== Code to fix closing hang issues =====

        private void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            // Prevent duplicate closing
            lock (closingLock)
            {
                if (isClosing)
                {
                    return;
                }
                isClosing = true;
            }

            try
            {
                AddLog(R.Get("AppClosing"));

                // Create background task to execute close operations
                var closeTask = Task.Run(() =>
                {
                    try
                    {
                        // Cancel all async operations
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
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Close exception: {ex.Message}");
                    }
                });

                // Wait for close completion, max 3 seconds
                if (!closeTask.Wait(3000))
                {
                    AddLog(R.Get("CloseTimeout"));
                    Environment.Exit(0); // Force exit
                }
                else
                {
                    AddLog(R.Get("AppClosed"));
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Close exception: {ex.Message}");
                Environment.Exit(0); // If any exception, force exit
            }
        }
    }

    // 辅助类和枚举
    public enum DokanStatus
    {
        NotInstalled,
        PartialInstallation,
        DokanNetOnly,
        FullyInstalled,
        CheckError
    }

    public class DokanCheckResult
    {
        public bool IsInstalled { get; set; }
        public DokanStatus Status { get; set; }
        public string Message { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public bool RegistryFound { get; set; }
        public bool FilesFound { get; set; }
        public bool ServiceFound { get; set; }
        public bool DokanNetFound { get; set; }
        public List<string> DetectedFiles { get; set; } = new List<string>();
    }

    // 添加 Dokan 服务检查结果类
    public class DokanServiceCheckResult
    {
        public bool ServicesFound { get; set; }
        public int ServiceCount { get; set; }
        public List<string> ServiceDetails { get; set; } = new List<string>();
        public string ErrorMessage { get; set; } = "";
    }
}