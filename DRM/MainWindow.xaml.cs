using DRM.VFS;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using XPlaneActivator.Helpers;
using XPlaneActivator.Services;

namespace XPlaneActivator
{
    /// <summary>
    /// MainWindow with real file decryption only - no fake file generation
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
        // State Management - 分离激活状态和VFS状态，只使用真实文件
        // =====================================================
        private volatile bool isClosing = false;
        private readonly object closingLock = new object();
        private CancellationTokenSource? cancellationTokenSource;
        private CancellationTokenSource? initializationCts;

        // 分离的状态管理
        private bool isActivated = false;           // 激活状态
        private bool isVfsMounted = false;          // VFS挂载状态
        private ActivationState? currentActivationState = null;

        // 真实文件状态信息
        private int mountedFileCount = 0;           // 挂载的真实文件数量
        private long totalMountedSize = 0;          // 总挂载大小
        private List<string> mountedFileNames = new List<string>(); // 挂载的真实文件名列表

        // =====================================================
        // Core Managers
        // =====================================================
        private readonly NetworkManager networkManager;
        private readonly SecurityManager securityManager;
        private readonly VirtualFileSystemManager vfsManager;
        private readonly ActivationStateManager stateManager;

        // =====================================================
        // Timer Management - 修复Timer死锁问题
        // =====================================================
        private Timer? networkCheckTimer;
        private Timer? activationCheckTimer;
        private Timer? vfsCheckTimer;

        // 防止Timer回调重入
        private volatile bool networkCheckRunning = false;
        private volatile bool activationCheckRunning = false;
        private volatile bool vfsCheckRunning = false;

        // =====================================================
        // Constructor and Initialization
        // =====================================================
        public MainWindow()
        {
            InitializeComponent();

            try
            {
                // 使用正确的X-Plane objects目录路径
                string xplaneObjectsPath = @"D:\steam\steamapps\common\X-Plane 12\Aircraft\MyPlane\777X\objects";

                // Initialize core managers
                networkManager = new NetworkManager();
                securityManager = new SecurityManager();
                vfsManager = new VirtualFileSystemManager(xplaneObjectsPath, VfsAccessMode.WhitelistOnly);
                stateManager = new ActivationStateManager();

                // Initialize encrypted files
                InitializationHelper.InitializeEncryptedFiles(securityManager);

                // Initialize services
                var serviceContainer = CreateServiceContainer();
                activationService = serviceContainer.GetService<IActivationService>();
                systemCheckService = serviceContainer.GetService<ISystemCheckService>();
                uiController = serviceContainer.GetService<IUIController>();

                // Setup event handlers
                SetupEventHandlers();

                // 延迟启动Timer以避免初始化冲突
                this.Loaded += MainWindow_Loaded;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[MainWindow] Constructor exception: {ex.Message}");
                MessageBox.Show($"Initialization failed: {ex.Message}", "Startup Error",
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                // 在UI完全加载后再启动异步初始化
                await Task.Delay(100); // 给UI一些时间完成渲染

                // 启动异步初始化，但不阻塞UI
                _ = SafeInitializeAsync();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[MainWindow] Loaded exception: {ex.Message}");
            }
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
            try
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
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[MainWindow] SetupEventHandlers exception: {ex.Message}");
            }
        }

        // =====================================================
        // 修复的异步初始化 - 只使用真实文件
        // =====================================================
        private async Task SafeInitializeAsync()
        {
            initializationCts = new CancellationTokenSource();

            try
            {
                await InitializeAsync();
            }
            catch (OperationCanceledException)
            {
                uiController.AddLog("Initialization was cancelled");
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Initialization error: {ex.Message}");
                uiController.UpdateStatus("Initialization failed");

                // 不要显示阻塞性MessageBox，使用非阻塞方式
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    uiController.ShowMessage($"Initialization failed: {ex.Message}", "Error", true);
                }));
            }
            finally
            {
                initializationCts?.Dispose();
                initializationCts = null;
            }
        }

        private async Task InitializeAsync()
        {
            var cancellationToken = initializationCts?.Token ?? CancellationToken.None;

            try
            {
                uiController.AddLog("========== X-Plane DRM Activator Starting (Real Files Only) ==========");
                uiController.AddLog($"VFS Mount Point: {vfsManager.MountPoint}");
                uiController.AddLog($"Real File VFS Manager: {vfsManager.GetType().Name}");
                uiController.AddLog($"CryptoEngine.dll Mode: True file decryption only");
                uiController.UpdateStatus("Initializing real file decryption system...");

                // 设置超时以防止初始化卡死
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                // Initialize encrypted file system with timeout
                uiController.AddLog("Setting up real encrypted file system...");

                bool encryptedSystemReady = await Task.Run(async () =>
                {
                    try
                    {
                        return await InitializationHelper.InitializeEncryptedFileSystemAsync(
                            securityManager, null).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Encrypted system init error: {ex.Message}");
                        return false;
                    }
                }, combinedCts.Token);

                if (encryptedSystemReady)
                {
                    uiController.AddLog("✓ Real encrypted file system initialized successfully");

                    // 显示真实加密文件信息
                    var encryptedFiles = securityManager.GetEncryptedFiles();
                    uiController.AddLog($"Available real encrypted files: {encryptedFiles.Count}");

                    if (encryptedFiles.Count > 0)
                    {
                        uiController.AddLog("Real encrypted file manifest:");
                        int displayCount = 0;
                        foreach (var file in encryptedFiles.Values.Take(5))
                        {
                            uiController.AddLog($"  - {file.RelativePath} ({FormatFileSize(file.OriginalSize)}) -> {file.EncryptedFile}");
                            displayCount++;
                        }

                        if (encryptedFiles.Count > 5)
                        {
                            uiController.AddLog($"  ... and {encryptedFiles.Count - 5} more real files");
                        }
                    }
                }
                else
                {
                    uiController.AddLog("⚠ Warning: Real encrypted file system initialization failed");
                }

                // Generate machine code with timeout
                await Task.Run(() =>
                {
                    try
                    {
                        string machineCode = HardwareIdHelper.GetMachineFingerprint();
                        Dispatcher.BeginInvoke(new Action(() =>
                        {
                            txtMachineCode.Text = machineCode;
                            uiController.AddLog($"Machine code generated: {machineCode.Substring(0, 8)}...");
                        }));
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Machine code generation error: {ex.Message}");
                    }
                }, combinedCts.Token);

                // System environment check with timeout
                await PerformSystemCheckAsync(combinedCts.Token);

                // Check previous activation with timeout
                await CheckPreviousActivationAsync(combinedCts.Token);

                // 更新初始UI状态
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    UpdateCombinedUIState();

                    if (!isActivated)
                    {
                        uiController.AddLog("System initialization complete, waiting for activation...");
                        uiController.UpdateStatus("Ready - Please enter activation code (Real Files Mode)");
                    }
                }));

                // 只有在初始化成功后才启动定时器
                StartTimersAfterInitialization();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                uiController.AddLog("Initialization cancelled by user");
                throw;
            }
            catch (OperationCanceledException)
            {
                uiController.AddLog("Initialization timed out");
                uiController.UpdateStatus("Initialization timeout - some features may not work");

                // 即使超时也启动基本功能
                StartTimersAfterInitialization();
            }
        }

        // =====================================================
        // 修复的Timer管理 - 防止重入和死锁
        // =====================================================
        private void StartTimersAfterInitialization()
        {
            try
            {
                // 启动Timer，但设置更安全的间隔
                networkCheckTimer = new Timer(SafeCheckNetworkStatus, null,
                    TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(45)); // 减少频率

                activationCheckTimer = new Timer(SafeCheckActivationStatus, null,
                    TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(2)); // 减少频率

                vfsCheckTimer = new Timer(SafeCheckVfsStatus, null,
                    TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(30)); // 大幅减少频率

                uiController.AddLog("Background monitoring started (Real Files Mode)");
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Timer startup error: {ex.Message}");
            }
        }

        // 安全的网络状态检查 - 防止重入
        private void SafeCheckNetworkStatus(object? state)
        {
            if (isClosing || networkCheckRunning) return;

            networkCheckRunning = true;

            _ = Task.Run(async () =>
            {
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    bool isConnected = await networkManager.TestServerConnectionAsync(ServerConfig.BASE_URL);

                    if (isClosing) return;

                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        if (isClosing) return;

                        try
                        {
                            if (isConnected)
                            {
                                lblNetworkStatus.Content = "Network Online (lars-store.kz)";
                                lblNetworkStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.LightGreen);
                                lblConnectionStatus.Content = "Online";
                                statusIndicator.Fill = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.LightGreen);
                            }
                            else
                            {
                                lblNetworkStatus.Content = "Network Disconnected";
                                lblNetworkStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Orange);
                                lblConnectionStatus.Content = "Offline";
                                statusIndicator.Fill = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Orange);
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"Network status UI update error: {ex.Message}");
                        }
                    }));
                }
                catch (Exception ex)
                {
                    if (isClosing) return;

                    System.Diagnostics.Debug.WriteLine($"Network check error: {ex.Message}");

                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        if (isClosing) return;

                        try
                        {
                            lblNetworkStatus.Content = "Network Error";
                            lblNetworkStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Red);
                            lblConnectionStatus.Content = "Error";
                            statusIndicator.Fill = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Red);
                        }
                        catch { }
                    }));
                }
                finally
                {
                    networkCheckRunning = false;
                }
            });
        }

        // 安全的激活状态检查 - 防止重入
        private void SafeCheckActivationStatus(object? state)
        {
            if (isClosing || activationCheckRunning || !isActivated) return;

            activationCheckRunning = true;

            _ = Task.Run(async () =>
            {
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                    var isValid = await activationService.ValidateExistingActivationAsync();

                    if (isClosing) return;

                    if (!isValid)
                    {
                        Dispatcher.BeginInvoke(new Action(() =>
                        {
                            if (isClosing) return;
                            uiController.AddLog("Activation has expired");
                            _ = SafeHandleActivationExpired();
                        }));
                    }
                    else if (currentActivationState != null)
                    {
                        // Check remaining days
                        int remainingDays = 30 - (int)(DateTime.Now - currentActivationState.ActivationTime).TotalDays;

                        if (remainingDays <= 0)
                        {
                            Dispatcher.BeginInvoke(new Action(() =>
                            {
                                if (isClosing) return;
                                uiController.AddLog("Activation has expired");
                                _ = SafeHandleActivationExpired();
                            }));
                        }
                        else if (remainingDays <= 3)
                        {
                            Dispatcher.BeginInvoke(new Action(() =>
                            {
                                if (isClosing) return;
                                uiController.AddLog($"Activation will expire soon, remaining {remainingDays} days");
                            }));
                        }

                        // Update heartbeat safely
                        try
                        {
                            stateManager.UpdateHeartbeat();
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"Heartbeat update error: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Check activation status exception: {ex.Message}");
                }
                finally
                {
                    activationCheckRunning = false;
                }
            });
        }

        // 安全的VFS状态检查 - 防止重入，支持真实文件信息
        private void SafeCheckVfsStatus(object? state)
        {
            if (isClosing || vfsCheckRunning) return;

            vfsCheckRunning = true;

            _ = Task.Run(() =>
            {
                try
                {
                    bool actuallyMounted = vfsManager.IsMounted;
                    int currentFileCount = vfsManager.FileCount;
                    long currentTotalSize = vfsManager.TotalSize;

                    if (isClosing) return;

                    // 检查VFS状态变化或文件数量变化
                    if (isVfsMounted != actuallyMounted || mountedFileCount != currentFileCount || totalMountedSize != currentTotalSize)
                    {
                        Dispatcher.BeginInvoke(new Action(() =>
                        {
                            if (isClosing) return;

                            try
                            {
                                string statusMessage = actuallyMounted
                                    ? $"Real file VFS status changed: Mounted ({currentFileCount} files, {FormatFileSize(currentTotalSize)})"
                                    : "Real file VFS status changed: Unmounted";

                                uiController.AddLog(statusMessage);

                                isVfsMounted = actuallyMounted;
                                mountedFileCount = currentFileCount;
                                totalMountedSize = currentTotalSize;

                                // 更新文件名列表
                                if (actuallyMounted)
                                {
                                    try
                                    {
                                        mountedFileNames = vfsManager.GetVirtualFileNames();
                                    }
                                    catch (Exception ex)
                                    {
                                        System.Diagnostics.Debug.WriteLine($"Error getting file names: {ex.Message}");
                                        mountedFileNames.Clear();
                                    }
                                }
                                else
                                {
                                    mountedFileNames.Clear();
                                }

                                UpdateCombinedUIState();
                            }
                            catch (Exception ex)
                            {
                                System.Diagnostics.Debug.WriteLine($"VFS status UI update error: {ex.Message}");
                            }
                        }));
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Check VFS status exception: {ex.Message}");
                }
                finally
                {
                    vfsCheckRunning = false;
                }
            });
        }

        // =====================================================
        // 异步系统检查 - 防止阻塞
        // =====================================================
        private async Task PerformSystemCheckAsync(CancellationToken cancellationToken)
        {
            try
            {
                uiController.AddLog("Checking system environment...");

                var checkResult = await Task.Run(async () =>
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    using var combined = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, cts.Token);

                    return await systemCheckService.PerformSystemCheckAsync();
                }, cancellationToken);

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
                    uiController.AddLog("✓ CryptoEngine.dll found and functional");
                    if (checkResult.CryptoEngineTest)
                    {
                        uiController.AddLog("✓ CryptoEngine real file decryption test passed");
                    }
                    else
                    {
                        uiController.AddLog("⚠ Warning: CryptoEngine test failed, real file decryption may not work");
                    }
                }
                else
                {
                    uiController.AddLog("✗ Warning: CryptoEngine.dll not found, real file decryption not available");
                }

                // Real encrypted files check
                var encryptedFiles = securityManager.GetEncryptedFiles();
                uiController.AddLog($"Real encrypted files available: {encryptedFiles.Count}");
            }
            catch (OperationCanceledException)
            {
                uiController.AddLog("System check timed out");
            }
            catch (Exception ex)
            {
                uiController.AddLog($"System check error: {ex.Message}");
            }
        }

        // =====================================================
        // 异步激活状态检查 - 只使用真实文件恢复
        // =====================================================
        private async Task CheckPreviousActivationAsync(CancellationToken cancellationToken)
        {
            try
            {
                uiController.AddLog("Checking previous activation status...");

                var (isValid, currentState) = await Task.Run(async () =>
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                    using var combined = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, cts.Token);

                    var valid = await activationService.ValidateExistingActivationAsync();
                    var state = activationService.GetCurrentActivationState();
                    return (valid, state);
                }, cancellationToken);

                if (isValid && currentState != null)
                {
                    uiController.AddLog($"✓ Found valid activation status, activation time: {currentState.ActivationTime:yyyy-MM-dd HH:mm:ss}");

                    int remainingDays = 30 - (int)(DateTime.Now - currentState.ActivationTime).TotalDays;
                    uiController.AddLog($"Activation remaining days: {remainingDays} days");

                    // 设置激活状态
                    isActivated = true;
                    currentActivationState = currentState;

                    // 尝试恢复VFS（使用真实文件解密，无超时）
                    _ = SafeRestoreRealVirtualFileSystem(currentState, cancellationToken);
                }
                else
                {
                    uiController.AddLog("No valid activation status found");
                    isActivated = false;
                    currentActivationState = null;
                }
            }
            catch (OperationCanceledException)
            {
                uiController.AddLog("Previous activation check timed out");
                isActivated = false;
                currentActivationState = null;
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Error checking activation status: {ex.Message}");
                isActivated = false;
                currentActivationState = null;
            }
        }

        // 安全的VFS恢复 - 只使用真实文件解密，不生成假数据
        private async Task SafeRestoreRealVirtualFileSystem(ActivationState state, CancellationToken cancellationToken)
        {
            try
            {
                uiController.AddLog("=== REAL FILE RESTORATION ===");
                uiController.AddLog("Attempting to restore virtual file system using real decrypted files...");
                uiController.UpdateStatus("Restoring real file system...");

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                using var combined = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, cts.Token);

                // 直接使用SecurityManager解密真实文件
                var decryptedFiles = await Task.Run(() =>
                {
                    try
                    {
                        uiController.AddLog("Calling SecurityManager.DecryptMultipleFiles() to decrypt real .enc files...");
                        return securityManager.DecryptMultipleFiles();
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Real file decryption error: {ex.Message}");
                        return null;
                    }
                }, combined.Token);

                if (decryptedFiles != null && decryptedFiles.Count > 0 && !combined.IsCancellationRequested)
                {
                    long totalSize = decryptedFiles.Values.Sum(data => data.Length);
                    uiController.AddLog($"✓ Real files decrypted successfully: {decryptedFiles.Count} files, total size: {totalSize} bytes");

                    // 记录解密的真实文件
                    uiController.AddLog("Real decrypted files:");
                    foreach (var file in decryptedFiles.Take(5))
                    {
                        uiController.AddLog($"  - {file.Key}: {FormatFileSize(file.Value.Length)}");
                    }
                    if (decryptedFiles.Count > 5)
                    {
                        uiController.AddLog($"  ... and {decryptedFiles.Count - 5} more real files");
                    }

                    // 直接设置真实解密的文件
                    vfsManager.SetVirtualFiles(decryptedFiles);

                    // 尝试挂载VFS with timeout
                    uiController.AddLog("Mounting real decrypted files to virtual file system...");
                    bool mounted = await vfsManager.MountAsync(combined.Token);

                    if (mounted && !combined.IsCancellationRequested)
                    {
                        isVfsMounted = true;
                        mountedFileCount = vfsManager.FileCount;
                        totalMountedSize = vfsManager.TotalSize;
                        mountedFileNames = vfsManager.GetVirtualFileNames();

                        uiController.AddLog($"✓ Real files successfully mounted to {vfsManager.MountPoint}");
                        uiController.AddLog($"Mounted: {mountedFileCount} real files, total size: {FormatFileSize(totalMountedSize)}");

                        // 验证VFS挂载
                        _ = SafeValidateVFS(state);
                    }
                    else
                    {
                        isVfsMounted = false;
                        mountedFileCount = 0;
                        totalMountedSize = 0;
                        mountedFileNames.Clear();
                        uiController.AddLog("✗ Real file virtual file system mount failed or timed out");
                    }
                }
                else
                {
                    isVfsMounted = false;
                    mountedFileCount = 0;
                    totalMountedSize = 0;
                    mountedFileNames.Clear();
                    uiController.AddLog("✗ Cannot decrypt real files, VFS not mounted");
                }

                // 更新UI状态
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (!isClosing)
                    {
                        UpdateCombinedUIState();
                    }
                }));
            }
            catch (OperationCanceledException)
            {
                isVfsMounted = false;
                mountedFileCount = 0;
                totalMountedSize = 0;
                mountedFileNames.Clear();
                uiController.AddLog("Real file virtual file system restoration timed out");

                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (!isClosing)
                    {
                        UpdateCombinedUIState();
                    }
                }));
            }
            catch (Exception ex)
            {
                isVfsMounted = false;
                mountedFileCount = 0;
                totalMountedSize = 0;
                mountedFileNames.Clear();
                uiController.AddLog($"Real file virtual file system restoration failed: {ex.Message}");

                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (!isClosing)
                    {
                        UpdateCombinedUIState();
                    }
                }));
            }
        }

        private async Task SafeValidateVFS(ActivationState state)
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                bool vfsValid = await InitializationHelper.ValidateVFSMountAsync(vfsManager.MountPoint);

                if (vfsValid)
                {
                    uiController.AddLog("✓ Real file virtual file system validation passed");
                    ShowActivationWelcomeMessage(state);
                }
                else
                {
                    uiController.AddLog("⚠ Warning: Real file virtual file system validation failed");
                }
            }
            catch (Exception ex)
            {
                uiController.AddLog($"VFS validation error: {ex.Message}");
            }
        }

        // 显示激活欢迎消息 - 包含真实文件信息
        private void ShowActivationWelcomeMessage(ActivationState state)
        {
            try
            {
                int remainingDays = 30 - (int)(DateTime.Now - state.ActivationTime).TotalDays;
                var encryptedFiles = securityManager.GetEncryptedFiles();

                string welcomeMessage = $"Welcome back to Real File Mode!\n\n" +
                                      $"Activation Status: {(isActivated ? "✓ Activated" : "✗ Not Activated")}\n" +
                                      $"VFS Status: {(isVfsMounted ? "✓ Mounted" : "✗ Not Mounted")}\n" +
                                      $"Activation Time: {state.ActivationTime:yyyy-MM-dd HH:mm:ss}\n" +
                                      $"Remaining Days: {remainingDays} days\n" +
                                      $"Virtual File System: {vfsManager.MountPoint}\n";

                if (isVfsMounted && mountedFileCount > 0)
                {
                    welcomeMessage += $"Real Mounted Files: {mountedFileCount} files ({FormatFileSize(totalMountedSize)})\n";
                }
                else
                {
                    welcomeMessage += $"Real Encrypted Files: {encryptedFiles.Count} files available\n";
                }

                welcomeMessage += $"Access Control: X-Plane processes only\n" +
                                 $"Decryption Method: CryptoEngine.dll (Real Files)\n\n" +
                                 $"Status: {(isVfsMounted ? "X-Plane is ready to use with real protected content." : "X-Plane activation saved, but real file VFS mount failed. You may need to reactivate.")}";

                uiController.ShowMessage(welcomeMessage, "Real File System Status");
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Error showing welcome message: {ex.Message}");
            }
        }

        // 安全的激活过期处理
        private async Task SafeHandleActivationExpired()
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                bool success = await activationService.DeactivateAsync();

                isActivated = false;
                isVfsMounted = false;
                currentActivationState = null;
                mountedFileCount = 0;
                totalMountedSize = 0;
                mountedFileNames.Clear();

                UpdateCombinedUIState();

                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (!isClosing)
                    {
                        uiController.ShowMessage("Activation has expired. Real encrypted files are no longer accessible. Please reactivate.",
                                                "Activation Expired", true);
                    }
                }));
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Error processing activation expiry: {ex.Message}");
            }
        }

        // =====================================================
        // 按钮点击事件处理 - 更新支持真实文件信息显示
        // =====================================================
        private async void BtnActivate_Click(object sender, RoutedEventArgs e)
        {
            if (isClosing || isActivated)
            {
                if (isActivated)
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
            cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(3));

            try
            {
                uiController.UpdateStatus("Validating activation code...");
                uiController.AddLog($"=== REAL FILE ACTIVATION ===");
                uiController.AddLog($"Starting real file activation process, code: {activationCode.Substring(0, Math.Min(8, activationCode.Length))}...");

                // Try online activation first
                var onlineResult = await activationService.ActivateOnlineAsync(activationCode, cancellationTokenSource.Token);

                if (onlineResult.IsSuccess)
                {
                    await HandleRealFileActivationSuccess(onlineResult);
                }
                else if (onlineResult.IsPartialSuccess)
                {
                    await HandlePartialRealFileActivationSuccess(onlineResult);
                }
                else
                {
                    // Ask if user wants to try offline activation
                    bool tryOffline = uiController.ConfirmAction(
                        $"Online activation failed: {onlineResult.ErrorMessage}\n\nWould you like to try offline activation?\n\nNote: Offline activation will decrypt real .enc files from local storage using CryptoEngine.dll.",
                        "Online Verification Failed");

                    if (tryOffline)
                    {
                        uiController.AddLog("Trying offline verification with real encrypted files...");
                        var offlineResult = await activationService.ActivateOfflineAsync(activationCode, cancellationTokenSource.Token);

                        if (offlineResult.IsSuccess)
                        {
                            await HandleRealFileActivationSuccess(offlineResult);
                        }
                        else if (offlineResult.IsPartialSuccess)
                        {
                            await HandlePartialRealFileActivationSuccess(offlineResult);
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
                uiController.AddLog("Activation cancelled or timed out");
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
                if (!isActivated)
                {
                    btnActivate.IsEnabled = true;
                    btnActivate.Content = "Online Activation";
                }
                cancellationTokenSource?.Dispose();
                cancellationTokenSource = null;
            }
        }

        // 处理真实文件激活成功
        private async Task HandleRealFileActivationSuccess(ActivationResult result)
        {
            isActivated = true;
            isVfsMounted = !string.IsNullOrEmpty(result.MountPoint);
            currentActivationState = activationService.GetCurrentActivationState();

            // 更新真实文件状态
            if (isVfsMounted)
            {
                mountedFileCount = vfsManager.FileCount;
                totalMountedSize = vfsManager.TotalSize;
                try
                {
                    mountedFileNames = vfsManager.GetVirtualFileNames();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error getting file names: {ex.Message}");
                    mountedFileNames.Clear();
                }
            }
            else
            {
                mountedFileCount = 0;
                totalMountedSize = 0;
                mountedFileNames.Clear();
            }

            UpdateCombinedUIState();

            var encryptedFiles = securityManager.GetEncryptedFiles();
            string successMessage = $"Real File Activation Successful!\n\n" +
                                   $"Activation Status: ✓ Activated and saved\n" +
                                   $"VFS Status: {(isVfsMounted ? "✓ Mounted successfully" : "✗ Mount failed")}\n" +
                                   $"Mount Point: {result.MountPoint ?? "N/A"}\n" +
                                   $"Decryption Method: CryptoEngine.dll (Real Files)\n";

            if (isVfsMounted && mountedFileCount > 0)
            {
                successMessage += $"Real Mounted Files: {mountedFileCount} files ({FormatFileSize(totalMountedSize)})\n";

                // 显示前5个真实文件名
                var displayFiles = mountedFileNames.Take(5).ToList();
                if (displayFiles.Count > 0)
                {
                    successMessage += "Real File List:\n";
                    foreach (var fileName in displayFiles)
                    {
                        successMessage += $"  - {fileName}\n";
                    }
                    if (mountedFileCount > 5)
                    {
                        successMessage += $"  ... and {mountedFileCount - 5} more real files\n";
                    }
                }
            }
            else
            {
                successMessage += $"Real Encrypted Files: {encryptedFiles.Count} files available\n";
            }

            successMessage += $"Access Control: X-Plane processes only\n\n" +
                             $"{(isVfsMounted ? "You can now start X-Plane and access real protected content." : "Activation saved, but real file VFS mount failed. You may need to reactivate.")}\n\n" +
                             $"Activation status saved and will be automatically restored on next startup.";

            uiController.ShowMessage(successMessage, "Real File Activation Complete");

            // Validate the mounted file system if mounted
            if (isVfsMounted && !string.IsNullOrEmpty(result.MountPoint))
            {
                _ = SafeValidateVFS(currentActivationState!);
            }
        }

        // 处理部分激活成功 - 真实文件信息
        private async Task HandlePartialRealFileActivationSuccess(ActivationResult result)
        {
            isActivated = result.StateSaved;
            isVfsMounted = false; // 部分成功意味着VFS挂载失败
            mountedFileCount = 0;
            totalMountedSize = 0;
            mountedFileNames.Clear();

            if (result.StateSaved)
            {
                currentActivationState = activationService.GetCurrentActivationState();
            }

            UpdateCombinedUIState();

            string partialMessage = $"Partial Real File Activation\n\n" +
                                   $"Activation Status: {(result.StateSaved ? "✓ Saved successfully" : "✗ Failed to save")}\n" +
                                   $"VFS Status: ✗ Mount failed\n" +
                                   $"Decryption Method: CryptoEngine.dll (Real Files)\n" +
                                   $"Issue: {result.ErrorMessage}\n\n" +
                                   $"{(result.StateSaved ? "Your activation has been saved, but the real file virtual file system could not be mounted." : "Real file activation could not be completed.")}\n\n" +
                                   $"You may need to:\n" +
                                   $"• Check if CryptoEngine.dll is available\n" +
                                   $"• Verify .enc files exist in encrypted folder\n" +
                                   $"• Check if Dokan driver is properly installed\n" +
                                   $"• Run as administrator\n" +
                                   $"• Try reactivating\n" +
                                   $"• Check the diagnostic report for more details";

            uiController.ShowMessage(partialMessage, "Partial Success", true);
        }

        private async void BtnDeactivate_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string deactivateMessage = "Are you sure you want to deactivate? This will:\n\n" +
                                         "• Clear saved activation status\n" +
                                         "• Unmount the virtual file system\n" +
                                         "• Make real encrypted files inaccessible\n\n";

                if (mountedFileCount > 0)
                {
                    deactivateMessage += $"Currently mounted: {mountedFileCount} real files ({FormatFileSize(totalMountedSize)})\n\n";
                }

                deactivateMessage += "X-Plane will no longer be able to access the real protected content.";

                bool confirmed = uiController.ConfirmAction(deactivateMessage, "Confirm Deactivation");

                if (confirmed)
                {
                    uiController.AddLog("User selected deactivation");
                    uiController.UpdateStatus("Deactivating...");

                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    bool success = await activationService.DeactivateAsync();

                    // 不管DeactivateAsync返回什么，都清除本地状态
                    isActivated = false;
                    isVfsMounted = false;
                    currentActivationState = null;
                    mountedFileCount = 0;
                    totalMountedSize = 0;
                    mountedFileNames.Clear();

                    UpdateCombinedUIState();

                    if (success)
                    {
                        uiController.AddLog("Deactivation successful");
                        uiController.ShowMessage("Deactivation successful. Real encrypted files are no longer accessible.", "Deactivation Complete");
                    }
                    else
                    {
                        uiController.AddLog("Deactivation completed with some issues");
                        uiController.ShowMessage("Deactivation completed. Some cleanup operations may have failed, but activation has been cleared.", "Deactivation Complete");
                    }
                }
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Deactivation error: {ex.Message}");

                // 即使出现异常，也清除本地状态
                isActivated = false;
                isVfsMounted = false;
                currentActivationState = null;
                mountedFileCount = 0;
                totalMountedSize = 0;
                mountedFileNames.Clear();
                UpdateCombinedUIState();

                uiController.ShowMessage($"Deactivation encountered errors but has been cleared: {ex.Message}", "Deactivation Complete", true);
            }
        }

        // 更新的激活信息显示 - 包含真实文件信息
        private void BtnActivationInfo_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!isActivated || currentActivationState == null)
                {
                    uiController.ShowMessage("Currently not activated or activation status information is unavailable.", "Information");
                    return;
                }

                int remainingDays = 30 - (int)(DateTime.Now - currentActivationState.ActivationTime).TotalDays;
                string machineFingerprint = HardwareIdHelper.GetDisplayFingerprint();
                var encryptedFiles = securityManager.GetEncryptedFiles();

                var timeSinceActivation = DateTime.Now - currentActivationState.ActivationTime;
                var timeSinceHeartbeat = DateTime.Now - currentActivationState.LastHeartbeat;

                string infoMessage = $"Real File Activation Information\n\n" +
                                   $"Activation Code: {currentActivationState.ActivationCode.Substring(0, Math.Min(8, currentActivationState.ActivationCode.Length))}...\n" +
                                   $"Activation Time: {currentActivationState.ActivationTime:yyyy-MM-dd HH:mm:ss}\n" +
                                   $"Activated Days: {(int)timeSinceActivation.TotalDays} days\n" +
                                   $"Remaining Days: {remainingDays} days\n" +
                                   $"Last Heartbeat: {currentActivationState.LastHeartbeat:yyyy-MM-dd HH:mm:ss}\n" +
                                   $"Heartbeat Interval: {(int)timeSinceHeartbeat.TotalMinutes} minutes ago\n" +
                                   $"Machine Fingerprint: {machineFingerprint}\n" +
                                   $"Mount Point: {currentActivationState.MountPoint ?? "Unknown"}\n" +
                                   $"Server Token: {(!string.IsNullOrEmpty(currentActivationState.ServerToken) ? "Available" : "Not Available")}\n" +
                                   $"Decryption Method: {securityManager.GetDecryptionMethod()}\n" +
                                   $"Available Real Encrypted Files: {encryptedFiles.Count} files\n" +
                                   $"VFS Status: {(isVfsMounted ? "✓ Mounted" : "✗ Not Mounted")}\n" +
                                   $"VFS Mount Point: {vfsManager.MountPoint}\n";

                if (isVfsMounted)
                {
                    infoMessage += $"Real Mounted Files: {mountedFileCount} files\n" +
                                  $"Total Mounted Size: {FormatFileSize(totalMountedSize)}\n";

                    if (mountedFileNames.Count > 0)
                    {
                        infoMessage += "Real Mounted File List:\n";
                        foreach (var fileName in mountedFileNames.Take(10))
                        {
                            infoMessage += $"  - {fileName}\n";
                        }
                        if (mountedFileNames.Count > 10)
                        {
                            infoMessage += $"  ... and {mountedFileNames.Count - 10} more real files\n";
                        }
                    }
                }

                infoMessage += $"Access Control: X-Plane processes only";

                uiController.ShowMessage(infoMessage, "Real File Activation Information");
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Error showing activation info: {ex.Message}");
                uiController.ShowMessage($"Cannot show activation info: {ex.Message}", "Error", true);
            }
        }

        // 更新的诊断方法 - 包含真实文件VFS信息
        private async void BtnDiagnostic_Click(object sender, RoutedEventArgs e)
        {
            if (isClosing) return;

            try
            {
                btnDiagnostic.IsEnabled = false;
                btnDiagnostic.Content = "Running Diagnostic...";

                uiController.AddLog("Starting comprehensive real file system diagnostic...");
                uiController.UpdateStatus("Running real file system diagnostic...");

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                var diagnosticReport = await CreateDiagnosticReportAsync(cts.Token);
                ShowDiagnosticMessage(diagnosticReport);

                uiController.AddLog("Real file system diagnostic complete");
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

        private async Task<string> CreateDiagnosticReportAsync(CancellationToken cancellationToken)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== Real File System Diagnostic Report ===");
            sb.AppendLine($"Diagnostic Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();

            try
            {
                // 分离的状态检查
                sb.AppendLine("=== Activation & Real File VFS Status ===");
                sb.AppendLine($"Activation Status: {(isActivated ? "✓ Activated" : "✗ Not Activated")}");
                sb.AppendLine($"Real File VFS Mount Status: {(isVfsMounted ? "✓ Mounted" : "✗ Not Mounted")}");
                sb.AppendLine($"VFS Mount Point: {vfsManager.MountPoint}");
                sb.AppendLine($"VFS Manager Status: {vfsManager.Status}");
                sb.AppendLine($"VFS Manager Type: {vfsManager.GetType().Name}");

                // 真实文件信息
                if (isVfsMounted)
                {
                    sb.AppendLine($"Mounted Real Files: {mountedFileCount} files");
                    sb.AppendLine($"Total Size: {FormatFileSize(totalMountedSize)}");

                    if (mountedFileNames.Count > 0)
                    {
                        sb.AppendLine("Real File List:");
                        foreach (var fileName in mountedFileNames.Take(10))
                        {
                            sb.AppendLine($"  - {fileName}");
                        }
                        if (mountedFileNames.Count > 10)
                        {
                            sb.AppendLine($"  ... and {mountedFileNames.Count - 10} more real files");
                        }
                    }
                }
                else
                {
                    sb.AppendLine("No real files mounted");
                }

                sb.AppendLine();

                // Basic system checks with timeout
                sb.AppendLine("=== System Checks ===");

                var systemCheckTask = Task.Run(() =>
                {
                    sb.AppendLine("1. Administrator Privileges: " + (systemCheckService.IsRunningAsAdministrator() ? "✓ Pass" : "✗ Fail"));
                    sb.AppendLine("2. CryptoEngine.dll: " + (securityManager.IsCryptoDllAvailable() ? "✓ Available" : "✗ Not Available"));
                    sb.AppendLine("3. Network Connection: " + (networkManager != null ? "✓ Normal" : "✗ Error"));

                    // Check real encrypted files
                    var encryptedFiles = securityManager.GetEncryptedFiles();
                    sb.AppendLine($"4. Real Encrypted Files: {encryptedFiles.Count} files available");

                    if (encryptedFiles.Count > 0)
                    {
                        sb.AppendLine("   Real Encrypted File Manifest:");
                        foreach (var file in encryptedFiles.Values.Take(5))
                        {
                            sb.AppendLine($"     - {file.RelativePath} ({FormatFileSize(file.OriginalSize)}) -> {file.EncryptedFile}");
                        }
                        if (encryptedFiles.Count > 5)
                        {
                            sb.AppendLine($"     ... and {encryptedFiles.Count - 5} more real files");
                        }
                    }

                    // Check security threats
                    var threatInfo = securityManager.CheckSecurityThreats();
                    sb.AppendLine("5. Security Check: " + (threatInfo.ThreatsDetected ? "⚠ Threats Detected" : "✓ Clean"));
                    if (threatInfo.ThreatsDetected)
                    {
                        sb.AppendLine($"   - {threatInfo.Message}");
                    }

                    // VFS Manager specific checks
                    sb.AppendLine($"6. VFS File Count: {vfsManager.FileCount}");
                    sb.AppendLine($"7. VFS Total Size: {FormatFileSize(vfsManager.TotalSize)}");
                    sb.AppendLine($"8. VFS Mounted: {(vfsManager.IsMounted ? "✓ Yes" : "✗ No")}");

                }, cancellationToken);

                await Task.WhenAny(systemCheckTask, Task.Delay(10000, cancellationToken));

                // 添加更多诊断信息...
                sb.AppendLine();
                sb.AppendLine("=== System Information ===");
                sb.AppendLine(systemCheckService.GetSystemInfo());

                // 添加真实文件系统特定信息
                sb.AppendLine();
                sb.AppendLine("=== Real File System Information ===");
                sb.AppendLine($"VFS Implementation: VirtualFileSystemManager (Real Files Only)");
                sb.AppendLine($"Current File Count: {vfsManager.FileCount}");
                sb.AppendLine($"Current Total Size: {FormatFileSize(vfsManager.TotalSize)}");
                sb.AppendLine($"Mount Point: {vfsManager.MountPoint}");
                sb.AppendLine($"Access Mode: Whitelist Only (X-Plane processes)");
                sb.AppendLine($"Decryption Method: {securityManager.GetDecryptionMethod()}");

                if (vfsManager.IsMounted)
                {
                    try
                    {
                        var fileNames = vfsManager.GetVirtualFileNames();
                        sb.AppendLine($"Real Virtual Files ({fileNames.Count}):");
                        foreach (var fileName in fileNames.Take(10))
                        {
                            sb.AppendLine($"  - {fileName}");
                        }
                        if (fileNames.Count > 10)
                        {
                            sb.AppendLine($"  ... and {fileNames.Count - 10} more real files");
                        }
                    }
                    catch (Exception ex)
                    {
                        sb.AppendLine($"Error getting real virtual file names: {ex.Message}");
                    }
                }

                return sb.ToString();
            }
            catch (OperationCanceledException)
            {
                sb.AppendLine("\n=== Diagnostic Timeout ===");
                sb.AppendLine("Some diagnostic checks timed out.");
                return sb.ToString();
            }
            catch (Exception ex)
            {
                sb.AppendLine($"\n=== Diagnostic Error ===");
                sb.AppendLine($"Error creating diagnostic report: {ex.Message}");
                return sb.ToString();
            }
        }

        private void ShowDiagnosticMessage(string report)
        {
            uiController.ShowMessage(report, "Real File System Diagnostic Report");
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
                    FileName = $"XPlane_RealFiles_Log_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
                };

                if (saveDialog.ShowDialog() == true)
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            string logContent = "";
                            Dispatcher.Invoke(() => logContent = txtActivationLog.Text);

                            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                            var diagnosticReport = await CreateDiagnosticReportAsync(cts.Token);
                            logContent += "\n\n" + diagnosticReport;

                            await System.IO.File.WriteAllTextAsync(saveDialog.FileName, logContent);

                            Dispatcher.BeginInvoke(new Action(() =>
                            {
                                if (!isClosing)
                                {
                                    uiController.AddLog($"Real file system log saved to: {saveDialog.FileName}");
                                    uiController.ShowMessage("Log saved successfully!", "Save Complete");
                                }
                            }));
                        }
                        catch (Exception ex)
                        {
                            Dispatcher.BeginInvoke(new Action(() =>
                            {
                                if (!isClosing)
                                {
                                    uiController.AddLog($"Log save failed: {ex.Message}");
                                    uiController.ShowMessage($"Log save failed: {ex.Message}", "Error", true);
                                }
                            }));
                        }
                    });
                }
            }
            catch (Exception ex)
            {
                uiController.AddLog($"Log save failed: {ex.Message}");
                uiController.ShowMessage($"Log save failed: {ex.Message}", "Error", true);
            }
        }

        // =====================================================
        // 更新的UI状态管理 - 支持真实文件显示
        // =====================================================
        private void UpdateCombinedUIState()
        {
            if (isClosing) return;

            try
            {
                // 更新激活相关UI
                if (isActivated)
                {
                    btnActivate.Content = "Activated (Real Files)";
                    btnActivate.IsEnabled = false;

                    if (currentActivationState != null)
                    {
                        int remainingDays = 30 - (int)(DateTime.Now - currentActivationState.ActivationTime).TotalDays;
                        txtActivationCode.Text = $"Activated - {remainingDays} days remaining (Real Files)";
                    }
                    else
                    {
                        txtActivationCode.Text = "Activated (Real Files)";
                    }
                    txtActivationCode.IsEnabled = false;

                    // 显示取消激活和信息按钮
                    if (btnDeactivate != null)
                    {
                        btnDeactivate.IsEnabled = true;
                        btnDeactivate.Visibility = Visibility.Visible;
                    }

                    if (btnActivationInfo != null)
                    {
                        btnActivationInfo.IsEnabled = true;
                        btnActivationInfo.Visibility = Visibility.Visible;
                    }
                }
                else
                {
                    btnActivate.Content = "Online Activation (Real Files)";
                    btnActivate.IsEnabled = true;

                    txtActivationCode.Text = "";
                    txtActivationCode.IsEnabled = true;

                    // 隐藏取消激活和信息按钮
                    if (btnDeactivate != null)
                    {
                        btnDeactivate.IsEnabled = false;
                        btnDeactivate.Visibility = Visibility.Collapsed;
                    }

                    if (btnActivationInfo != null)
                    {
                        btnActivationInfo.IsEnabled = false;
                        btnActivationInfo.Visibility = Visibility.Collapsed;
                    }
                }

                // 更新VFS状态显示 - 支持真实文件信息
                if (isVfsMounted)
                {
                    string vfsStatusText = $"Real Files: Mounted to {vfsManager.MountPoint}";
                    if (mountedFileCount > 0)
                    {
                        vfsStatusText += $" ({mountedFileCount} real files, {FormatFileSize(totalMountedSize)})";
                    }

                    lblVfsStatus.Content = vfsStatusText;
                    lblVfsStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.LightGreen);
                }
                else
                {
                    lblVfsStatus.Content = "Real Files: Not mounted";
                    lblVfsStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Gray);
                }

                // 更新激活信息面板
                if (isActivated && currentActivationState != null)
                {
                    if (lblActivationStatusTitle != null)
                    {
                        lblActivationStatusTitle.Visibility = Visibility.Visible;
                    }

                    if (spActivationInfo != null)
                    {
                        spActivationInfo.Visibility = Visibility.Visible;

                        // 更新激活详细信息
                        if (lblActivationTime != null)
                        {
                            lblActivationTime.Content = $"Activation Time: {currentActivationState.ActivationTime:yyyy-MM-dd HH:mm:ss}";
                        }

                        if (lblRemainingDays != null)
                        {
                            int remainingDays = 30 - (int)(DateTime.Now - currentActivationState.ActivationTime).TotalDays;
                            lblRemainingDays.Content = $"Remaining Days: {remainingDays} days";
                        }

                        if (lblLastHeartbeat != null)
                        {
                            var timeSinceHeartbeat = DateTime.Now - currentActivationState.LastHeartbeat;
                            string heartbeatText = timeSinceHeartbeat.TotalMinutes < 1
                                ? "Last Heartbeat: Just now"
                                : $"Last Heartbeat: {(int)timeSinceHeartbeat.TotalMinutes} minutes ago";
                            lblLastHeartbeat.Content = heartbeatText;
                        }
                    }
                }
                else
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

                // 更新总体状态 - 包含真实文件信息
                if (isActivated && isVfsMounted)
                {
                    string statusText = "Activated - Real files ready";
                    if (mountedFileCount > 0)
                    {
                        statusText += $" ({mountedFileCount} files)";
                    }
                    uiController.UpdateStatus(statusText);
                }
                else if (isActivated && !isVfsMounted)
                {
                    uiController.UpdateStatus("Activated - Real file VFS mount failed");
                }
                else
                {
                    uiController.UpdateStatus("Ready - Please enter activation code (Real Files Mode)");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"UI update error: {ex.Message}");
            }
        }

        // =====================================================
        // Event Handlers - 完整实现
        // =====================================================
        private void OnActivationProgressChanged(object? sender, ActivationProgressEventArgs e)
        {
            if (!isClosing)
            {
                uiController.AddLog(e.Message);
                uiController.UpdateStatus(e.Message);
            }
        }

        private void OnServiceLogMessage(object? sender, string e)
        {
            if (!isClosing)
            {
                uiController.AddLog(e);
            }
        }

        private void VfsManager_StatusChanged(object? sender, VfsStatusEventArgs e)
        {
            if (isClosing) return;

            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (isClosing) return;

                try
                {
                    uiController.AddLog($"Real File VFS Status: {e.Message}");

                    // 更新VFS挂载状态
                    bool newMountedState = (e.Status == VfsStatus.Mounted);
                    if (isVfsMounted != newMountedState)
                    {
                        isVfsMounted = newMountedState;

                        // 更新真实文件状态
                        if (isVfsMounted)
                        {
                            mountedFileCount = vfsManager.FileCount;
                            totalMountedSize = vfsManager.TotalSize;
                            try
                            {
                                mountedFileNames = vfsManager.GetVirtualFileNames();
                            }
                            catch
                            {
                                mountedFileNames.Clear();
                            }
                        }
                        else
                        {
                            mountedFileCount = 0;
                            totalMountedSize = 0;
                            mountedFileNames.Clear();
                        }

                        UpdateCombinedUIState();
                    }

                    switch (e.Status)
                    {
                        case VfsStatus.Mounted:
                            string mountedText = "Real file virtual file system mounted";
                            if (mountedFileCount > 0)
                            {
                                mountedText += $" ({mountedFileCount} real files)";
                            }
                            lblVfsStatus.Content = mountedText;
                            lblVfsStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.LightGreen);
                            break;
                        case VfsStatus.Mounting:
                            lblVfsStatus.Content = "Real file virtual file system mounting";
                            lblVfsStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Yellow);
                            break;
                        case VfsStatus.Error:
                            lblVfsStatus.Content = "Real file virtual file system error";
                            lblVfsStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Red);
                            break;
                        case VfsStatus.Unmounted:
                            lblVfsStatus.Content = "Real file virtual file system not mounted";
                            lblVfsStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Gray);
                            break;
                        case VfsStatus.FileAccessed:
                            string accessText = "Real file virtual file system - file accessed";
                            if (mountedFileCount > 0)
                            {
                                accessText += $" ({mountedFileCount} real files available)";
                            }
                            lblVfsStatus.Content = accessText;
                            lblVfsStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Cyan);
                            break;
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"VFS status update error: {ex.Message}");
                }
            }));
        }

        private void VfsManager_LogMessage(object? sender, string e)
        {
            if (!isClosing)
            {
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (!isClosing)
                    {
                        uiController.AddLog($"Real File VFS: {e}");
                    }
                }));
            }
        }

        // =====================================================
        // 安全的窗口关闭处理 - 包括真实文件清理
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

                if (mountedFileCount > 0)
                {
                    uiController.AddLog($"Cleaning up {mountedFileCount} mounted real files...");
                }

                // Cancel all operations
                cancellationTokenSource?.Cancel();
                initializationCts?.Cancel();

                // Stop timers safely
                try
                {
                    networkCheckTimer?.Dispose();
                    activationCheckTimer?.Dispose();
                    vfsCheckTimer?.Dispose();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Timer disposal error: {ex.Message}");
                }

                // Quick heartbeat update if activated
                if (isActivated)
                {
                    try
                    {
                        var updateTask = Task.Run(() => stateManager?.UpdateHeartbeat());
                        if (!updateTask.Wait(1000)) // 最多等待1秒
                        {
                            System.Diagnostics.Debug.WriteLine("Heartbeat update timeout on close");
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Heartbeat update error on close: {ex.Message}");
                    }
                }

                // Force unmount virtual file system quickly
                if (isVfsMounted)
                {
                    try
                    {
                        var unmountTask = Task.Run(() => vfsManager?.ForceUnmount());
                        if (!unmountTask.Wait(3000)) // 增加等待时间用于真实文件清理
                        {
                            System.Diagnostics.Debug.WriteLine("Real file VFS unmount timeout on close");
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Real file VFS unmount error on close: {ex.Message}");
                    }
                }

                // Release resources quickly
                try
                {
                    networkManager?.Dispose();
                    securityManager?.Dispose();
                    vfsManager?.Dispose();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Resource disposal error: {ex.Message}");
                }

                uiController.AddLog("Application has been closed");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Close exception: {ex.Message}");
            }
        }

        // =====================================================
        // 工具方法
        // =====================================================
        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
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