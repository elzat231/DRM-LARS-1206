using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace XPlaneActivator
{
    public partial class App : Application
    {
        private static Mutex? _mutex;
        private const string MUTEX_NAME = "XPlaneActivator_SingleInstance";

        protected override void OnStartup(StartupEventArgs e)
        {
            // Setup global exception handling
            SetupGlobalExceptionHandling();

            // Check if there's already an instance running
            if (!CheckSingleInstance())
            {
                MessageBox.Show(R.Get("AppSingleInstanceRunning"), R.Get("Application"),
                               MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown();
                return;
            }

            // Check runtime environment
            if (!CheckSystemRequirements())
            {
                Shutdown();
                return;
            }

            // Log startup info
            LogStartupInfo();

            base.OnStartup(e);
        }

        protected override void OnExit(ExitEventArgs e)
        {
            try
            {
                // Release mutex
                _mutex?.ReleaseMutex();
                _mutex?.Dispose();

                // Log exit info
                Debug.WriteLine($"[App] {R.GetFormatted("AppExiting", e.ApplicationExitCode)}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[App] {R.GetFormatted("AppExitException", ex.Message)}");
            }

            base.OnExit(e);
        }

        /// <summary>
        /// Check if only one instance is running
        /// </summary>
        private bool CheckSingleInstance()
        {
            try
            {
                _mutex = new Mutex(true, MUTEX_NAME, out bool createdNew);
                return createdNew;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[App] {R.GetFormatted("AppSingleInstanceCheckException", ex.Message)}");
                return true; // Allow running if exception occurs
            }
        }

        /// <summary>
        /// Check system requirements
        /// </summary>
        private bool CheckSystemRequirements()
        {
            try
            {
                // Check operating system version
                if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                {
                    MessageBox.Show(R.Get("AppSystemRequirementsNotMet"), R.Get("SystemRequirements"),
                                   MessageBoxButton.OK, MessageBoxImage.Error);
                    return false;
                }

                // Check .NET version
                string frameworkVersion = Environment.Version.ToString();
                Debug.WriteLine($"[App] {R.GetFormatted("AppDotNetVersionInfo", frameworkVersion)}");

                // Check if working directory is writable
                string currentDir = AppDomain.CurrentDomain.BaseDirectory;
                if (!IsDirectoryWritable(currentDir))
                {
                    MessageBox.Show(R.GetFormatted("AppDirectoryNotWritable", currentDir),
                                   R.Get("PermissionIssue"), MessageBoxButton.OK, MessageBoxImage.Warning);
                }

                // Check required DLL files
                CheckRequiredFiles();

                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(R.GetFormatted("AppSystemRequirementsCheckFailed", ex.Message), R.Get("ErrorMessage"),
                               MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        /// <summary>
        /// Check required files
        /// </summary>
        private void CheckRequiredFiles()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;

            // Check optional DLL files
            string[] optionalFiles = {
                "CryptoEngine.dll",
                "network.dll"
            };

            foreach (string file in optionalFiles)
            {
                string filePath = Path.Combine(baseDir, file);
                if (File.Exists(filePath))
                {
                    Debug.WriteLine($"[App] {R.GetFormatted("AppOptionalFileFound", file)}");
                }
                else
                {
                    Debug.WriteLine($"[App] {R.GetFormatted("AppOptionalFileNotFound", file)}");
                }
            }
        }

        /// <summary>
        /// Check if directory is writable
        /// </summary>
        private bool IsDirectoryWritable(string dirPath)
        {
            try
            {
                string testFile = Path.Combine(dirPath, "test_write_access.tmp");
                File.WriteAllText(testFile, "test");
                File.Delete(testFile);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Setup global exception handling
        /// </summary>
        private void SetupGlobalExceptionHandling()
        {
            // Handle UI thread exceptions
            DispatcherUnhandledException += App_DispatcherUnhandledException;

            // Handle non-UI thread exceptions
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;

            // Handle Task exceptions
            TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
        }

        private void App_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            try
            {
                LogException(R.Get("UIThreadException"), e.Exception);

                string message = R.GetFormatted("ApplicationErrorMessage", e.Exception.Message);

                MessageBoxResult result = MessageBox.Show(message, R.Get("UnhandledException"),
                                                         MessageBoxButton.YesNo, MessageBoxImage.Error);

                if (result == MessageBoxResult.Yes)
                {
                    e.Handled = true; // Continue running
                }
                else
                {
                    Shutdown(); // Close application
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[App] {R.GetFormatted("ExceptionHandlerException", ex.Message)}");
            }
        }

        private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            try
            {
                LogException(R.Get("NonUIThreadException"), e.ExceptionObject as Exception);

                if (e.IsTerminating)
                {
                    MessageBox.Show(R.Get("ApplicationTerminating"), R.Get("SeriousError"),
                                   MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[App] {R.GetFormatted("NonUIExceptionHandlerException", ex.Message)}");
            }
        }

        private void TaskScheduler_UnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
        {
            try
            {
                LogException(R.Get("TaskException"), e.Exception);
                e.SetObserved(); // Mark exception as observed
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[App] {R.GetFormatted("TaskExceptionHandlerException", ex.Message)}");
            }
        }

        /// <summary>
        /// Log exception information
        /// </summary>
        private void LogException(string category, Exception? exception)
        {
            if (exception == null) return;

            try
            {
                string logMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{category}]\n" +
                                  $"Exception Type: {exception.GetType().Name}\n" +
                                  $"Exception Message: {exception.Message}\n" +
                                  $"Stack Trace: {exception.StackTrace}\n" +
                                  new string('=', 80);

                Debug.WriteLine(logMessage);

                // Try to write to log file
                try
                {
                    string logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
                    if (!Directory.Exists(logDir))
                    {
                        Directory.CreateDirectory(logDir);
                    }

                    string logFile = Path.Combine(logDir, $"error_{DateTime.Now:yyyyMMdd}.log");
                    File.AppendAllText(logFile, logMessage + Environment.NewLine);
                }
                catch
                {
                    // Ignore log write failures
                }
            }
            catch
            {
                // Ignore logging exceptions
            }
        }

        /// <summary>
        /// Log startup information
        /// </summary>
        private void LogStartupInfo()
        {
            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                var version = assembly.GetName().Version?.ToString() ?? "Unknown";
                var location = assembly.Location;

                Debug.WriteLine($"[App] {R.Get("AppStarting")}");
                Debug.WriteLine($"[App] {R.GetFormatted("AppVersionInfo", version)}");
                Debug.WriteLine($"[App] {R.GetFormatted("AppLocationInfo", location)}");
                Debug.WriteLine($"[App] {R.GetFormatted("AppWorkingDirectoryInfo", AppDomain.CurrentDomain.BaseDirectory)}");
                Debug.WriteLine($"[App] {R.GetFormatted("AppOperatingSystemInfo", Environment.OSVersion)}");
                Debug.WriteLine($"[App] {R.GetFormatted("AppDotNetVersionInfo", Environment.Version)}");
                Debug.WriteLine($"[App] {R.GetFormatted("AppIs64BitInfo", Environment.Is64BitProcess)}");
                Debug.WriteLine($"[App] {R.GetFormatted("AppMachineNameInfo", Environment.MachineName)}");
                Debug.WriteLine($"[App] {R.GetFormatted("AppUserNameInfo", Environment.UserName)}");
                Debug.WriteLine($"[App] {R.GetFormatted("AppStartupTimeInfo", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"))}");
                Debug.WriteLine($"[App] ===============================================");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[App] Startup info logging exception: {ex.Message}");
            }
        }
    }
}