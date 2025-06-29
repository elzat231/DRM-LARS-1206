﻿using System.Resources;
using System.Reflection;
using System.Globalization;
using System.Collections.Generic;

namespace XPlaneActivator
{
    /// <summary>
    /// Resource Manager - English UI strings for X-Plane DRM Activator
    /// </summary>
    public static class R
    {
        private static readonly Dictionary<string, string> englishStrings = new Dictionary<string, string>
        {
            // Application
            ["AppTitle"] = "X-Plane DRM Activator",
            ["AppStarting"] = "========== X-Plane DRM Activator Starting ==========",
            ["AppClosing"] = "Application is closing...",
            ["AppClosed"] = "Application has been closed",

            // Main Window UI
            ["ActivationCode"] = "Activation Code",
            ["EnterActivationCode"] = "Enter your activation code",
            ["ActivateButton"] = "Online Activation",
            ["ActivatingButton"] = "Activating...",
            ["AlreadyActivated"] = "Activated",
            ["DeactivateButton"] = "Deactivate",
            ["DiagnosticButton"] = "System Diagnostic",
            ["ActivationInfo"] = "Activation Info",

            // Status Messages
            ["Status"] = "Status",
            ["StatusReady"] = "Ready - Please enter activation code",
            ["StatusNotActivated"] = "Not Activated",
            ["StatusActivated"] = "Activated",
            ["StatusActivating"] = "Activating...",
            ["StatusError"] = "Error",
            ["StatusInitializing"] = "Initializing system...",
            ["StatusValidating"] = "Validating activation code...",
            ["StatusDecrypting"] = "Decrypting activation data...",
            ["StatusMounting"] = "Mounting virtual file system...",
            ["StatusDeactivating"] = "Deactivating...",
            ["StatusDeactivated"] = "Deactivated",
            ["StatusExpired"] = "Activation has expired - Please reactivate",
            ["StatusMountingVFS"] = "Mounting virtual file system...",
            ["StatusRestoring"] = "Restoring activation status...",

            // Network Status
            ["NetworkStatus"] = "Network Status",
            ["NetworkOnline"] = "Network Online (lars-store.kz)",
            ["NetworkOffline"] = "Network Disconnected",
            ["NetworkError"] = "Network Error",
            ["ConnectionOnline"] = "Online",
            ["ConnectionOffline"] = "Offline",
            ["ConnectionError"] = "Error",

            // Virtual File System
            ["VirtualFileSystem"] = "Virtual File System",
            ["VFSMounted"] = "Mounted",
            ["VFSNotMounted"] = "Not Mounted",
            ["VFSMounting"] = "Mounting...",
            ["VFSError"] = "Error",

            // Machine Code
            ["MachineCode"] = "Machine Code",
            ["MachineCodeGenerated"] = "Machine code generated: {0}...",

            // System Checks
            ["SystemEnvironmentCheck"] = "Checking system environment...",
            ["AdminPrivilegesCheck"] = "Administrator privileges check passed",
            ["AdminPrivilegesWarning"] = "Warning: Not running as administrator, virtual file system may not work properly",

            // Dokan Driver
            ["DokanDriverFound"] = "Dokan driver detected",
            ["DokanDriverNotFound"] = "Warning: Dokan driver not detected, please install Dokan driver first",
            ["DokanDriverNotInstalled"] = "Dokan driver not detected",
            ["DokanDriverFullyInstalled"] = "Dokan driver fully installed and ready",
            ["DokanNetFoundButDriverMissing"] = "DokanNet library found, but system driver may be missing",
            ["DokanPartialInstallation"] = "Partial Dokan installation detected, may have compatibility issues",
            ["DokanCheckError"] = "Error checking Dokan installation: {0}",

            // Crypto Engine
            ["CryptoEngineDllFound"] = "CryptoEngine.dll found",
            ["CryptoEngineDllNotFound"] = "Warning: CryptoEngine.dll not found, will use C# fallback verification",
            ["CryptoEngineTestPassed"] = "CryptoEngine functioning normally",
            ["CryptoEngineTestFailed"] = "Warning: CryptoEngine test failed, will use fallback method",
            ["CryptoEngineTestException"] = "Warning: CryptoEngine test exception: {0}",

            // Activation Process
            ["StartingActivation"] = "Starting activation process, code: {0}...",
            ["ConnectingToServer"] = "Connecting to lars-store.kz activation server...",
            ["SendingActivationRequest"] = "Sending activation request to lars-store.kz...",
            ["ProcessingServerResponse"] = "Processing lars-store.kz server response...",
            ["OnlineActivationSuccess"] = "lars-store.kz online verification successful, received access token",
            ["OnlineActivationSuccessNoToken"] = "Activation successful but no token received, using offline mode",
            ["OnlineActivationFailed"] = "lars-store.kz verification failed: {0}",
            ["OfflineActivationAttempt"] = "User chose to try offline verification...",
            ["OfflineActivationSuccess"] = "Offline verification successful",
            ["OfflineActivationFailed"] = "Offline verification failed: {0}",
            ["ActivationCancelled"] = "User cancelled offline verification",
            ["ActivationStatusCancelled"] = "Activation cancelled",

            // Data Processing
            ["DecryptingData"] = "Decrypting data using server token...",
            ["DataDecryptionSuccess"] = "Data decryption successful, size: {0} bytes",
            ["DataDecryptionFailed"] = "Token decryption failed",
            ["DataIntegrityCheckPassed"] = "Data integrity verification passed",
            ["DataIntegrityCheckFailed"] = "Data integrity verification failed",
            ["UsingActivationCodeDecryption"] = "Decrypting locally using activation code...",
            ["ActivationCodeDecryptionFailed"] = "Activation code decryption failed",

            // Virtual File System Messages
            ["StartingVirtualFileSystem"] = "Starting virtual file system...",
            ["MountingVirtualFileSystem"] = "Mounting virtual file system...",
            ["VFSMountedSuccess"] = "Virtual file system successfully mounted to {0}",
            ["VFSMountFailed"] = "Virtual file system mount failed",
            ["VFSUnmounting"] = "Unmounting virtual file system",
            ["VFSUnmounted"] = "Virtual file system unmounted",
            ["VFSStatus"] = "VFS Status: {0}",

            // Activation State Management
            ["CheckingPreviousActivation"] = "Checking previous activation status...",
            ["FoundValidActivation"] = "Found valid activation status, activation time: {0}",
            ["ActivationRemainingDays"] = "Activation remaining days: {0} days",
            ["RevalidationNeeded"] = "Need to revalidate activation status...",
            ["RevalidationSuccess"] = "Revalidation successful",
            ["RevalidationFailed"] = "Revalidation failed, need to reactivate",
            ["NoValidActivation"] = "No valid activation status found",
            ["ActivationCheckError"] = "Error checking activation status: {0}",
            ["RestoringVirtualFileSystem"] = "Restoring virtual file system...",
            ["VFSRestoredSuccess"] = "Virtual file system restored and mounted to {0}",
            ["VFSRestorationFailed"] = "Virtual file system restoration failed",
            ["CannotDecryptSavedData"] = "Cannot decrypt saved activation data",
            ["ActivationStateSaved"] = "Activation status saved",
            ["ActivationStateSaveFailed"] = "Activation status save failed, but virtual file system is mounted",
            ["ActivationExpiredWarning"] = "Activation will expire soon, remaining {0} days",
            ["ActivationExpired"] = "Activation has expired, need to reactivate",

            // Welcome Messages
            ["WelcomeBack"] = "Welcome back!",
            ["ActivationStatusActive"] = "Activation Status: Activated",
            ["ActivationTimeLabel"] = "Activation Time: {0}",
            ["RemainingDaysLabel"] = "Remaining Days: {0} days",
            ["VirtualFileSystemLabel"] = "Virtual File System: {0}",
            ["XPlaneReadyMessage"] = "X-Plane is ready to use.",

            // Activation Info Dialog
            ["DetailedActivationInfo"] = "Detailed Activation Information",
            ["ActivationCodeLabel"] = "Activation Code: {0}...",
            ["ActivatedDaysLabel"] = "Activated Days: {0} days",
            ["LastHeartbeatLabel"] = "Last Heartbeat: {0}",
            ["HeartbeatIntervalLabel"] = "Heartbeat Interval: {0} minutes ago",
            ["MachineFingerprintLabel"] = "Machine Fingerprint: {0}",
            ["MountPointLabel"] = "Mount Point: {0}",
            ["ServerTokenLabel"] = "Server Token: {0}",
            ["ServerTokenAvailable"] = "Available",
            ["ServerTokenNotAvailable"] = "Not Available",

            // Error Messages
            ["ErrorMessage"] = "Error",
            ["Warning"] = "Warning",
            ["Information"] = "Information",
            ["InputRequired"] = "Input Required",
            ["EnterActivationCodeMessage"] = "Please enter your activation code!",
            ["SystemAlreadyActivated"] = "System is already activated. To reactivate, please deactivate first.",
            ["CurrentlyNotActivated"] = "Currently not activated or activation status information is unavailable.",
            ["NetworkTimeout"] = "Network Timeout",
            ["NetworkTimeoutMessage"] = "Connection to activation server timed out. Please check your network connection or try again later.",
            ["NetworkError"] = "Network Error",
            ["NetworkErrorMessage"] = "Unable to connect to activation server: {0}\n\nPlease check your network connection or firewall settings.",
            ["ActivationError"] = "Activation Error",
            ["ActivationErrorMessage"] = "Activation failed: {0}",
            ["OnlineActivationFailedMessage"] = "Online activation failed: {0}\n\nWould you like to try offline activation?\n\nNote: Offline activation only works with valid activation codes.",
            ["OfflineActivationFailedMessage"] = "Offline activation failed: {0}",
            ["TokenProcessingException"] = "Token processing exception: {0}",
            ["ActivationCodeProcessingException"] = "Activation code processing exception: {0}",
            ["VFSMountException"] = "Virtual file system mount exception: {0}",
            ["VFSMountFailedMessage"] = "Virtual file system mount failed. Please check if Dokan driver is installed and running as administrator.",
            ["ShowingActivationInfoError"] = "Error showing activation info: {0}",
            ["CannotShowActivationInfo"] = "Cannot show activation info: {0}",
            ["DeactivationError"] = "Deactivation error: {0}",
            ["DeactivationFailed"] = "Deactivation failed: {0}",
            ["ProcessActivationExpiredError"] = "Error processing activation expiry: {0}",

            // Deactivation
            ["ConfirmDeactivation"] = "Confirm Deactivation",
            ["ConfirmDeactivationMessage"] = "Are you sure you want to deactivate? This will clear saved activation status and unmount the virtual file system.",
            ["UserSelectedDeactivation"] = "User selected deactivation",
            ["DeactivationComplete"] = "Deactivation Complete",
            ["DeactivationCompleteMessage"] = "Deactivation successful.",

            // Success Messages
            ["ActivationComplete"] = "Activation Complete",
            ["ActivationSuccessMessage"] = "Activation successful!\n\nVirtual file system mounted to {0}\nYou can now start X-Plane.\n\nActivation status saved, will be automatically restored on next startup.",
            ["ActivationSuccessful"] = "Activation successful - Virtual file system ready",
            ["ActivationCompleted"] = "Activation completed successfully",

            // System Initialization
            ["InitializingSystem"] = "Initializing system...",
            ["SystemInitializationComplete"] = "System initialization complete, waiting for activation...",
            ["SystemInitializationFailed"] = "System initialization failed: {0}",
            ["InitializationFailed"] = "Initialization failed",

            // Online/Offline Verification
            ["OnlineVerificationFailed"] = "Online verification failed",
            ["TryingOfflineVerification"] = "Trying offline verification...",
            ["UserCancelledOfflineVerification"] = "User cancelled offline verification",
            ["PerformingOnlineRevalidation"] = "Performing online revalidation...",
            ["PerformingOfflineRevalidation"] = "Performing offline revalidation...",

            // Network Connection
            ["TryingServerConnection"] = "Trying to connect to server: {0}",
            ["ServerConnectionSuccess"] = "Successfully connected to server: {0}",
            ["ServerConnectionFailed"] = "Server {0} connection failed: {1}",
            ["TryingNextServer"] = "Trying next server...",
            ["AllServersFailed"] = "All servers failed to connect",
            ["InvalidServerResponse"] = "Invalid server response format",
            ["ServerResponseContent"] = "Response content: {0}",

            // Diagnostics
            ["DiagnosticStarting"] = "Starting comprehensive system diagnostic...",
            ["DiagnosticCompleted"] = "Diagnostic completed! Total {0} checks performed",
            ["DiagnosticCheckCount"] = "Diagnostic completed! Total {0} checks",
            ["DiagnosticSummary"] = "Diagnostics finished: {0} total, {1} passed, {2} warnings, {3} failed",
            ["DiagnosticResultSummary"] = "Diagnostic Results Summary:\nTotal Tests: {0}\nPassed: {1}\nWarnings: {2}\nFailed: {3}\nOverall Status: {4}",
            ["StartingSystemDiagnostic"] = "Starting system diagnostic...",
            ["SystemDiagnosticComplete"] = "System diagnostic complete",
            ["DiagnosticProcessException"] = "Diagnostic process exception: {0}",
            ["DiagnosticFailed"] = "Diagnostic failed: {0}",
            ["RunningDiagnostic"] = "Running diagnostic...",
            ["DiagnosticProgress"] = "Diagnostic progress: {0}/{1} tests completed",
            ["DiagnosticStepCompleted"] = "Step completed: {0}",
            ["DiagnosticOverallResult"] = "Overall diagnostic result: {0}",

            // Log Management
            ["LogCleared"] = "Log cleared",
            ["LogSaved"] = "Log saved to: {0}",
            ["LogSaveSuccess"] = "Log saved successfully!",
            ["LogSaveComplete"] = "Save Complete",
            ["LogSaveFailed"] = "Log save failed: {0}",
            ["SaveActivationLog"] = "Save Activation Log",

            // Application Lifecycle
            ["ApplicationExiting"] = "Application exiting, exit code: {0}",
            ["ExitException"] = "Exception on exit: {0}",
            ["SingleInstanceCheck"] = "X-Plane DRM Activator is already running!",
            ["Application"] = "Application",
            ["SystemRequirements"] = "System Requirements",
            ["SystemRequirementsNotMet"] = "This application can only run on Windows systems.",
            ["PermissionIssue"] = "Permission Issue",
            ["DirectoryNotWritable"] = "Application directory is not writable: {0}\n\nPlease run as administrator or choose another directory.",
            ["SystemRequirementsCheckFailed"] = "System requirements check failed: {0}",
            ["SingleInstanceCheckException"] = "Single instance check exception: {0}",

            // Exception Handling
            ["UIThreadException"] = "UI Thread Exception",
            ["NonUIThreadException"] = "Non-UI Thread Exception",
            ["TaskException"] = "Task Exception",
            ["UnhandledException"] = "Unhandled Exception",
            ["ApplicationErrorMessage"] = "Application encountered an unexpected error:\n\n{0}\n\nDo you want to continue running?",
            ["ApplicationTerminating"] = "Application is about to terminate due to an unrecoverable error.",
            ["SeriousError"] = "Serious Error",
            ["CloseTimeout"] = "Close timeout, forcing exit",
            ["CloseException"] = "Exception during close: {0}",
            ["ExceptionHandlerException"] = "Exception handler exception: {0}",
            ["NonUIExceptionHandlerException"] = "Non-UI exception handler exception: {0}",
            ["TaskExceptionHandlerException"] = "Task exception handler exception: {0}",

            // File and Directory Operations
            ["OptionalFileFound"] = "Found optional file: {0}",
            ["OptionalFileNotFound"] = "Optional file does not exist: {0} (will use backup method)",

            // Version and Environment Info
            ["VersionInfo"] = "Version: {0}",
            ["LocationInfo"] = "Location: {0}",
            ["WorkingDirectoryInfo"] = "Working Directory: {0}",
            ["OperatingSystemInfo"] = "Operating System: {0}",
            ["DotNetVersionInfo"] = ".NET Version: {0}",
            ["Is64BitInfo"] = "Is 64-bit: {0}",
            ["MachineNameInfo"] = "Machine Name: {0}",
            ["UserNameInfo"] = "User Name: {0}",
            ["StartupTimeInfo"] = "Startup Time: {0}",

            // Hardware Information
            ["MachineCodeGenerationError"] = "Error generating machine code: {0}",
            ["HardwareInfoError"] = "Error getting WMI info ({0}.{1}): {2}",
            ["MacAddressError"] = "Error getting MAC address: {0}",
            ["MachineFingerprintMismatch"] = "Machine fingerprint mismatch",
            ["ActivationExpiredMessage"] = "Activation has expired",
            ["HeartbeatTimeout"] = "Heartbeat timeout",
            ["StateValidationException"] = "State validation exception: {0}",
            ["ReadingStateFailed"] = "Reading state failed: {0}",
            ["SavingStateFailed"] = "Saving state failed: {0}",
            ["UpdateHeartbeatFailed"] = "Update heartbeat failed: {0}",
            ["ClearingStateFailed"] = "Clearing state failed: {0}",
            ["ActivationStateCleared"] = "Activation state cleared",

            // Generic UI
            ["OK"] = "OK",
            ["Cancel"] = "Cancel",
            ["Close"] = "Close",
            ["Yes"] = "Yes",
            ["No"] = "No",
            ["Save"] = "Save",
            ["ClearLog"] = "Clear Log",
            ["SaveLog"] = "Save Log",

            // VFS Specific Messages
            ["VFSSetupVirtualFiles"] = "Virtual files set up: Fuse 1.obj ({0} bytes)",
            ["VFSFoundXPlaneProcess"] = "Found X-Plane process: {0}",
            ["VFSProcessCheckError"] = "Process check error: {0}",
            ["VFSAccessDenied"] = "Access denied to non-X-Plane process: {0}",
            ["VFSFileAccessRequest"] = "File access request: {0}",
            ["VFSFileAccessSuccess"] = "File access successful: {0}",
            ["VFSFileNotExists"] = "File does not exist: {0}",
            ["VFSReadFileRequest"] = "Read file request: {0}, offset: {1}, buffer size: {2}",
            ["VFSReadSuccess"] = "Successfully read {0} bytes from {1}",
            ["VFSReadBytesInfo"] = "Read {0} bytes",
            ["VFSCannotReadFile"] = "Cannot read file: {0}",
            ["VFSGetFileInfo"] = "Get file info: {0}",
            ["VFSFindFilesRequest"] = "Find files request: {0}",
            ["VFSFoundFiles"] = "Found {0} files",
            ["VFSFindFilesWithPattern"] = "Find files request (with pattern): {0}, pattern: {1}",
            ["VFSFoundMatchingFiles"] = "Found {0} matching files",
            ["VFSMountedToPoint"] = "File system mounted to: {0}",
            ["VFSUnmountedFromPoint"] = "File system unmounted",

            // Status Values
            ["StatusExcellent"] = "Excellent",
            ["StatusGood"] = "Good",
            ["StatusNeedsAttention"] = "Needs Attention",
            ["StatusHasIssues"] = "Has Issues",
            ["Unknown"] = "Unknown",

            // Test Status
            ["TestStatusPassed"] = "Passed",
            ["TestStatusWarning"] = "Warning",
            ["TestStatusFailed"] = "Failed"
        };

        private static ResourceManager? resourceManager;

        static R()
        {
            try
            {
                resourceManager = new ResourceManager("XPlaneActivator.Resources", Assembly.GetExecutingAssembly());
            }
            catch
            {
                resourceManager = null;
            }
        }

        /// <summary>
        /// Get localized string for specified key
        /// </summary>
        /// <param name="key">Resource key</param>
        /// <returns>Localized string</returns>
        public static string Get(string key)
        {
            try
            {
                // First try to get from resource file
                if (resourceManager != null)
                {
                    string? value = resourceManager.GetString(key, CultureInfo.CurrentUICulture);
                    if (!string.IsNullOrEmpty(value))
                    {
                        return value;
                    }
                }

                // Get from English dictionary
                if (englishStrings.TryGetValue(key, out string? englishValue))
                {
                    return englishValue;
                }

                return key; // If not found, return the key itself
            }
            catch
            {
                // Get from English dictionary
                if (englishStrings.TryGetValue(key, out string? englishValue))
                {
                    return englishValue;
                }
                return key;
            }
        }

        /// <summary>
        /// Get formatted localized string
        /// </summary>
        /// <param name="key">Resource key</param>
        /// <param name="args">Format parameters</param>
        /// <returns>Formatted localized string</returns>
        public static string GetFormatted(string key, params object[] args)
        {
            try
            {
                string format = Get(key);
                return string.Format(format, args);
            }
            catch
            {
                return $"{key}: {string.Join(", ", args)}";
            }
        }

        // =====================================================
        // Quick access properties for commonly used strings
        // =====================================================

        // Application
        public static string AppTitle => Get("AppTitle");

        // Main Window UI
        public static string ActivationCode => Get("ActivationCode");
        public static string EnterActivationCode => Get("EnterActivationCode");
        public static string ActivateButton => Get("ActivateButton");
        public static string ActivatingButton => Get("ActivatingButton");
        public static string DeactivateButton => Get("DeactivateButton");
        public static string DiagnosticButton => Get("DiagnosticButton");

        // Status
        public static string Status => Get("Status");
        public static string StatusNotActivated => Get("StatusNotActivated");
        public static string StatusActivated => Get("StatusActivated");
        public static string StatusError => Get("StatusError");

        // Messages
        public static string InputRequired => Get("InputRequired");
        public static string EnterActivationCodeMessage => Get("EnterActivationCodeMessage");
        public static string ActivationComplete => Get("ActivationComplete");
        public static string ActivationSuccessMessage => Get("ActivationSuccessMessage");
        public static string ActivationFailed => Get("ActivationFailed");

        // Generic
        public static string OK => Get("OK");
        public static string Cancel => Get("Cancel");
        public static string Close => Get("Close");
        public static string Yes => Get("Yes");
        public static string No => Get("No");

        // Formatting methods
        public static string MachineCodeGenerated(string code) => GetFormatted("MachineCodeGenerated", code);
        public static string DataDecryptionSuccess(int size) => GetFormatted("DataDecryptionSuccess", size);
        public static string VFSMountedSuccess(string mountPoint) => GetFormatted("VFSMountedSuccess", mountPoint);
        public static string ActivationSuccessMessageFormatted(string mountPoint) => GetFormatted("ActivationSuccessMessage", mountPoint);
        public static string NetworkErrorMessage(string error) => GetFormatted("NetworkErrorMessage", error);
        public static string ActivationErrorMessage(string error) => GetFormatted("ActivationErrorMessage", error);
    }
}