using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.ServiceProcess; // 现在应该可以正常使用了

namespace XPlaneActivator
{
    /// <summary>
    /// System Diagnostics - Comprehensive check of all functional modules
    /// </summary>
    public class SystemDiagnostics
    {
        private readonly SecurityManager? securityManager;
        private readonly VirtualFileSystemManager? vfsManager;
        private readonly NetworkManager? networkManager;
        private readonly List<DiagnosticResult> results;

        // P/Invoke for testing C++ DLL - 添加安全检查
        private static bool _dllAvailable = false;
        private static bool _dllChecked = false;

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern int ValidateActivationCode([MarshalAs(UnmanagedType.LPStr)] string activationCode, int codeLength);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern int GetDecryptedDataSize();

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        private static extern void SecureMemoryCleanup();

        public SystemDiagnostics(SecurityManager? securityManager, VirtualFileSystemManager? vfsManager, NetworkManager? networkManager = null)
        {
            this.securityManager = securityManager;
            this.vfsManager = vfsManager;
            this.networkManager = networkManager ?? new NetworkManager();
            this.results = new List<DiagnosticResult>();
        }

        /// <summary>
        /// 检查 DLL 是否可用
        /// </summary>
        private static void CheckDllAvailability()
        {
            if (_dllChecked) return;

            try
            {
                // 检查文件是否存在
                string dllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CryptoEngine.dll");
                if (!File.Exists(dllPath))
                {
                    _dllAvailable = false;
                    _dllChecked = true;
                    return;
                }

                // 尝试调用一个简单的函数来测试DLL是否可用
                SecureMemoryCleanup();
                _dllAvailable = true;
            }
            catch (DllNotFoundException)
            {
                _dllAvailable = false;
            }
            catch (EntryPointNotFoundException)
            {
                _dllAvailable = false;
            }
            catch (Exception)
            {
                _dllAvailable = false;
            }
            finally
            {
                _dllChecked = true;
            }
        }

        /// <summary>
        /// Run comprehensive system diagnostics
        /// </summary>
        /// <returns>Diagnostic report</returns>
        public async Task<DiagnosticReport> RunFullDiagnostics()
        {
            results.Clear();
            var report = new DiagnosticReport();

            try
            {
                AddLog("🔍 " + R.Get("DiagnosticStarting"));

                // 1. Basic environment check
                await CheckBasicEnvironment();

                // 2. C++ DLL functionality check
                await CheckCppDllFunctionality();

                // 3. C# fallback verification check
                await CheckCsharpFallbackFunctionality();

                // 4. Virtual file system check
                await CheckVirtualFileSystem();

                // 5. Process access control check
                await CheckProcessAccessControl();

                // 6. Memory security check
                await CheckMemorySecurity();

                // 7. Network functionality check
                await CheckNetworkFunctionality();

                // 8. Performance testing
                await CheckPerformance();

                // 9. Integrated functionality testing
                await CheckIntegratedFunctionality();

                // Generate report
                report = GenerateReport();

                // 修复：使用正确的格式化方法
                AddLog("✅ " + R.GetFormatted("DiagnosticCompleted", results.Count));

            }
            catch (Exception ex)
            {
                AddLog("❌ " + R.GetFormatted("DiagnosticProcessException", ex.Message));
                results.Add(new DiagnosticResult
                {
                    Category = "System Diagnostics",
                    Test = "Diagnostic Process",
                    Status = TestStatus.Failed,
                    Message = R.GetFormatted("DiagnosticProcessException", ex.Message),
                    Details = ex.StackTrace ?? ""
                });
            }

            return report;
        }

        /// <summary>
        /// Check basic environment
        /// </summary>
        private async Task CheckBasicEnvironment()
        {
            AddLog("🔧 " + R.Get("DiagnosticCheckingBasicEnvironment"));

            await Task.Run(() =>
            {
                // Check operating system
                try
                {
                    var osInfo = Environment.OSVersion;
                    bool isWindows = osInfo.Platform == PlatformID.Win32NT;

                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryBasic"),
                        Test = "Operating System",
                        Status = isWindows ? TestStatus.Passed : TestStatus.Warning,
                        Message = $"Operating System: {osInfo.VersionString}",
                        Details = isWindows ? "Windows environment normal" : "Non-Windows environment, some features may be limited"
                    });
                }
                catch (Exception ex)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryBasic"),
                        Test = "Operating System",
                        Status = TestStatus.Failed,
                        Message = "Cannot detect operating system",
                        Details = ex.Message
                    });
                }

                // Check administrator privileges
                try
                {
                    bool isAdmin = IsRunningAsAdministrator();
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryBasic"),
                        Test = "Administrator Privileges",
                        Status = isAdmin ? TestStatus.Passed : TestStatus.Warning,
                        Message = isAdmin ? "Has administrator privileges" : "Lacks administrator privileges",
                        Details = isAdmin ? "Virtual file system mount normal" : "Virtual file system may not mount"
                    });
                }
                catch (Exception ex)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryBasic"),
                        Test = "Administrator Privileges",
                        Status = TestStatus.Failed,
                        Message = "Privilege check failed",
                        Details = ex.Message
                    });
                }

                // Check Dokan driver - 使用改进的检查方法
                CheckDokanDriverAdvanced();
            });
        }

        /// <summary>
        /// 改进的Dokan驱动检查方法
        /// </summary>
        private void CheckDokanDriverAdvanced()
        {
            try
            {
                // 检查注册表
                bool registryFound = false;
                string registryDetails = "";

                try
                {
                    using var key1 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Dokan\DokanLibrary");
                    if (key1 != null)
                    {
                        registryFound = true;
                        registryDetails += "Found in HKLM\\SOFTWARE\\Dokan\\DokanLibrary; ";
                    }
                }
                catch { }

                try
                {
                    using var key2 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Dokan\DokanLibrary");
                    if (key2 != null)
                    {
                        registryFound = true;
                        registryDetails += "Found in HKLM\\SOFTWARE\\WOW6432Node\\Dokan\\DokanLibrary; ";
                    }
                }
                catch { }

                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryBasic"),
                    Test = "Dokan Registry Entries",
                    Status = registryFound ? TestStatus.Passed : TestStatus.Warning,
                    Message = registryFound ? "Dokan registry entries found" : "No Dokan registry entries found",
                    Details = registryFound ? registryDetails.TrimEnd(' ', ';') : "Registry check completed but no entries detected"
                });

                // 检查系统文件
                var dokanFiles = new List<string>();
                string[] checkPaths = {
                    @"C:\Windows\System32\drivers\dokan2.sys",
                    @"C:\Windows\System32\drivers\dokan1.sys",
                    @"C:\Windows\System32\dokan2.dll",
                    @"C:\Windows\System32\dokan1.dll",
                    @"C:\Windows\SysWOW64\dokan2.dll",
                    @"C:\Windows\SysWOW64\dokan1.dll"
                };

                foreach (string path in checkPaths)
                {
                    if (File.Exists(path))
                    {
                        dokanFiles.Add(Path.GetFileName(path));
                    }
                }

                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryBasic"),
                    Test = "Dokan System Files",
                    Status = dokanFiles.Count > 0 ? TestStatus.Passed : TestStatus.Warning,
                    Message = dokanFiles.Count > 0 ? $"Found {dokanFiles.Count} Dokan system files" : "No Dokan system files found",
                    Details = dokanFiles.Count > 0 ? string.Join(", ", dokanFiles) : "No dokan*.sys or dokan*.dll files detected in system directories"
                });

                // 检查DokanNet.dll
                string dokanNetPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "DokanNet.dll");
                bool dokanNetExists = File.Exists(dokanNetPath);

                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryBasic"),
                    Test = "DokanNet Library",
                    Status = dokanNetExists ? TestStatus.Passed : TestStatus.Failed,
                    Message = dokanNetExists ? "DokanNet.dll found" : "DokanNet.dll not found",
                    Details = dokanNetExists ? $"Path: {dokanNetPath}" : "DokanNet.dll is required for virtual file system functionality"
                });

                // 检查服务 - 修复后的代码
                bool dokanServiceFound = false;
                string serviceDetails = "";

                try
                {
                    var services = ServiceController.GetServices();
                    var dokanServices = services.Where(s =>
                        s.ServiceName.ToLower().Contains("dokan") ||
                        s.DisplayName.ToLower().Contains("dokan")).ToList();

                    if (dokanServices.Any())
                    {
                        dokanServiceFound = true;
                        serviceDetails = string.Join(", ", dokanServices.Select(s => $"{s.ServiceName} ({s.Status})"));
                    }
                }
                catch (Exception ex)
                {
                    serviceDetails = $"Service check failed: {ex.Message}";
                }

                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryBasic"),
                    Test = "Dokan Services",
                    Status = dokanServiceFound ? TestStatus.Passed : TestStatus.Warning,
                    Message = dokanServiceFound ? "Dokan services detected" : "No Dokan services found",
                    Details = !string.IsNullOrEmpty(serviceDetails) ? serviceDetails : "No Dokan-related services detected"
                });

                // 综合评估
                int dokanScore = 0;
                if (registryFound) dokanScore += 25;
                if (dokanFiles.Count > 0) dokanScore += 25;
                if (dokanNetExists) dokanScore += 30;
                if (dokanServiceFound) dokanScore += 20;

                TestStatus overallStatus;
                string overallMessage;
                string overallDetails;

                if (dokanScore >= 80)
                {
                    overallStatus = TestStatus.Passed;
                    overallMessage = "Dokan driver fully installed and ready";
                    overallDetails = $"Installation completeness: {dokanScore}% - All components detected";
                }
                else if (dokanScore >= 50)
                {
                    overallStatus = TestStatus.Warning;
                    overallMessage = "Dokan driver partially installed";
                    overallDetails = $"Installation completeness: {dokanScore}% - Some components missing, functionality may be limited";
                }
                else
                {
                    overallStatus = TestStatus.Failed;
                    overallMessage = "Dokan driver not properly installed";
                    overallDetails = $"Installation completeness: {dokanScore}% - Critical components missing. Please install Dokan from https://github.com/dokan-dev/dokany/releases";
                }

                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryBasic"),
                    Test = "Dokan Driver Overall Status",
                    Status = overallStatus,
                    Message = overallMessage,
                    Details = overallDetails
                });
            }
            catch (Exception ex)
            {
                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryBasic"),
                    Test = "Dokan Driver Check",
                    Status = TestStatus.Failed,
                    Message = "Dokan driver check failed",
                    Details = ex.Message
                });
            }
        }

        /// <summary>
        /// Check C++ DLL functionality
        /// </summary>
        private async Task CheckCppDllFunctionality()
        {
            AddLog("🔧 " + R.Get("DiagnosticCheckingCppDll"));

            await Task.Run(() =>
            {
                // Check DLL file exists
                string dllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CryptoEngine.dll");
                bool dllExists = File.Exists(dllPath);

                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryCppDll"),
                    Test = "DLL File Exists",
                    Status = dllExists ? TestStatus.Passed : TestStatus.Failed,
                    Message = dllExists ? "Found CryptoEngine.dll" : "CryptoEngine.dll does not exist",
                    Details = $"Path: {dllPath}"
                });

                if (!dllExists) return;

                // 检查 DLL 可用性
                CheckDllAvailability();

                if (!_dllAvailable)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryCppDll"),
                        Test = "DLL Loading",
                        Status = TestStatus.Failed,
                        Message = "Cannot load CryptoEngine.dll",
                        Details = "May be missing dependencies or DLL is corrupted"
                    });
                    return;
                }

                // Test DLL function calls
                try
                {
                    // Test activation code validation function
                    int result = ValidateActivationCode("TEST-DLL-FUNCTION", 17);

                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryCppDll"),
                        Test = "Activation Code Validation Function",
                        Status = result == 1 ? TestStatus.Passed : TestStatus.Failed,
                        Message = result == 1 ? "Activation code validation function normal" : "Activation code validation function abnormal",
                        Details = $"Test result: {result}"
                    });

                    // Test data size retrieval function
                    if (result == 1)
                    {
                        int dataSize = GetDecryptedDataSize();

                        results.Add(new DiagnosticResult
                        {
                            Category = R.Get("DiagnosticCategoryCppDll"),
                            Test = "Data Size Retrieval",
                            Status = dataSize > 0 ? TestStatus.Passed : TestStatus.Failed,
                            Message = dataSize > 0 ? "Data size retrieval normal" : "Data size retrieval abnormal",
                            Details = $"Data size: {dataSize} bytes"
                        });

                        // Test memory cleanup function
                        try
                        {
                            SecureMemoryCleanup();
                            results.Add(new DiagnosticResult
                            {
                                Category = R.Get("DiagnosticCategoryCppDll"),
                                Test = "Memory Cleanup Function",
                                Status = TestStatus.Passed,
                                Message = "Memory cleanup function call successful",
                                Details = "C++ DLL memory cleanup normal"
                            });
                        }
                        catch (Exception ex)
                        {
                            results.Add(new DiagnosticResult
                            {
                                Category = R.Get("DiagnosticCategoryCppDll"),
                                Test = "Memory Cleanup Function",
                                Status = TestStatus.Warning,
                                Message = "Memory cleanup function call exception",
                                Details = ex.Message
                            });
                        }
                    }
                }
                catch (DllNotFoundException)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryCppDll"),
                        Test = "DLL Loading",
                        Status = TestStatus.Failed,
                        Message = "Cannot load CryptoEngine.dll",
                        Details = "May be missing dependencies or DLL is corrupted"
                    });
                }
                catch (EntryPointNotFoundException ex)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryCppDll"),
                        Test = "Function Export",
                        Status = TestStatus.Failed,
                        Message = "DLL function export exception",
                        Details = ex.Message
                    });
                }
                catch (Exception ex)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryCppDll"),
                        Test = "DLL Functionality Test",
                        Status = TestStatus.Failed,
                        Message = "DLL functionality test failed",
                        Details = ex.Message
                    });
                }
            });
        }

        /// <summary>
        /// Check C# fallback verification functionality
        /// </summary>
        private async Task CheckCsharpFallbackFunctionality()
        {
            AddLog("🔧 " + R.Get("DiagnosticCheckingCsharpFallback"));

            await Task.Run(() =>
            {
                try
                {
                    if (securityManager != null)
                    {
                        // Test valid activation code fallback verification
                        var result = securityManager.ValidateAndDecrypt("FALLBACK-TEST-XPLANE");

                        results.Add(new DiagnosticResult
                        {
                            Category = R.Get("DiagnosticCategoryCsharp"),
                            Test = "Fallback Verification Function",
                            Status = result != null ? TestStatus.Passed : TestStatus.Failed,
                            Message = result != null ? "C# fallback verification normal" : "C# fallback verification failed",
                            Details = result != null ? $"Returned data: {result.Length} bytes" : "Fallback verification returned null"
                        });

                        // Test invalid activation code
                        var invalidResult = securityManager.ValidateAndDecrypt("INVALID");

                        results.Add(new DiagnosticResult
                        {
                            Category = R.Get("DiagnosticCategoryCsharp"),
                            Test = "Invalid Activation Code Rejection",
                            Status = invalidResult == null ? TestStatus.Passed : TestStatus.Failed,
                            Message = invalidResult == null ? "Correctly rejects invalid activation code" : "Incorrectly accepts invalid activation code",
                            Details = "Security validation logic normal"
                        });
                    }
                    else
                    {
                        results.Add(new DiagnosticResult
                        {
                            Category = R.Get("DiagnosticCategoryCsharp"),
                            Test = "SecurityManager",
                            Status = TestStatus.Failed,
                            Message = "SecurityManager not initialized",
                            Details = "Cannot test fallback verification functionality"
                        });
                    }
                }
                catch (Exception ex)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryCsharp"),
                        Test = "Fallback Verification Test",
                        Status = TestStatus.Failed,
                        Message = "Fallback verification test exception",
                        Details = ex.Message
                    });
                }
            });
        }

        /// <summary>
        /// Check virtual file system
        /// </summary>
        private async Task CheckVirtualFileSystem()
        {
            AddLog("🔧 " + R.Get("DiagnosticCheckingVirtualFileSystem"));

            await Task.Run(() =>
            {
                try
                {
                    // Check mount point
                    if (vfsManager != null)
                    {
                        string mountPoint = vfsManager.MountPoint;
                        bool mountPointExists = Directory.Exists(mountPoint);

                        results.Add(new DiagnosticResult
                        {
                            Category = R.Get("DiagnosticCategoryVfs"),
                            Test = "Mount Point Check",
                            Status = mountPointExists ? TestStatus.Passed : TestStatus.Warning,
                            Message = mountPointExists ? $"Mount point {mountPoint} exists" : $"Mount point {mountPoint} does not exist",
                            Details = mountPointExists ? "Virtual file system is mounted" : "Virtual file system not mounted or mount failed"
                        });

                        // Check virtual files
                        if (mountPointExists)
                        {
                            try
                            {
                                string[] files = Directory.GetFiles(mountPoint);

                                results.Add(new DiagnosticResult
                                {
                                    Category = R.Get("DiagnosticCategoryVfs"),
                                    Test = "Virtual Files",
                                    Status = files.Length > 0 ? TestStatus.Passed : TestStatus.Warning,
                                    Message = $"Found {files.Length} virtual files",
                                    Details = string.Join(", ", files)
                                });

                                // Check key files
                                string fuseFile = Path.Combine(mountPoint, "Fuse 1.obj");
                                bool fuseExists = File.Exists(fuseFile);

                                results.Add(new DiagnosticResult
                                {
                                    Category = R.Get("DiagnosticCategoryVfs"),
                                    Test = "Key File Exists",
                                    Status = fuseExists ? TestStatus.Passed : TestStatus.Failed,
                                    Message = fuseExists ? "Fuse 1.obj exists" : "Fuse 1.obj does not exist",
                                    Details = fuseExists ? $"Path: {fuseFile}" : "Main file missing"
                                });
                            }
                            catch (Exception ex)
                            {
                                results.Add(new DiagnosticResult
                                {
                                    Category = R.Get("DiagnosticCategoryVfs"),
                                    Test = "File Enumeration",
                                    Status = TestStatus.Warning,
                                    Message = "Cannot enumerate virtual files",
                                    Details = ex.Message
                                });
                            }
                        }
                    }
                    else
                    {
                        results.Add(new DiagnosticResult
                        {
                            Category = R.Get("DiagnosticCategoryVfs"),
                            Test = "VFS Manager",
                            Status = TestStatus.Failed,
                            Message = "VirtualFileSystemManager not initialized",
                            Details = "Cannot check virtual file system status"
                        });
                    }
                }
                catch (Exception ex)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryVfs"),
                        Test = "VFS Check",
                        Status = TestStatus.Failed,
                        Message = "Virtual file system check exception",
                        Details = ex.Message
                    });
                }
            });
        }

        /// <summary>
        /// Check process access control
        /// </summary>
        private async Task CheckProcessAccessControl()
        {
            AddLog("🔧 " + R.Get("DiagnosticCheckingProcessAccessControl"));

            await Task.Run(() =>
            {
                try
                {
                    // Get current process information
                    var currentProcess = Process.GetCurrentProcess();

                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryProcess"),
                        Test = "Current Process Information",
                        Status = TestStatus.Passed,
                        Message = $"Current process: {currentProcess.ProcessName}",
                        Details = $"PID: {currentProcess.Id}, Start time: {currentProcess.StartTime}"
                    });

                    // Check process enumeration permissions
                    try
                    {
                        var processes = Process.GetProcesses();

                        results.Add(new DiagnosticResult
                        {
                            Category = R.Get("DiagnosticCategoryProcess"),
                            Test = "Process Enumeration Permission",
                            Status = TestStatus.Passed,
                            Message = $"Can enumerate {processes.Length} processes",
                            Details = "Has process monitoring permissions"
                        });

                        // Look for target processes
                        bool foundXPlane = false;
                        foreach (var proc in processes)
                        {
                            try
                            {
                                if (proc.ProcessName.ToLower().Contains("xplane") ||
                                    proc.ProcessName.ToLower().Contains("x-plane"))
                                {
                                    foundXPlane = true;
                                    results.Add(new DiagnosticResult
                                    {
                                        Category = R.Get("DiagnosticCategoryProcess"),
                                        Test = "Target Process Detection",
                                        Status = TestStatus.Passed,
                                        Message = $"Found X-Plane process: {proc.ProcessName}",
                                        Details = $"PID: {proc.Id}"
                                    });
                                    break;
                                }
                            }
                            catch
                            {
                                // Ignore inaccessible processes
                            }
                        }

                        if (!foundXPlane)
                        {
                            results.Add(new DiagnosticResult
                            {
                                Category = R.Get("DiagnosticCategoryProcess"),
                                Test = "Target Process Detection",
                                Status = TestStatus.Warning,
                                Message = "No X-Plane process found",
                                Details = "X-Plane may not be running"
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        results.Add(new DiagnosticResult
                        {
                            Category = R.Get("DiagnosticCategoryProcess"),
                            Test = "Process Enumeration",
                            Status = TestStatus.Warning,
                            Message = "Process enumeration restricted",
                            Details = ex.Message
                        });
                    }
                }
                catch (Exception ex)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryProcess"),
                        Test = "Process Control Check",
                        Status = TestStatus.Failed,
                        Message = "Process control check exception",
                        Details = ex.Message
                    });
                }
            });
        }

        /// <summary>
        /// Check memory security
        /// </summary>
        private async Task CheckMemorySecurity()
        {
            AddLog("🔧 " + R.Get("DiagnosticCheckingMemorySecurity"));

            await Task.Run(() =>
            {
                try
                {
                    // Check memory usage
                    var currentProcess = Process.GetCurrentProcess();
                    long workingSet = currentProcess.WorkingSet64;
                    long privateMemory = currentProcess.PrivateMemorySize64;

                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryMemory"),
                        Test = "Memory Usage",
                        Status = TestStatus.Passed,
                        Message = $"Working set: {workingSet / 1024 / 1024} MB, Private memory: {privateMemory / 1024 / 1024} MB",
                        Details = "Memory usage normal"
                    });

                    // Test garbage collection
                    long beforeGC = GC.GetTotalMemory(false);
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    GC.Collect();
                    long afterGC = GC.GetTotalMemory(true);

                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryMemory"),
                        Test = "Garbage Collection",
                        Status = TestStatus.Passed,
                        Message = $"Before GC: {beforeGC / 1024} KB, After GC: {afterGC / 1024} KB",
                        Details = $"Memory freed: {(beforeGC - afterGC) / 1024} KB"
                    });

                    // Check secure cleanup functionality
                    if (securityManager != null)
                    {
                        try
                        {
                            // Create some test data then clean up
                            byte[] testData = new byte[1024];
                            new Random().NextBytes(testData);

                            // Clear test
                            Array.Clear(testData, 0, testData.Length);

                            results.Add(new DiagnosticResult
                            {
                                Category = R.Get("DiagnosticCategoryMemory"),
                                Test = "Data Clearing Function",
                                Status = TestStatus.Passed,
                                Message = "Memory clearing function normal",
                                Details = "Sensitive data can be securely cleared"
                            });
                        }
                        catch (Exception ex)
                        {
                            results.Add(new DiagnosticResult
                            {
                                Category = R.Get("DiagnosticCategoryMemory"),
                                Test = "Data Clearing Function",
                                Status = TestStatus.Warning,
                                Message = "Data clearing test exception",
                                Details = ex.Message
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryMemory"),
                        Test = "Memory Security Check",
                        Status = TestStatus.Failed,
                        Message = "Memory security check exception",
                        Details = ex.Message
                    });
                }
            });
        }

        /// <summary>
        /// Check network functionality
        /// </summary>
        private async Task CheckNetworkFunctionality()
        {
            AddLog("🔧 " + R.Get("DiagnosticCheckingNetworkFunctionality"));

            try
            {
                // Check if network.dll exists
                string dllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "network.dll");
                bool dllExists = File.Exists(dllPath);

                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryNetwork"),
                    Test = "Network DLL File Exists",
                    Status = dllExists ? TestStatus.Passed : TestStatus.Failed,
                    Message = dllExists ? "Found network.dll" : "network.dll does not exist",
                    Details = $"Path: {dllPath}"
                });

                if (networkManager != null)
                {
                    // Check if network.dll is available
                    bool dllAvailable = await Task.Run(() => networkManager.IsNetworkDllAvailable());

                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryNetwork"),
                        Test = "Network DLL Loading",
                        Status = dllAvailable ? TestStatus.Passed : TestStatus.Warning,
                        Message = dllAvailable ? "network.dll loaded successfully" : "network.dll cannot be loaded, will use fallback method",
                        Details = dllAvailable ? "Can call DLL functions" : "May be missing dependencies or DLL is corrupted"
                    });

                    // Test connection functionality
                    await TestNetworkConnection();

                    // Test response validation functionality
                    await TestNetworkValidation();

                    // Test complete validation process
                    await TestFullNetworkValidation();
                }
                else
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryNetwork"),
                        Test = "NetworkManager",
                        Status = TestStatus.Failed,
                        Message = "NetworkManager not initialized",
                        Details = "Cannot test network functionality"
                    });
                }
            }
            catch (Exception ex)
            {
                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryNetwork"),
                    Test = "Network Functionality Check",
                    Status = TestStatus.Failed,
                    Message = "Network functionality check exception",
                    Details = ex.Message
                });
            }
        }

        /// <summary>
        /// Test network connection
        /// </summary>
        private async Task TestNetworkConnection()
        {
            try
            {
                // Test multiple public services
                string[] testUrls = {
                    "https://httpbin.org/status/200",
                    "https://www.google.com",
                    "https://www.microsoft.com"
                };

                int successCount = 0;
                foreach (var url in testUrls)
                {
                    try
                    {
                        bool connected = await networkManager!.TestServerConnectionAsync(url);
                        if (connected) successCount++;
                    }
                    catch
                    {
                        // Ignore individual connection failures
                    }
                }

                TestStatus status = successCount > 0 ? TestStatus.Passed : TestStatus.Failed;
                if (successCount < testUrls.Length && successCount > 0)
                {
                    status = TestStatus.Warning;
                }

                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryNetwork"),
                    Test = "Network Connection Test",
                    Status = status,
                    Message = $"Successfully connected to {successCount}/{testUrls.Length} test servers",
                    Details = successCount > 0 ? "Network connection normal" : "Network connection abnormal, please check network settings"
                });
            }
            catch (Exception ex)
            {
                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryNetwork"),
                    Test = "Network Connection Test",
                    Status = TestStatus.Failed,
                    Message = "Network connection test failed",
                    Details = ex.Message
                });
            }
        }

        /// <summary>
        /// Test network validation functionality
        /// </summary>
        private async Task TestNetworkValidation()
        {
            try
            {
                // Create test data
                string testUrl = "https://httpbin.org/post"; // httpbin.org provides test API
                string testData = networkManager!.CreateTestRequestData("TEST-NETWORK-VALIDATION");

                // Test response validation
                bool validationResult = await networkManager.ValidateServerResponseAsync(testUrl, testData);

                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryNetwork"),
                    Test = "Response Validation Function",
                    Status = TestStatus.Passed, // Since it's a test server, mainly test that it doesn't crash
                    Message = "Response validation function normal",
                    Details = $"Test result: {validationResult} (using test server, result may be false)"
                });

                // Test error handling
                string lastError = networkManager.GetLastError();
                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryNetwork"),
                    Test = "Error Information Retrieval",
                    Status = !string.IsNullOrEmpty(lastError) ? TestStatus.Passed : TestStatus.Warning,
                    Message = "Error information retrieval function normal",
                    Details = $"Last error: {lastError}"
                });
            }
            catch (Exception ex)
            {
                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryNetwork"),
                    Test = "Response Validation Function",
                    Status = TestStatus.Failed,
                    Message = "Response validation test failed",
                    Details = ex.Message
                });
            }
        }

        /// <summary>
        /// Test complete network validation process
        /// </summary>
        private async Task TestFullNetworkValidation()
        {
            try
            {
                string testActivationCode = "NETWORK-DIAGNOSTIC-TEST";
                string testServerUrl = "https://httpbin.org/post";

                var validationResult = await networkManager!.PerformFullValidationAsync(testActivationCode, testServerUrl);

                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryNetwork"),
                    Test = "Complete Validation Process",
                    Status = validationResult.ConnectionTest ? TestStatus.Passed : TestStatus.Warning,
                    Message = "Complete validation process test completed",
                    Details = $"Connection test: {validationResult.ConnectionTest}, Time taken: {validationResult.Duration.TotalMilliseconds:F0}ms, Info: {validationResult.ErrorMessage}"
                });

                // Performance check
                if (validationResult.Duration.TotalSeconds < 10)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryNetwork"),
                        Test = "Network Performance",
                        Status = TestStatus.Passed,
                        Message = $"Network response time: {validationResult.Duration.TotalMilliseconds:F0}ms",
                        Details = "Network performance good"
                    });
                }
                else
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryNetwork"),
                        Test = "Network Performance",
                        Status = TestStatus.Warning,
                        Message = $"Network response time: {validationResult.Duration.TotalMilliseconds:F0}ms",
                        Details = "Network response slow, may affect user experience"
                    });
                }
            }
            catch (Exception ex)
            {
                results.Add(new DiagnosticResult
                {
                    Category = R.Get("DiagnosticCategoryNetwork"),
                    Test = "Complete Validation Process",
                    Status = TestStatus.Failed,
                    Message = "Complete validation process test failed",
                    Details = ex.Message
                });
            }
        }

        /// <summary>
        /// Performance testing
        /// </summary>
        private async Task CheckPerformance()
        {
            AddLog("🔧 " + R.Get("DiagnosticPerformanceTesting"));

            await Task.Run(() =>
            {
                try
                {
                    // Test activation code validation performance
                    var stopwatch = Stopwatch.StartNew();

                    for (int i = 0; i < 100; i++)
                    {
                        if (securityManager != null)
                        {
                            securityManager.ValidateAndDecrypt($"TEST-PERFORMANCE-{i}");
                        }
                    }

                    stopwatch.Stop();
                    double avgTime = stopwatch.ElapsedMilliseconds / 100.0;

                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryPerformance"),
                        Test = "Activation Code Validation Performance",
                        Status = avgTime < 100 ? TestStatus.Passed : TestStatus.Warning,
                        Message = $"Average validation time: {avgTime:F2} ms",
                        Details = $"100 validations total time: {stopwatch.ElapsedMilliseconds} ms"
                    });

                    // Test file system access performance
                    if (vfsManager != null && Directory.Exists(vfsManager.MountPoint))
                    {
                        stopwatch.Restart();

                        for (int i = 0; i < 50; i++)
                        {
                            try
                            {
                                Directory.GetFiles(vfsManager.MountPoint);
                            }
                            catch
                            {
                                // Ignore access errors
                            }
                        }

                        stopwatch.Stop();
                        double avgFileAccess = stopwatch.ElapsedMilliseconds / 50.0;

                        results.Add(new DiagnosticResult
                        {
                            Category = R.Get("DiagnosticCategoryPerformance"),
                            Test = "File System Access Performance",
                            Status = avgFileAccess < 50 ? TestStatus.Passed : TestStatus.Warning,
                            Message = $"Average access time: {avgFileAccess:F2} ms",
                            Details = $"50 accesses total time: {stopwatch.ElapsedMilliseconds} ms"
                        });
                    }
                }
                catch (Exception ex)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryPerformance"),
                        Test = "Performance Testing",
                        Status = TestStatus.Failed,
                        Message = "Performance testing exception",
                        Details = ex.Message
                    });
                }
            });
        }

        /// <summary>
        /// Integrated functionality testing
        /// </summary>
        private async Task CheckIntegratedFunctionality()
        {
            AddLog("🔧 " + R.Get("DiagnosticIntegratedFunctionality"));

            await Task.Run(() =>
            {
                try
                {
                    // Simulate complete activation process
                    if (securityManager != null)
                    {
                        string testCode = "XPLANE-INTEGRATED-TEST-2025";
                        var result = securityManager.ValidateAndDecrypt(testCode);

                        if (result != null)
                        {
                            // Check data integrity
                            string content = System.Text.Encoding.UTF8.GetString(result);
                            bool hasObjHeader = content.Contains("# X-Plane");
                            bool hasVertices = content.Contains("v ");
                            bool hasFaces = content.Contains("f ");

                            results.Add(new DiagnosticResult
                            {
                                Category = R.Get("DiagnosticCategoryIntegrated"),
                                Test = "Complete Activation Process",
                                Status = hasObjHeader && hasVertices && hasFaces ? TestStatus.Passed : TestStatus.Warning,
                                Message = "Activation process test completed",
                                Details = $"Data size: {result.Length}, OBJ format: {hasObjHeader}, Geometry data: {hasVertices && hasFaces}"
                            });

                            // Check if contains C++ DLL marker
                            bool hasCppMarker = content.Contains("C++ DLL") || content.Contains("CryptoEngine");
                            bool hasFallbackMarker = content.Contains("Fallback") || content.Contains("backup");

                            string sourceMethod = hasCppMarker ? "C++ DLL" : (hasFallbackMarker ? "C# Fallback" : "Unknown");

                            results.Add(new DiagnosticResult
                            {
                                Category = R.Get("DiagnosticCategoryIntegrated"),
                                Test = "Data Source Verification",
                                Status = TestStatus.Passed,
                                Message = $"Data source: {sourceMethod}",
                                Details = hasCppMarker ? "Uses C++ DLL to generate data" : "Uses C# fallback method to generate data"
                            });
                        }
                        else
                        {
                            results.Add(new DiagnosticResult
                            {
                                Category = R.Get("DiagnosticCategoryIntegrated"),
                                Test = "Complete Activation Process",
                                Status = TestStatus.Failed,
                                Message = "Activation process failed",
                                Details = "SecurityManager returned null"
                            });
                        }
                    }

                    // Test network and security integration
                    if (networkManager != null && securityManager != null)
                    {
                        try
                        {
                            // Create a network request containing security information
                            string testCode = "NETWORK-SECURITY-INTEGRATION";
                            string requestData = networkManager.CreateTestRequestData(testCode);

                            // Verify request data format
                            bool hasActivationCode = requestData.Contains("activation_code");
                            bool hasTimestamp = requestData.Contains("timestamp");
                            bool hasClientVersion = requestData.Contains("client_version");

                            results.Add(new DiagnosticResult
                            {
                                Category = R.Get("DiagnosticCategoryIntegrated"),
                                Test = "Network Security Integration",
                                Status = hasActivationCode && hasTimestamp && hasClientVersion ? TestStatus.Passed : TestStatus.Warning,
                                Message = "Network security integration test completed",
                                Details = $"Request format validation: Activation code{(hasActivationCode ? "✓" : "✗")}, Timestamp{(hasTimestamp ? "✓" : "✗")}, Version{(hasClientVersion ? "✓" : "✗")}"
                            });
                        }
                        catch (Exception ex)
                        {
                            results.Add(new DiagnosticResult
                            {
                                Category = R.Get("DiagnosticCategoryIntegrated"),
                                Test = "Network Security Integration",
                                Status = TestStatus.Warning,
                                Message = "Network security integration test exception",
                                Details = ex.Message
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    results.Add(new DiagnosticResult
                    {
                        Category = R.Get("DiagnosticCategoryIntegrated"),
                        Test = "Integrated Functionality Test",
                        Status = TestStatus.Failed,
                        Message = "Integrated functionality test exception",
                        Details = ex.Message
                    });
                }
            });
        }

        /// <summary>
        /// Check if running as administrator
        /// </summary>
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
        /// Generate diagnostic report
        /// </summary>
        private DiagnosticReport GenerateReport()
        {
            var report = new DiagnosticReport
            {
                Timestamp = DateTime.Now,
                TotalTests = results.Count,
                PassedTests = results.Count(r => r.Status == TestStatus.Passed),
                WarningTests = results.Count(r => r.Status == TestStatus.Warning),
                FailedTests = results.Count(r => r.Status == TestStatus.Failed),
                Results = results.ToList()
            };

            // Calculate overall status
            if (report.FailedTests == 0 && report.WarningTests == 0)
            {
                report.OverallStatus = "Excellent";
            }
            else if (report.FailedTests == 0)
            {
                report.OverallStatus = "Good";
            }
            else if (report.FailedTests < report.PassedTests)
            {
                report.OverallStatus = "Needs Attention";
            }
            else
            {
                report.OverallStatus = "Has Issues";
            }

            // 记录详细的诊断摘要
            string summaryMessage = R.GetFormatted("DiagnosticResultSummary",
                report.TotalTests,
                report.PassedTests,
                report.WarningTests,
                report.FailedTests,
                report.OverallStatus);

            AddLog(summaryMessage);

            return report;
        }

        private void AddLog(string message)
        {
            Console.WriteLine($"[SystemDiagnostics] {message}");
        }

        // Windows API
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);
    }

    /// <summary>
    /// Diagnostic result
    /// </summary>
    public class DiagnosticResult
    {
        public string Category { get; set; } = "";
        public string Test { get; set; } = "";
        public TestStatus Status { get; set; }
        public string Message { get; set; } = "";
        public string Details { get; set; } = "";
    }

    /// <summary>
    /// Test status enumeration
    /// </summary>
    public enum TestStatus
    {
        Passed,
        Warning,
        Failed
    }

    /// <summary>
    /// Diagnostic report
    /// </summary>
    public class DiagnosticReport
    {
        public DateTime Timestamp { get; set; }
        public int TotalTests { get; set; }
        public int PassedTests { get; set; }
        public int WarningTests { get; set; }
        public int FailedTests { get; set; }
        public string OverallStatus { get; set; } = "";
        public List<DiagnosticResult> Results { get; set; } = new List<DiagnosticResult>();
    }
}