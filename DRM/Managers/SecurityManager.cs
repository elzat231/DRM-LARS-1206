using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Linq;

namespace XPlaneActivator
{
    /// <summary>
    /// 真实文件解密的安全管理器 - 完全移除假数据生成
    /// </summary>
    public class SecurityManager : IDisposable
    {
        private bool disposed = false;
        private readonly Dictionary<string, EncryptedFileInfo> encryptedFiles = new();
        private readonly string encryptedDirectoryPath;

        // P/Invoke 声明 - 与 C++ DLL 完全匹配
        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int TestFunctionality();

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ValidateActivationCode([MarshalAs(UnmanagedType.LPStr)] string activationCode, int codeLength);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int DecryptWithToken([MarshalAs(UnmanagedType.LPStr)] string token, byte[] outputBuffer, int bufferSize);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int DecryptWithActivationCode([MarshalAs(UnmanagedType.LPStr)] string activationCode, byte[] outputBuffer, int bufferSize);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int DecryptEncryptedFile([MarshalAs(UnmanagedType.LPStr)] string encryptedFilePath, byte[] outputBuffer, int bufferSize);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ValidateEncryptedFileHeader([MarshalAs(UnmanagedType.LPStr)] string encryptedFilePath);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int GetEncryptedFileOriginalSize([MarshalAs(UnmanagedType.LPStr)] string encryptedFilePath);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ExtractEncryptedFileInfo([MarshalAs(UnmanagedType.LPStr)] string encryptedFilePath,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder originalNameBuffer, int nameBufferSize,
            out uint originalSize, out uint encryptedSize);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int VerifyFileIntegrity([MarshalAs(UnmanagedType.LPStr)] string encryptedFilePath,
            byte[] decryptedData, int dataSize);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int GetLastErrorCode();

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int GetLastErrorMessage([MarshalAs(UnmanagedType.LPStr)] StringBuilder errorBuffer, int bufferSize);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void SecureMemoryCleanup();

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ValidateCallingProcess();

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int DetectSecurityThreats();

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int CheckTargetApplicationRunning();

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ValidateDataIntegrity(byte[] data, int dataSize);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int GetDecryptedDataSize();

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int InitializeCryptoEngine([MarshalAs(UnmanagedType.LPStr)] string configParams);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void CleanupCryptoEngine();

        public SecurityManager(string? encryptedDirectoryPath = null)
        {
            this.encryptedDirectoryPath = encryptedDirectoryPath ??
                @"D:\steam\steamapps\common\X-Plane 12\Aircraft\MyPlane\777X\encrypted";

            System.Diagnostics.Debug.WriteLine($"[SecurityManager] === REAL FILE DECRYPTION MANAGER ===");
            System.Diagnostics.Debug.WriteLine($"[SecurityManager] Target directory: {this.encryptedDirectoryPath}");

            // 初始化 CryptoEngine.dll
            InitializeCryptoDll();

            // 扫描真实加密文件
            ScanRealEncryptedFiles();

            System.Diagnostics.Debug.WriteLine($"[SecurityManager] Initialization complete - {encryptedFiles.Count} real encrypted files found");
        }

        /// <summary>
        /// 初始化 CryptoEngine.dll
        /// </summary>
        private void InitializeCryptoDll()
        {
            try
            {
                if (IsCryptoDllAvailable())
                {
                    int initResult = InitializeCryptoEngine("real_file_mode");
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] CryptoEngine.dll initialization: {(initResult == 1 ? "SUCCESS" : "FAILED")}");
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine("[SecurityManager] CryptoEngine.dll not available");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] CryptoEngine.dll initialization error: {ex.Message}");
            }
        }

        /// <summary>
        /// 扫描真实的加密文件目录
        /// </summary>
        private void ScanRealEncryptedFiles()
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Scanning for real encrypted files: {encryptedDirectoryPath}");

                if (!Directory.Exists(encryptedDirectoryPath))
                {
                    System.Diagnostics.Debug.WriteLine("[SecurityManager] ✗ Encrypted directory not found - NO REAL FILES AVAILABLE");
                    return;
                }

                var encFiles = Directory.GetFiles(encryptedDirectoryPath, "*.enc", SearchOption.AllDirectories);
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Found {encFiles.Length} .enc files in directory");

                encryptedFiles.Clear();

                foreach (string encFile in encFiles)
                {
                    try
                    {
                        var fileInfo = ExtractRealFileInfo(encFile);
                        if (fileInfo != null)
                        {
                            string key = fileInfo.RelativePath;
                            if (string.IsNullOrEmpty(key))
                            {
                                key = Path.GetFileNameWithoutExtension(Path.GetFileNameWithoutExtension(Path.GetFileName(encFile)));
                            }

                            encryptedFiles[key] = fileInfo;
                            System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✓ Real file loaded: {key} -> {encFile} ({fileInfo.OriginalSize} bytes)");
                        }
                        else
                        {
                            System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ Failed to process: {encFile}");
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ Error processing {encFile}: {ex.Message}");
                    }
                }

                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Real file scan complete: {encryptedFiles.Count} files loaded");

                if (encryptedFiles.Count == 0)
                {
                    System.Diagnostics.Debug.WriteLine("[SecurityManager] ⚠ WARNING: No real encrypted files found - system will not function properly");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Scan error: {ex.Message}");
            }
        }

        /// <summary>
        /// 提取真实文件信息 - 只使用真实的 .enc 文件
        /// </summary>
        private EncryptedFileInfo? ExtractRealFileInfo(string encryptedFilePath)
        {
            try
            {
                if (!File.Exists(encryptedFilePath))
                {
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] File does not exist: {encryptedFilePath}");
                    return null;
                }

                // 首先尝试使用 DLL 提取信息
                if (IsCryptoDllAvailable())
                {
                    try
                    {
                        // 验证文件头
                        int headerValid = ValidateEncryptedFileHeader(encryptedFilePath);
                        if (headerValid == 1)
                        {
                            var originalNameBuffer = new StringBuilder(256);
                            uint originalSize, encryptedSize;

                            int result = ExtractEncryptedFileInfo(encryptedFilePath, originalNameBuffer, originalNameBuffer.Capacity,
                                out originalSize, out encryptedSize);

                            if (result == 1)
                            {
                                string originalName = originalNameBuffer.ToString();
                                if (string.IsNullOrEmpty(originalName))
                                {
                                    originalName = Path.GetFileNameWithoutExtension(Path.GetFileNameWithoutExtension(Path.GetFileName(encryptedFilePath)));
                                }

                                System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✓ DLL extracted info: {originalName} ({originalSize} bytes)");

                                return new EncryptedFileInfo
                                {
                                    RelativePath = originalName,
                                    OriginalSize = (int)originalSize,
                                    EncryptedSize = (int)encryptedSize,
                                    EncryptedFile = encryptedFilePath,
                                    Checksum = "dll_verified"
                                };
                            }
                            else
                            {
                                string error = GetDllLastError();
                                System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ DLL info extraction failed: {error}");
                            }
                        }
                        else
                        {
                            string error = GetDllLastError();
                            System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ Invalid file header: {encryptedFilePath} - {error}");
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ DLL info extraction exception: {ex.Message}");
                    }
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine("[SecurityManager] ✗ CryptoEngine.dll not available for file info extraction");
                }

                return null; // 不创建任何回退数据
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ Extract file info error: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 真实的多文件解密方法 - 只解密真实的 .enc 文件
        /// </summary>
        public Dictionary<string, byte[]>? DecryptMultipleFiles()
        {
            System.Diagnostics.Debug.WriteLine($"[SecurityManager] === DecryptMultipleFiles (REAL FILES ONLY) ===");
            System.Diagnostics.Debug.WriteLine($"[SecurityManager] Files to decrypt: {encryptedFiles.Count}");

            if (encryptedFiles.Count == 0)
            {
                System.Diagnostics.Debug.WriteLine("[SecurityManager] ✗ No encrypted files to decrypt");
                return null;
            }

            if (!IsCryptoDllAvailable())
            {
                System.Diagnostics.Debug.WriteLine("[SecurityManager] ✗ CryptoEngine.dll not available - cannot decrypt real files");
                return null;
            }

            var results = new Dictionary<string, byte[]>();
            int successCount = 0;
            int failCount = 0;

            foreach (var fileEntry in encryptedFiles)
            {
                try
                {
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] 🔓 Decrypting real file: {fileEntry.Key}");

                    byte[]? decryptedData = DecryptRealFile(fileEntry.Value);
                    if (decryptedData != null && decryptedData.Length > 0)
                    {
                        results[fileEntry.Key] = decryptedData;
                        successCount++;

                        // 记录真实解密的文件信息
                        string header = GetFileHeaderInfo(decryptedData);
                        System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✅ REAL decryption SUCCESS: {fileEntry.Key} ({decryptedData.Length} bytes) - {header}");
                    }
                    else
                    {
                        failCount++;
                        System.Diagnostics.Debug.WriteLine($"[SecurityManager] ❌ REAL decryption FAILED: {fileEntry.Key}");
                    }
                }
                catch (Exception ex)
                {
                    failCount++;
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] ❌ Exception decrypting {fileEntry.Key}: {ex.Message}");
                }
            }

            System.Diagnostics.Debug.WriteLine($"[SecurityManager] Real decryption complete: {successCount} success, {failCount} failed");

            if (results.Count == 0)
            {
                System.Diagnostics.Debug.WriteLine("[SecurityManager] ✗ No files successfully decrypted - NO REAL CONTENT AVAILABLE");
                return null;
            }

            return results;
        }

        /// <summary>
        /// 解密单个真实文件 - 完全移除假数据生成
        /// </summary>
        private byte[]? DecryptRealFile(EncryptedFileInfo fileInfo)
        {
            try
            {
                if (!File.Exists(fileInfo.EncryptedFile))
                {
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ Encrypted file not found: {fileInfo.EncryptedFile}");
                    return null; // 不生成假数据
                }

                if (!IsCryptoDllAvailable())
                {
                    System.Diagnostics.Debug.WriteLine("[SecurityManager] ✗ CryptoEngine.dll not available for real decryption");
                    return null; // 不生成假数据
                }

                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Starting REAL decryption: {fileInfo.RelativePath}");

                // 获取文件的真实大小
                int originalSize = GetEncryptedFileOriginalSize(fileInfo.EncryptedFile);
                if (originalSize <= 0)
                {
                    string error = GetDllLastError();
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ Cannot get original size: {originalSize} - {error}");
                    return null;
                }

                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Original file size: {originalSize} bytes");

                // 分配足够的缓冲区
                byte[] outputBuffer = new byte[originalSize + 1024]; // 额外的安全边界

                // 调用 DLL 解密文件
                int decryptedSize = DecryptEncryptedFile(fileInfo.EncryptedFile, outputBuffer, outputBuffer.Length);

                if (decryptedSize > 0)
                {
                    // 调整缓冲区大小到实际解密的大小
                    Array.Resize(ref outputBuffer, decryptedSize);

                    // 验证解密数据的完整性
                    int integrityCheck = ValidateDataIntegrity(outputBuffer, decryptedSize);
                    if (integrityCheck == 1)
                    {
                        System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✅ Data integrity verified: {fileInfo.RelativePath}");
                    }
                    else
                    {
                        System.Diagnostics.Debug.WriteLine($"[SecurityManager] ⚠ Data integrity check failed: {fileInfo.RelativePath} (but continuing)");
                    }

                    // 验证文件完整性
                    try
                    {
                        int fileIntegrityCheck = VerifyFileIntegrity(fileInfo.EncryptedFile, outputBuffer, decryptedSize);
                        if (fileIntegrityCheck == 1)
                        {
                            System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✅ File integrity verified: {fileInfo.RelativePath}");
                        }
                        else
                        {
                            System.Diagnostics.Debug.WriteLine($"[SecurityManager] ⚠ File integrity check failed: {fileInfo.RelativePath} (but continuing)");
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[SecurityManager] Integrity check exception: {ex.Message}");
                    }

                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✅ REAL decryption successful: {fileInfo.RelativePath} ({decryptedSize} bytes)");
                    return outputBuffer;
                }
                else
                {
                    string error = GetDllLastError();
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ REAL decryption failed: {fileInfo.RelativePath} - {error}");
                    return null; // 不生成假数据
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ Exception in real decryption: {fileInfo.RelativePath} - {ex.Message}");
                return null; // 不生成假数据
            }
        }

        /// <summary>
        /// 使用服务器令牌解密 - 只返回真实数据
        /// </summary>
        public byte[]? DecryptWithToken(string serverToken)
        {
            System.Diagnostics.Debug.WriteLine($"[SecurityManager] === DecryptWithToken (REAL FILES ONLY) ===");

            if (!IsCryptoDllAvailable())
            {
                System.Diagnostics.Debug.WriteLine("[SecurityManager] ✗ CryptoEngine.dll not available for token decryption");
                return null;
            }

            try
            {
                // 先尝试解密真实文件
                var realFiles = DecryptMultipleFiles();
                if (realFiles != null && realFiles.Count > 0)
                {
                    // 返回最大的文件作为主要内容
                    var primaryFile = realFiles.OrderByDescending(f => f.Value.Length).First();
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] Returning primary real file: {primaryFile.Key} ({primaryFile.Value.Length} bytes)");
                    return primaryFile.Value;
                }

                // 如果没有真实文件，尝试使用令牌解密
                System.Diagnostics.Debug.WriteLine("[SecurityManager] No real files available, trying token decryption");

                byte[] outputBuffer = new byte[GetDecryptedDataSize()];
                int decryptedSize = DecryptWithToken(serverToken, outputBuffer, outputBuffer.Length);

                if (decryptedSize > 0)
                {
                    Array.Resize(ref outputBuffer, decryptedSize);
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✅ Token decryption successful: {decryptedSize} bytes");
                    return outputBuffer;
                }
                else
                {
                    string error = GetDllLastError();
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ Token decryption failed: {error}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Token decryption exception: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 使用激活码解密 - 只返回真实数据
        /// </summary>
        public byte[]? ValidateAndDecrypt(string activationCode)
        {
            System.Diagnostics.Debug.WriteLine($"[SecurityManager] === ValidateAndDecrypt (REAL FILES ONLY) ===");

            if (!IsCryptoDllAvailable())
            {
                System.Diagnostics.Debug.WriteLine("[SecurityManager] ✗ CryptoEngine.dll not available for activation code decryption");
                return null;
            }

            try
            {
                // 先验证激活码
                int validationResult = ValidateActivationCode(activationCode, activationCode.Length);
                if (validationResult != 1)
                {
                    string error = GetDllLastError();
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ Activation code validation failed: {error}");
                    return null;
                }

                // 先尝试解密真实文件
                var realFiles = DecryptMultipleFiles();
                if (realFiles != null && realFiles.Count > 0)
                {
                    // 返回最大的文件作为主要内容
                    var primaryFile = realFiles.OrderByDescending(f => f.Value.Length).First();
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] Returning primary real file: {primaryFile.Key} ({primaryFile.Value.Length} bytes)");
                    return primaryFile.Value;
                }

                // 如果没有真实文件，尝试使用激活码解密
                System.Diagnostics.Debug.WriteLine("[SecurityManager] No real files available, trying activation code decryption");

                byte[] outputBuffer = new byte[GetDecryptedDataSize()];
                int decryptedSize = DecryptWithActivationCode(activationCode, outputBuffer, outputBuffer.Length);

                if (decryptedSize > 0)
                {
                    Array.Resize(ref outputBuffer, decryptedSize);
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✅ Activation code decryption successful: {decryptedSize} bytes");
                    return outputBuffer;
                }
                else
                {
                    string error = GetDllLastError();
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] ✗ Activation code decryption failed: {error}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Activation code decryption exception: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 获取文件头信息用于验证
        /// </summary>
        private string GetFileHeaderInfo(byte[] data)
        {
            try
            {
                if (data == null || data.Length < 16)
                    return "Empty/Too small";

                // 检查文件类型
                if (data.Length >= 8 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47)
                {
                    return "PNG Image";
                }

                if (data.Length >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF)
                {
                    return "JPEG Image";
                }

                // 检查文本文件
                try
                {
                    string textStart = Encoding.UTF8.GetString(data, 0, Math.Min(50, data.Length));
                    if (textStart.StartsWith("#") || textStart.Contains("TEXTURE") || textStart.Contains("v ") || textStart.Contains("f "))
                    {
                        return $"OBJ file: {textStart.Substring(0, Math.Min(20, textStart.Length)).Replace('\n', ' ').Replace('\r', ' ')}...";
                    }
                }
                catch { }

                // 显示前几个字节
                string hexStart = string.Join(" ", data.Take(8).Select(b => b.ToString("X2")));
                return $"Binary: {hexStart}...";
            }
            catch
            {
                return "Unknown";
            }
        }

        /// <summary>
        /// 获取 DLL 的最后错误信息
        /// </summary>
        private string GetDllLastError()
        {
            if (!IsCryptoDllAvailable()) return "DLL not available";

            try
            {
                var errorBuffer = new StringBuilder(512);
                int length = GetLastErrorMessage(errorBuffer, errorBuffer.Capacity);

                if (length > 0)
                {
                    return errorBuffer.ToString();
                }

                int errorCode = GetLastErrorCode();
                return $"Error code: {errorCode}";
            }
            catch (Exception ex)
            {
                return $"Failed to get DLL error info: {ex.Message}";
            }
        }

        // =====================================================
        // 标准接口方法
        // =====================================================

        public Dictionary<string, EncryptedFileInfo> GetEncryptedFiles()
        {
            return new Dictionary<string, EncryptedFileInfo>(encryptedFiles);
        }

        public bool IsCryptoDllAvailable()
        {
            try
            {
                int result = TestFunctionality();
                return result == 1;
            }
            catch
            {
                return false;
            }
        }

        public bool TestCryptoDll() => IsCryptoDllAvailable();

        public bool ValidateDecryptedData(byte[] data)
        {
            if (data == null || data.Length == 0) return false;

            try
            {
                // 使用 DLL 的数据完整性验证
                if (IsCryptoDllAvailable())
                {
                    int result = ValidateDataIntegrity(data, data.Length);
                    return result == 1;
                }

                // 回退验证
                string content = Encoding.UTF8.GetString(data);
                bool hasObjHeader = content.Contains("# X-Plane") || content.Contains("# Object") || content.StartsWith("# ");
                bool hasVertices = content.Contains("v ") || content.Contains("vt ") || content.Contains("vn ");
                bool hasFaces = content.Contains("f ");
                bool isPngFile = data.Length > 8 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47;
                bool isDdsFile = data.Length > 4 && data[0] == 0x44 && data[1] == 0x44 && data[2] == 0x53 && data[3] == 0x20;

                return (hasObjHeader && hasVertices) || isPngFile || isDdsFile || (data.Length > 100 && hasVertices);
            }
            catch
            {
                return data.Length > 0;
            }
        }

        public bool ValidateProcessSecurity()
        {
            if (!IsCryptoDllAvailable()) return true;

            try
            {
                int result = ValidateCallingProcess();
                return result == 1;
            }
            catch
            {
                return true;
            }
        }

        public string GetDecryptionMethod()
        {
            return IsCryptoDllAvailable()
                ? $"CryptoEngine.dll Real File Decryption (Files: {encryptedFiles.Count})"
                : $"No Decryption Available (Files: {encryptedFiles.Count})";
        }

        public SecurityThreatInfo CheckSecurityThreats()
        {
            var threatInfo = new SecurityThreatInfo
            {
                DllAvailable = IsCryptoDllAvailable(),
                ThreatsDetected = false,
                ThreatCount = 0,
                XPlaneRunning = false,
                XPlaneProcessCount = 0,
                Message = "System security check completed"
            };

            try
            {
                if (IsCryptoDllAvailable())
                {
                    int threatCount = DetectSecurityThreats();
                    if (threatCount > 0)
                    {
                        threatInfo.ThreatsDetected = true;
                        threatInfo.ThreatCount = threatCount;
                        threatInfo.Message = $"Security threats detected: {threatCount}";
                    }

                    int targetApps = CheckTargetApplicationRunning();
                    if (targetApps > 0)
                    {
                        threatInfo.XPlaneRunning = true;
                        threatInfo.XPlaneProcessCount = targetApps;
                        threatInfo.Message = $"X-Plane processes detected: {targetApps}";
                    }
                }
            }
            catch (Exception ex)
            {
                threatInfo.ThreatsDetected = true;
                threatInfo.ThreatCount = 1;
                threatInfo.Message = $"Security check failed: {ex.Message}";
            }

            return threatInfo;
        }

        public void PerformSecureCleanup()
        {
            try
            {
                if (IsCryptoDllAvailable())
                {
                    SecureMemoryCleanup();
                }
                encryptedFiles.Clear();
                System.Diagnostics.Debug.WriteLine("[SecurityManager] Secure cleanup completed");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Secure cleanup exception: {ex.Message}");
            }
        }

        public string CalculateDataHash(byte[] data)
        {
            if (data == null || data.Length == 0) return string.Empty;

            try
            {
                using (var sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(data);
                    return Convert.ToHexString(hash).ToLower();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Hash calculation exception: {ex.Message}");
                return string.Empty;
            }
        }

        public void CreateEncryptionManifestFromJson(string jsonData)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine("[SecurityManager] Ignoring JSON manifest, using real files only");
                // 不使用 JSON 清单，只扫描真实文件
                ScanRealEncryptedFiles();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Failed to scan real files: {ex.Message}");
            }
        }

        public void Dispose()
        {
            if (!disposed)
            {
                try
                {
                    if (IsCryptoDllAvailable())
                    {
                        CleanupCryptoEngine();
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] Cleanup exception: {ex.Message}");
                }

                PerformSecureCleanup();
                disposed = true;
                System.Diagnostics.Debug.WriteLine("[SecurityManager] Disposed");
            }
        }
    }

    // 支持类保持不变
    public class EncryptedFileInfo
    {
        public string RelativePath { get; set; } = string.Empty;
        public int OriginalSize { get; set; }
        public int EncryptedSize { get; set; }
        public string EncryptedFile { get; set; } = string.Empty;
        public string Checksum { get; set; } = string.Empty;
    }

    public class SecurityThreatInfo
    {
        public bool DllAvailable { get; set; }
        public bool ThreatsDetected { get; set; }
        public int ThreatCount { get; set; }
        public bool XPlaneRunning { get; set; }
        public int XPlaneProcessCount { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}