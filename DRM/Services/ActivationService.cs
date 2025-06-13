using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
// 使用正确的DRM.VFS命名空间
using VFSManager = DRM.VFS.VirtualFileSystemManager;

namespace XPlaneActivator.Services
{
    public interface IActivationService
    {
        Task<ActivationResult> ActivateOnlineAsync(string activationCode, CancellationToken cancellationToken = default);
        Task<ActivationResult> ActivateOfflineAsync(string activationCode, CancellationToken cancellationToken = default);
        Task<bool> DeactivateAsync();
        Task<bool> ValidateExistingActivationAsync();
        ActivationState? GetCurrentActivationState();
        event EventHandler<ActivationProgressEventArgs> ProgressChanged;
        event EventHandler<string> LogMessage;
    }

    public class ActivationService : IActivationService
    {
        private readonly NetworkManager networkManager;
        private readonly SecurityManager securityManager;
        private readonly VFSManager vfsManager;
        private readonly ActivationStateManager stateManager;

        public event EventHandler<ActivationProgressEventArgs>? ProgressChanged;
        public event EventHandler<string>? LogMessage;

        public ActivationService(
            NetworkManager networkManager,
            SecurityManager securityManager,
            VFSManager vfsManager,
            ActivationStateManager stateManager)
        {
            this.networkManager = networkManager;
            this.securityManager = securityManager;
            this.vfsManager = vfsManager;
            this.stateManager = stateManager;
        }

        public async Task<ActivationResult> ActivateOnlineAsync(string activationCode, CancellationToken cancellationToken = default)
        {
            try
            {
                ReportProgress(ActivationStage.Connecting, "Connecting to activation server...");

                // 生成机器码
                string machineCode = HardwareIdHelper.GetMachineFingerprint();

                // 构建请求数据
                var requestData = ServerConfig.CreateActivationRequest(activationCode, machineCode);
                string requestJson = System.Text.Json.JsonSerializer.Serialize(requestData);

                ReportProgress(ActivationStage.Validating, "Sending activation request...");

                string response = "";
                bool requestSuccessful = false;

                // 获取所有可用的服务器URL
                var serverUrls = ServerConfig.GetAllServerUrls();

                // 依次尝试每个服务器
                foreach (string serverUrl in serverUrls)
                {
                    try
                    {
                        LogMessage?.Invoke(this, $"Trying to connect to server: {serverUrl}");

                        response = await networkManager.HttpPostAsync(
                            requestJson,
                            ServerConfig.ACTIVATION_ENDPOINT,
                            serverUrl
                        );

                        // 如果请求成功，跳出循环
                        requestSuccessful = true;
                        LogMessage?.Invoke(this, $"Server connection successful: {serverUrl}");
                        break;
                    }
                    catch (Exception ex)
                    {
                        LogMessage?.Invoke(this, $"Server {serverUrl} connection failed: {ex.Message}");

                        // 如果不是最后一个服务器，继续尝试下一个
                        if (serverUrl != serverUrls[serverUrls.Length - 1])
                        {
                            LogMessage?.Invoke(this, "Trying next server...");
                            continue;
                        }
                    }
                }

                // 如果所有服务器都失败了
                if (!requestSuccessful)
                {
                    LogMessage?.Invoke(this, "All servers failed to connect");
                    return ActivationResult.Failed("Unable to connect to activation server");
                }

                ReportProgress(ActivationStage.ProcessingResponse, "Processing server response...");

                // 显示响应内容用于调试
                LogMessage?.Invoke(this, $"Server response length: {response?.Length ?? 0}");
                if (!string.IsNullOrEmpty(response))
                {
                    string responsePreview = response.Length > 200 ? response.Substring(0, 200) + "..." : response;
                    LogMessage?.Invoke(this, $"Server response preview: {responsePreview}");
                }

                // 验证响应格式
                if (!ServerConfig.IsValidResponse(response))
                {
                    LogMessage?.Invoke(this, "Invalid server response format");
                    LogMessage?.Invoke(this, $"Raw response: {response}");
                    return ActivationResult.Failed("Invalid server response format");
                }

                // 检查是否是成功响应
                if (!ServerConfig.IsSuccessResponse(response))
                {
                    // 激活失败，提取错误信息
                    string errorMessage = ServerConfig.ExtractErrorMessage(response);
                    LogMessage?.Invoke(this, $"Online activation failed: {errorMessage}");
                    return ActivationResult.Failed(errorMessage);
                }

                // 解析成功响应
                System.Text.Json.JsonDocument? jsonDoc = null;
                System.Text.Json.JsonElement root = default;

                try
                {
                    jsonDoc = System.Text.Json.JsonDocument.Parse(response);
                    root = jsonDoc.RootElement;
                    LogMessage?.Invoke(this, "JSON parsing successful");
                }
                catch (Exception ex)
                {
                    LogMessage?.Invoke(this, $"JSON parsing failed: {ex.Message}");
                    return ActivationResult.Failed("Unable to parse server response");
                }

                try
                {
                    // 尝试获取令牌
                    string? serverToken = ExtractServerToken(root);

                    // 分离激活状态和VFS挂载
                    // 1. 先保存激活状态（不管VFS是否成功）
                    bool stateSaved = stateManager.SaveActivationState(activationCode, serverToken, vfsManager.MountPoint);
                    LogMessage?.Invoke(this, stateSaved ? "Activation state saved" : "Failed to save activation state");

                    // 2. 直接使用CryptoEngine.dll解密真实文件并挂载
                    if (!string.IsNullOrEmpty(serverToken))
                    {
                        LogMessage?.Invoke(this, "Online activation successful, received server token");
                        return await ProcessRealFilesAndMount(activationCode, stateSaved, serverToken);
                    }
                    else
                    {
                        LogMessage?.Invoke(this, "Online activation successful but no token received, using activation code");
                        return await ProcessRealFilesAndMount(activationCode, stateSaved);
                    }
                }
                finally
                {
                    jsonDoc?.Dispose();
                }
            }
            catch (System.TimeoutException)
            {
                LogMessage?.Invoke(this, "Network connection timeout");
                return ActivationResult.Failed("Network connection timeout");
            }
            catch (System.Net.Http.HttpRequestException ex)
            {
                LogMessage?.Invoke(this, $"Network error: {ex.Message}");
                return ActivationResult.Failed($"Network error: {ex.Message}");
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"Online activation exception: {ex.Message}");
                LogMessage?.Invoke(this, $"Exception stack: {ex.StackTrace}");
                return ActivationResult.Failed(ex.Message);
            }
        }

        public async Task<ActivationResult> ActivateOfflineAsync(string activationCode, CancellationToken cancellationToken = default)
        {
            try
            {
                ReportProgress(ActivationStage.Validating, "Offline activation code validation...");

                // 分离激活状态和VFS挂载
                // 1. 先保存激活状态
                bool stateSaved = stateManager.SaveActivationState(activationCode, null, vfsManager.MountPoint);
                LogMessage?.Invoke(this, stateSaved ? "Activation state saved" : "Failed to save activation state");

                // 2. 直接使用CryptoEngine.dll解密真实文件并挂载
                return await ProcessRealFilesAndMount(activationCode, stateSaved);
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"Offline activation exception: {ex.Message}");
                return ActivationResult.Failed(ex.Message);
            }
        }

        /// <summary>
        /// 直接使用CryptoEngine.dll解密真实文件并挂载 - 不生成任何假数据
        /// </summary>
        private async Task<ActivationResult> ProcessRealFilesAndMount(string activationCode, bool stateSaved, string? serverToken = null)
        {
            try
            {
                ReportProgress(ActivationStage.Decrypting, "Decrypting real encrypted files using CryptoEngine.dll...");

                LogMessage?.Invoke(this, "=== REAL FILE DECRYPTION ===");
                LogMessage?.Invoke(this, $"Using SecurityManager to decrypt actual .enc files");

                Dictionary<string, byte[]>? decryptedFiles = null;

                // 根据是否有服务器令牌选择解密方法
                if (!string.IsNullOrEmpty(serverToken))
                {
                    LogMessage?.Invoke(this, "Attempting decryption with server token...");
                    var tokenData = securityManager.DecryptWithToken(serverToken);
                    if (tokenData != null)
                    {
                        // 如果令牌解密成功，尝试获取多文件数据
                        decryptedFiles = securityManager.DecryptMultipleFiles();
                        if (decryptedFiles == null || decryptedFiles.Count == 0)
                        {
                            // 如果多文件解密失败，使用单文件数据
                            decryptedFiles = new Dictionary<string, byte[]>
                            {
                                ["primary_file.obj"] = tokenData
                            };
                        }
                    }
                }

                // 如果令牌解密失败或没有令牌，使用激活码解密
                if (decryptedFiles == null || decryptedFiles.Count == 0)
                {
                    LogMessage?.Invoke(this, "Attempting decryption with activation code...");
                    var activationData = securityManager.ValidateAndDecrypt(activationCode);
                    if (activationData != null)
                    {
                        // 尝试获取多文件数据
                        decryptedFiles = securityManager.DecryptMultipleFiles();
                        if (decryptedFiles == null || decryptedFiles.Count == 0)
                        {
                            // 如果多文件解密失败，使用单文件数据
                            decryptedFiles = new Dictionary<string, byte[]>
                            {
                                ["primary_file.obj"] = activationData
                            };
                        }
                    }
                }

                // 最后尝试直接调用多文件解密
                if (decryptedFiles == null || decryptedFiles.Count == 0)
                {
                    LogMessage?.Invoke(this, "Attempting direct multi-file decryption...");
                    decryptedFiles = securityManager.DecryptMultipleFiles();
                }

                if (decryptedFiles != null && decryptedFiles.Count > 0)
                {
                    long totalSize = decryptedFiles.Values.Sum(data => data.Length);
                    LogMessage?.Invoke(this, $"✓ Successfully decrypted {decryptedFiles.Count} real files, total size: {totalSize} bytes");

                    // 记录解密的真实文件
                    LogMessage?.Invoke(this, "Real decrypted files:");
                    foreach (var file in decryptedFiles.Take(10))
                    {
                        LogMessage?.Invoke(this, $"  - {file.Key}: {FormatFileSize(file.Value.Length)}");
                    }
                    if (decryptedFiles.Count > 10)
                    {
                        LogMessage?.Invoke(this, $"  ... and {decryptedFiles.Count - 10} more files");
                    }

                    // 验证解密数据的完整性
                    bool isValid = ValidateRealDecryptedFiles(decryptedFiles);
                    LogMessage?.Invoke(this, $"Data integrity validation: {(isValid ? "✓ PASSED" : "✗ FAILED")}");

                    if (isValid)
                    {
                        // 尝试挂载虚拟文件系统
                        LogMessage?.Invoke(this, "Mounting real decrypted files to virtual file system...");
                        bool mounted = await MountRealDecryptedFiles(decryptedFiles);

                        if (mounted)
                        {
                            LogMessage?.Invoke(this, "✓ SUCCESS: Real files decrypted and mounted");
                            return ActivationResult.Success(vfsManager.MountPoint, stateSaved, decryptedFiles.Count, totalSize);
                        }
                        else
                        {
                            LogMessage?.Invoke(this, "✗ Real files decrypted but VFS mount failed");
                            return ActivationResult.PartialSuccess("Real files decrypted but virtual file system mount failed", stateSaved, decryptedFiles.Count);
                        }
                    }
                    else
                    {
                        LogMessage?.Invoke(this, "✗ Real file integrity validation failed");
                        return ActivationResult.PartialSuccess("Real files decrypted but integrity validation failed", stateSaved, decryptedFiles.Count);
                    }
                }
                else
                {
                    LogMessage?.Invoke(this, "✗ FAILED: No real files could be decrypted");

                    if (stateSaved)
                    {
                        LogMessage?.Invoke(this, "Activation state saved, but no real files available");
                        return ActivationResult.PartialSuccess("Activation state saved, but unable to decrypt real files", stateSaved);
                    }
                    else
                    {
                        return ActivationResult.Failed("Unable to decrypt real files");
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"Real file processing exception: {ex.Message}");
                return ActivationResult.PartialSuccess($"Error processing real files: {ex.Message}", stateSaved);
            }
        }

        /// <summary>
        /// 验证真实解密文件的完整性
        /// </summary>
        private bool ValidateRealDecryptedFiles(Dictionary<string, byte[]> decryptedFiles)
        {
            try
            {
                LogMessage?.Invoke(this, $"Validating {decryptedFiles.Count} real decrypted files...");

                int validFiles = 0;
                foreach (var file in decryptedFiles)
                {
                    if (file.Value != null && file.Value.Length > 0)
                    {
                        // 使用SecurityManager的验证方法
                        bool isValid = securityManager.ValidateDecryptedData(file.Value);
                        if (isValid)
                        {
                            validFiles++;
                            LogMessage?.Invoke(this, $"✓ Valid real file: {file.Key} ({file.Value.Length} bytes)");
                        }
                        else
                        {
                            LogMessage?.Invoke(this, $"⚠ Invalid real file: {file.Key}");
                        }
                    }
                }

                bool overallValid = validFiles > 0;
                LogMessage?.Invoke(this, $"Real file validation result: {validFiles}/{decryptedFiles.Count} files valid");
                return overallValid;
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"Real file validation exception: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 挂载真实解密的文件到VFS
        /// </summary>
        private async Task<bool> MountRealDecryptedFiles(Dictionary<string, byte[]> decryptedFiles, CancellationToken cancellationToken = default)
        {
            try
            {
                LogMessage?.Invoke(this, "Starting real file virtual file system...");
                ReportProgress(ActivationStage.MountingVFS, $"Mounting {decryptedFiles.Count} real decrypted files...");

                // 直接设置真实解密的文件到VFS
                vfsManager.SetVirtualFiles(decryptedFiles);

                long totalSize = decryptedFiles.Values.Sum(data => data.Length);
                LogMessage?.Invoke(this, $"Set {decryptedFiles.Count} real files to VFS, total size: {totalSize} bytes");

                // 尝试挂载
                bool mounted = await vfsManager.MountAsync(cancellationToken);

                if (mounted)
                {
                    LogMessage?.Invoke(this, $"✓ Real files successfully mounted to {vfsManager.MountPoint}");
                    LogMessage?.Invoke(this, $"Mounted: {vfsManager.FileCount} real files, total size: {FormatFileSize(vfsManager.TotalSize)}");
                    ReportProgress(ActivationStage.Complete, "Real file VFS mount successful");
                    return true;
                }
                else
                {
                    LogMessage?.Invoke(this, "✗ Real file virtual file system mount failed");
                    return false;
                }
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"Real file virtual file system mount exception: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> DeactivateAsync()
        {
            try
            {
                ReportProgress(ActivationStage.Deactivating, "Deactivating...");

                // 1. 清除激活状态
                stateManager.ClearActivationState();
                LogMessage?.Invoke(this, "Activation state cleared");

                // 2. 卸载虚拟文件系统（独立操作）
                try
                {
                    bool unmounted = await vfsManager.UnmountAsync();
                    LogMessage?.Invoke(this, unmounted ? "VFS unmounted successfully" : "VFS unmount failed");
                }
                catch (Exception ex)
                {
                    LogMessage?.Invoke(this, $"VFS unmount exception: {ex.Message}");
                    // VFS卸载失败不影响激活状态清除
                }

                LogMessage?.Invoke(this, "Deactivation completed");
                return true;
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"Deactivation failed: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> ValidateExistingActivationAsync()
        {
            try
            {
                var savedState = stateManager.GetCurrentState();
                if (savedState == null)
                {
                    LogMessage?.Invoke(this, "No saved activation state found");
                    return false;
                }

                LogMessage?.Invoke(this, "Found saved activation state, validating...");

                if (stateManager.ShouldRevalidate())
                {
                    LogMessage?.Invoke(this, "Need to revalidate activation state");

                    // 执行重新验证 - 使用真实文件解密验证
                    if (!string.IsNullOrEmpty(savedState.ActivationCode))
                    {
                        LogMessage?.Invoke(this, "Performing revalidation using real file decryption...");
                        var decryptedFiles = securityManager.DecryptMultipleFiles();

                        bool isValid = decryptedFiles != null && decryptedFiles.Count > 0;
                        LogMessage?.Invoke(this, isValid ? "✓ Revalidation successful - real files decrypted" : "✗ Revalidation failed - cannot decrypt real files");

                        if (isValid)
                        {
                            stateManager.UpdateHeartbeat();
                        }

                        return isValid;
                    }
                }

                LogMessage?.Invoke(this, "Activation state validation passed");
                return true;
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"Activation state validation exception: {ex.Message}");
                return false;
            }
        }

        public ActivationState? GetCurrentActivationState()
        {
            return stateManager.GetCurrentState();
        }

        private void ReportProgress(ActivationStage stage, string message)
        {
            ProgressChanged?.Invoke(this, new ActivationProgressEventArgs(stage, message));
            LogMessage?.Invoke(this, message);
        }

        /// <summary>
        /// 提取服务器令牌（增强版本）
        /// </summary>
        private string? ExtractServerToken(System.Text.Json.JsonElement root)
        {
            try
            {
                LogMessage?.Invoke(this, "Extracting server token...");

                // 扩展的令牌字段名列表
                var tokenProperties = new[] {
                    "token", "activation_token", "access_token", "jwt_token", "auth_token",
                    "serverToken", "server_token", "authToken", "accessToken", "activationToken"
                };

                // 首先在根级别查找
                foreach (var prop in tokenProperties)
                {
                    if (root.TryGetProperty(prop, out var tokenProp))
                    {
                        string? token = tokenProp.GetString();
                        if (!string.IsNullOrWhiteSpace(token))
                        {
                            LogMessage?.Invoke(this, $"Found token field: {prop}, length: {token.Length}");
                            return token;
                        }
                    }
                }

                // 检查嵌套的data字段
                if (root.TryGetProperty("data", out var dataProp))
                {
                    LogMessage?.Invoke(this, "Checking nested data field...");
                    foreach (var prop in tokenProperties)
                    {
                        if (dataProp.TryGetProperty(prop, out var dataTokenProp))
                        {
                            string? token = dataTokenProp.GetString();
                            if (!string.IsNullOrWhiteSpace(token))
                            {
                                LogMessage?.Invoke(this, $"Found token in data field: {prop}, length: {token.Length}");
                                return token;
                            }
                        }
                    }
                }

                // 检查payload字段
                if (root.TryGetProperty("payload", out var payloadProp))
                {
                    LogMessage?.Invoke(this, "Checking payload field...");
                    foreach (var prop in tokenProperties)
                    {
                        if (payloadProp.TryGetProperty(prop, out var payloadTokenProp))
                        {
                            string? token = payloadTokenProp.GetString();
                            if (!string.IsNullOrWhiteSpace(token))
                            {
                                LogMessage?.Invoke(this, $"Found token in payload field: {prop}, length: {token.Length}");
                                return token;
                            }
                        }
                    }
                }

                // 如果仍然找不到，记录所有可用字段
                LogMessage?.Invoke(this, "No standard token field found, response structure:");
                LogResponseStructure(root, "", 0);

                // 尝试使用任何看起来像令牌的长字符串字段
                foreach (var property in root.EnumerateObject())
                {
                    if (property.Value.ValueKind == System.Text.Json.JsonValueKind.String)
                    {
                        string? value = property.Value.GetString();
                        if (!string.IsNullOrWhiteSpace(value) && value.Length > 50)
                        {
                            LogMessage?.Invoke(this, $"Found possible token field: {property.Name}, length: {value.Length}");
                            return value;
                        }
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"Exception extracting token: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 记录响应结构（用于调试）
        /// </summary>
        private void LogResponseStructure(System.Text.Json.JsonElement element, string path, int depth)
        {
            if (depth > 3) return; // 防止过深递归

            foreach (var property in element.EnumerateObject())
            {
                string fullPath = string.IsNullOrEmpty(path) ? property.Name : $"{path}.{property.Name}";

                switch (property.Value.ValueKind)
                {
                    case System.Text.Json.JsonValueKind.String:
                        string? stringValue = property.Value.GetString();
                        int length = stringValue?.Length ?? 0;
                        LogMessage?.Invoke(this, $"  {fullPath}: String (length: {length})");
                        break;
                    case System.Text.Json.JsonValueKind.Object:
                        LogMessage?.Invoke(this, $"  {fullPath}: Object");
                        LogResponseStructure(property.Value, fullPath, depth + 1);
                        break;
                    case System.Text.Json.JsonValueKind.Array:
                        LogMessage?.Invoke(this, $"  {fullPath}: Array");
                        break;
                    default:
                        LogMessage?.Invoke(this, $"  {fullPath}: {property.Value.ValueKind}");
                        break;
                }
            }
        }

        /// <summary>
        /// 格式化文件大小显示
        /// </summary>
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
    }

    // 支持类保持不变
    public enum ActivationStage
    {
        Connecting,
        Validating,
        ProcessingResponse,
        Decrypting,
        MountingVFS,
        Deactivating,
        Complete
    }

    public class ActivationProgressEventArgs : EventArgs
    {
        public ActivationStage Stage { get; }
        public string Message { get; }
        public DateTime Timestamp { get; }

        public ActivationProgressEventArgs(ActivationStage stage, string message)
        {
            Stage = stage;
            Message = message;
            Timestamp = DateTime.Now;
        }
    }

    public class ActivationResult
    {
        public bool IsSuccess { get; private set; }
        public bool IsPartialSuccess { get; private set; }
        public string? MountPoint { get; private set; }
        public bool StateSaved { get; private set; }
        public string? ErrorMessage { get; private set; }
        public int FileCount { get; private set; }
        public long TotalSize { get; private set; }

        private ActivationResult() { }

        public static ActivationResult Success(string mountPoint, bool stateSaved, int fileCount = 0, long totalSize = 0)
        {
            return new ActivationResult
            {
                IsSuccess = true,
                IsPartialSuccess = false,
                MountPoint = mountPoint,
                StateSaved = stateSaved,
                FileCount = fileCount,
                TotalSize = totalSize
            };
        }

        public static ActivationResult PartialSuccess(string errorMessage, bool stateSaved, int fileCount = 0)
        {
            return new ActivationResult
            {
                IsSuccess = false,
                IsPartialSuccess = true,
                StateSaved = stateSaved,
                ErrorMessage = errorMessage,
                FileCount = fileCount
            };
        }

        public static ActivationResult Failed(string errorMessage)
        {
            return new ActivationResult
            {
                IsSuccess = false,
                IsPartialSuccess = false,
                StateSaved = false,
                ErrorMessage = errorMessage,
                FileCount = 0,
                TotalSize = 0
            };
        }
    }
}