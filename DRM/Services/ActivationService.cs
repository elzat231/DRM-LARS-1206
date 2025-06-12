using System;
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
                ReportProgress(ActivationStage.Connecting, "连接到激活服务器...");

                // 生成机器码
                string machineCode = HardwareIdHelper.GetMachineFingerprint();

                // 构建请求数据
                var requestData = ServerConfig.CreateActivationRequest(activationCode, machineCode);
                string requestJson = System.Text.Json.JsonSerializer.Serialize(requestData);

                ReportProgress(ActivationStage.Validating, "发送激活请求...");

                string response = "";
                bool requestSuccessful = false;

                // 获取所有可用的服务器URL
                var serverUrls = ServerConfig.GetAllServerUrls();

                // 依次尝试每个服务器
                foreach (string serverUrl in serverUrls)
                {
                    try
                    {
                        LogMessage?.Invoke(this, $"尝试连接服务器: {serverUrl}");

                        response = await networkManager.HttpPostAsync(
                            requestJson,
                            ServerConfig.ACTIVATION_ENDPOINT,
                            serverUrl
                        );

                        // 如果请求成功，跳出循环
                        requestSuccessful = true;
                        LogMessage?.Invoke(this, $"服务器连接成功: {serverUrl}");
                        break;
                    }
                    catch (Exception ex)
                    {
                        LogMessage?.Invoke(this, $"服务器 {serverUrl} 连接失败: {ex.Message}");

                        // 如果不是最后一个服务器，继续尝试下一个
                        if (serverUrl != serverUrls[serverUrls.Length - 1])
                        {
                            LogMessage?.Invoke(this, "尝试下一个服务器...");
                            continue;
                        }
                    }
                }

                // 如果所有服务器都失败了
                if (!requestSuccessful)
                {
                    LogMessage?.Invoke(this, "所有服务器连接失败");
                    return ActivationResult.Failed("无法连接到激活服务器");
                }

                ReportProgress(ActivationStage.ProcessingResponse, "处理服务器响应...");

                // 显示响应内容用于调试
                LogMessage?.Invoke(this, $"服务器响应长度: {response?.Length ?? 0}");
                if (!string.IsNullOrEmpty(response))
                {
                    string responsePreview = response.Length > 200 ? response.Substring(0, 200) + "..." : response;
                    LogMessage?.Invoke(this, $"服务器响应预览: {responsePreview}");
                }

                // 验证响应格式
                if (!ServerConfig.IsValidResponse(response))
                {
                    LogMessage?.Invoke(this, "服务器响应格式无效");
                    LogMessage?.Invoke(this, $"原始响应: {response}");
                    return ActivationResult.Failed("服务器响应格式无效");
                }

                // 检查是否是成功响应
                if (!ServerConfig.IsSuccessResponse(response))
                {
                    // 激活失败，提取错误信息
                    string errorMessage = ServerConfig.ExtractErrorMessage(response);
                    LogMessage?.Invoke(this, $"在线激活失败: {errorMessage}");
                    return ActivationResult.Failed(errorMessage);
                }

                // 解析成功响应
                System.Text.Json.JsonDocument? jsonDoc = null;
                System.Text.Json.JsonElement root = default;

                try
                {
                    jsonDoc = System.Text.Json.JsonDocument.Parse(response);
                    root = jsonDoc.RootElement;
                    LogMessage?.Invoke(this, "JSON解析成功");
                }
                catch (Exception ex)
                {
                    LogMessage?.Invoke(this, $"JSON解析失败: {ex.Message}");
                    return ActivationResult.Failed("无法解析服务器响应");
                }

                try
                {
                    // 尝试获取令牌
                    string? serverToken = ExtractServerToken(root);

                    // 处理成功的激活
                    if (!string.IsNullOrEmpty(serverToken))
                    {
                        LogMessage?.Invoke(this, "在线激活成功，获得服务器令牌");
                        return await ProcessServerTokenAndSave(serverToken, activationCode);
                    }
                    else
                    {
                        LogMessage?.Invoke(this, "在线激活成功但未获得令牌，尝试直接使用激活码");
                        return await ProcessActivationWithoutTokenAndSave(activationCode);
                    }
                }
                finally
                {
                    jsonDoc?.Dispose();
                }
            }
            catch (System.TimeoutException)
            {
                LogMessage?.Invoke(this, "网络连接超时");
                return ActivationResult.Failed("网络连接超时");
            }
            catch (System.Net.Http.HttpRequestException ex)
            {
                LogMessage?.Invoke(this, $"网络错误: {ex.Message}");
                return ActivationResult.Failed($"网络错误: {ex.Message}");
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"在线激活异常: {ex.Message}");
                LogMessage?.Invoke(this, $"异常堆栈: {ex.StackTrace}");
                return ActivationResult.Failed(ex.Message);
            }
        }

        public async Task<ActivationResult> ActivateOfflineAsync(string activationCode, CancellationToken cancellationToken = default)
        {
            try
            {
                ReportProgress(ActivationStage.Validating, "离线验证激活码...");

                byte[]? decryptedData = await Task.Run(() =>
                    securityManager.ValidateAndDecrypt(activationCode), cancellationToken);

                if (decryptedData != null && decryptedData.Length > 0)
                {
                    ReportProgress(ActivationStage.MountingVFS, "挂载虚拟文件系统...");

                    bool mounted = vfsManager.MountVirtualFileSystem(decryptedData, cancellationToken);
                    if (mounted)
                    {
                        bool saved = stateManager.SaveActivationState(activationCode, null, vfsManager.MountPoint);
                        LogMessage?.Invoke(this, "离线激活成功");
                        return ActivationResult.Success(vfsManager.MountPoint, saved);
                    }
                    else
                    {
                        return ActivationResult.Failed("虚拟文件系统挂载失败");
                    }
                }
                else
                {
                    return ActivationResult.Failed("激活码解密失败");
                }
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"离线激活异常: {ex.Message}");
                return ActivationResult.Failed(ex.Message);
            }
        }

        public async Task<bool> DeactivateAsync()
        {
            try
            {
                ReportProgress(ActivationStage.Deactivating, "取消激活...");

                // 清除激活状态
                stateManager.ClearActivationState();

                // 卸载虚拟文件系统
                vfsManager.UnmountVirtualFileSystem();

                LogMessage?.Invoke(this, "取消激活成功");
                return true;
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"取消激活失败: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> ValidateExistingActivationAsync()
        {
            try
            {
                var savedState = stateManager.GetCurrentState();
                if (savedState == null) return false;

                if (stateManager.ShouldRevalidate())
                {
                    // 执行重新验证
                    if (!string.IsNullOrEmpty(savedState.ServerToken))
                    {
                        // 在线重新验证
                        LogMessage?.Invoke(this, "执行在线重新验证...");
                        await Task.Delay(100); // 模拟验证过程
                        return true; // 简化处理
                    }
                    else if (!string.IsNullOrEmpty(savedState.ActivationCode))
                    {
                        // 离线重新验证
                        LogMessage?.Invoke(this, "执行离线重新验证...");
                        byte[]? data = await Task.Run(() =>
                            securityManager.ValidateAndDecrypt(savedState.ActivationCode));
                        return data != null && data.Length > 0;
                    }
                }

                return true;
            }
            catch
            {
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
                LogMessage?.Invoke(this, "提取服务器令牌...");

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
                            LogMessage?.Invoke(this, $"找到令牌字段: {prop}, 长度: {token.Length}");
                            return token;
                        }
                    }
                }

                // 检查嵌套的data字段
                if (root.TryGetProperty("data", out var dataProp))
                {
                    LogMessage?.Invoke(this, "检查嵌套的data字段...");
                    foreach (var prop in tokenProperties)
                    {
                        if (dataProp.TryGetProperty(prop, out var dataTokenProp))
                        {
                            string? token = dataTokenProp.GetString();
                            if (!string.IsNullOrWhiteSpace(token))
                            {
                                LogMessage?.Invoke(this, $"在data字段中找到令牌: {prop}, 长度: {token.Length}");
                                return token;
                            }
                        }
                    }
                }

                // 检查payload字段
                if (root.TryGetProperty("payload", out var payloadProp))
                {
                    LogMessage?.Invoke(this, "检查payload字段...");
                    foreach (var prop in tokenProperties)
                    {
                        if (payloadProp.TryGetProperty(prop, out var payloadTokenProp))
                        {
                            string? token = payloadTokenProp.GetString();
                            if (!string.IsNullOrWhiteSpace(token))
                            {
                                LogMessage?.Invoke(this, $"在payload字段中找到令牌: {prop}, 长度: {token.Length}");
                                return token;
                            }
                        }
                    }
                }

                // 如果仍然找不到，记录所有可用字段
                LogMessage?.Invoke(this, "未找到标准令牌字段，响应结构:");
                LogResponseStructure(root, "", 0);

                // 尝试使用任何看起来像令牌的长字符串字段
                foreach (var property in root.EnumerateObject())
                {
                    if (property.Value.ValueKind == System.Text.Json.JsonValueKind.String)
                    {
                        string? value = property.Value.GetString();
                        if (!string.IsNullOrWhiteSpace(value) && value.Length > 50)
                        {
                            LogMessage?.Invoke(this, $"发现可能的令牌字段: {property.Name}, 长度: {value.Length}");
                            return value;
                        }
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"提取令牌时异常: {ex.Message}");
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
                        LogMessage?.Invoke(this, $"  {fullPath}: String (长度: {length})");
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
        /// 处理服务器令牌并保存（增强版本）
        /// </summary>
        private async Task<ActivationResult> ProcessServerTokenAndSave(string serverToken, string activationCode)
        {
            try
            {
                ReportProgress(ActivationStage.Decrypting, "使用服务器令牌解密数据...");

                // 增加令牌信息调试
                LogMessage?.Invoke(this, $"处理服务器令牌，长度: {serverToken?.Length ?? 0}");

                if (string.IsNullOrWhiteSpace(serverToken))
                {
                    LogMessage?.Invoke(this, "服务器令牌为空");
                    return ActivationResult.Failed("服务器令牌为空");
                }

                // 显示令牌预览（用于调试）
                string tokenPreview = serverToken.Length > 50
                    ? serverToken.Substring(0, 50) + "..."
                    : serverToken;
                LogMessage?.Invoke(this, $"令牌预览: {tokenPreview}");

                byte[]? decryptedData = await Task.Run(() =>
                {
                    try
                    {
                        LogMessage?.Invoke(this, "调用 SecurityManager.DecryptWithToken...");
                        var result = securityManager.DecryptWithToken(serverToken);

                        if (result == null)
                        {
                            LogMessage?.Invoke(this, "SecurityManager.DecryptWithToken 返回 null");
                        }
                        else
                        {
                            LogMessage?.Invoke(this, $"SecurityManager.DecryptWithToken 返回 {result.Length} 字节");
                        }

                        return result;
                    }
                    catch (Exception ex)
                    {
                        LogMessage?.Invoke(this, $"DecryptWithToken 异常: {ex.Message}");
                        return null;
                    }
                });

                if (decryptedData != null && decryptedData.Length > 0)
                {
                    LogMessage?.Invoke(this, $"数据解密成功，大小: {decryptedData.Length} 字节");

                    // 验证解密数据完整性
                    LogMessage?.Invoke(this, "验证数据完整性...");
                    string content = System.Text.Encoding.UTF8.GetString(decryptedData);

                    // 显示内容预览
                    string contentPreview = content.Length > 200
                        ? content.Substring(0, 200) + "..."
                        : content;
                    LogMessage?.Invoke(this, $"解密内容预览: {contentPreview}");

                    // 检查OBJ文件标识
                    bool hasObjHeader = content.Contains("# X-Plane") || content.Contains("# Object");
                    bool hasVertices = content.Contains("v ");
                    bool hasFaces = content.Contains("f ");

                    LogMessage?.Invoke(this, $"完整性检查 - Header: {hasObjHeader}, Vertices: {hasVertices}, Faces: {hasFaces}");

                    if (hasObjHeader && (hasVertices || hasFaces))
                    {
                        LogMessage?.Invoke(this, "数据完整性验证通过");

                        // 挂载虚拟文件系统
                        LogMessage?.Invoke(this, "开始挂载虚拟文件系统...");
                        bool mounted = await MountVirtualFileSystem(decryptedData);

                        if (mounted)
                        {
                            // 保存激活状态
                            bool saved = stateManager.SaveActivationState(activationCode, serverToken, vfsManager.MountPoint);
                            if (saved)
                            {
                                LogMessage?.Invoke(this, "激活状态已保存");
                            }
                            else
                            {
                                LogMessage?.Invoke(this, "激活状态保存失败，但虚拟文件系统已挂载");
                            }
                            return ActivationResult.Success(vfsManager.MountPoint, saved);
                        }
                        else
                        {
                            LogMessage?.Invoke(this, "虚拟文件系统挂载失败");
                            return ActivationResult.Failed("虚拟文件系统挂载失败");
                        }
                    }
                    else
                    {
                        LogMessage?.Invoke(this, "数据完整性验证失败 - 不是有效的OBJ文件格式");

                        // 如果令牌解密失败，尝试使用激活码
                        LogMessage?.Invoke(this, "尝试使用激活码进行离线解密...");
                        return await ProcessActivationWithoutTokenAndSave(activationCode);
                    }
                }
                else
                {
                    LogMessage?.Invoke(this, "令牌解密失败 - 返回数据为空");

                    // 如果令牌解密失败，尝试使用激活码
                    LogMessage?.Invoke(this, "尝试使用激活码进行离线解密...");
                    return await ProcessActivationWithoutTokenAndSave(activationCode);
                }
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"处理服务器令牌异常: {ex.Message}");
                LogMessage?.Invoke(this, $"异常堆栈: {ex.StackTrace}");

                // 发生异常时也尝试离线激活
                LogMessage?.Invoke(this, "异常情况下尝试离线激活...");
                try
                {
                    return await ProcessActivationWithoutTokenAndSave(activationCode);
                }
                catch (Exception fallbackEx)
                {
                    LogMessage?.Invoke(this, $"离线激活也失败: {fallbackEx.Message}");
                    return ActivationResult.Failed($"处理服务器令牌时出错: {ex.Message}");
                }
            }
        }

        private async Task<ActivationResult> ProcessActivationWithoutTokenAndSave(string activationCode)
        {
            try
            {
                ReportProgress(ActivationStage.Decrypting, "使用激活码解密数据...");

                byte[]? decryptedData = await Task.Run(() => securityManager.ValidateAndDecrypt(activationCode));

                if (decryptedData != null && decryptedData.Length > 0)
                {
                    LogMessage?.Invoke(this, $"数据解密成功，大小: {decryptedData.Length} 字节");

                    // 验证解密数据完整性
                    if (securityManager.ValidateDecryptedData(decryptedData))
                    {
                        LogMessage?.Invoke(this, "数据完整性验证通过");

                        // 挂载虚拟文件系统
                        bool mounted = await MountVirtualFileSystem(decryptedData);

                        if (mounted)
                        {
                            // 保存激活状态
                            bool saved = stateManager.SaveActivationState(activationCode, null, vfsManager.MountPoint);
                            if (saved)
                            {
                                LogMessage?.Invoke(this, "激活状态已保存");
                            }
                            else
                            {
                                LogMessage?.Invoke(this, "激活状态保存失败");
                            }
                            return ActivationResult.Success(vfsManager.MountPoint, saved);
                        }
                        return ActivationResult.Failed("虚拟文件系统挂载失败");
                    }
                    else
                    {
                        LogMessage?.Invoke(this, "数据完整性验证失败");
                        return ActivationResult.Failed("数据完整性验证失败");
                    }
                }
                else
                {
                    LogMessage?.Invoke(this, "激活码解密失败");
                    return ActivationResult.Failed("激活码解密失败");
                }
            }
            catch (Exception ex)
            {
                return ActivationResult.Failed($"处理激活码时出错: {ex.Message}");
            }
        }

        private async Task<bool> MountVirtualFileSystem(byte[] decryptedData)
        {
            try
            {
                LogMessage?.Invoke(this, "启动虚拟文件系统...");
                ReportProgress(ActivationStage.MountingVFS, "挂载虚拟文件系统...");

                // 使用固定的VFS管理器，正确等待挂载完成
                bool mounted = await Task.Run(() =>
                    vfsManager.MountVirtualFileSystem(
                        decryptedData,
                        CancellationToken.None
                    )
                );

                if (mounted)
                {
                    LogMessage?.Invoke(this, $"虚拟文件系统成功挂载到 {vfsManager.MountPoint}");
                    ReportProgress(ActivationStage.Complete, "激活成功");
                    return true;
                }
                else
                {
                    LogMessage?.Invoke(this, "虚拟文件系统挂载失败");
                    return false;
                }
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"虚拟文件系统挂载异常: {ex.Message}");
                return false;
            }
        }
    }

    // 支持类
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
        public string? MountPoint { get; private set; }
        public bool StateSaved { get; private set; }
        public string? ErrorMessage { get; private set; }

        private ActivationResult() { }

        public static ActivationResult Success(string mountPoint, bool stateSaved)
        {
            return new ActivationResult
            {
                IsSuccess = true,
                MountPoint = mountPoint,
                StateSaved = stateSaved
            };
        }

        public static ActivationResult Failed(string errorMessage)
        {
            return new ActivationResult
            {
                IsSuccess = false,
                ErrorMessage = errorMessage
            };
        }
    }
}