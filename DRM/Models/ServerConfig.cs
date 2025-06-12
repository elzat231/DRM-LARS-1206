using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace XPlaneActivator
{
    /// <summary>
    /// 服务器配置管理类
    /// </summary>
    public static class ServerConfig
    {
        // =====================================================
        // 基础服务器配置
        // =====================================================

        /// <summary>
        /// 主服务器地址
        /// </summary>
        public const string BASE_URL = "https://lars-store.kz";

        /// <summary>
        /// 备用服务器地址列表（如果有多个可用服务器）
        /// </summary>
        public static readonly string[] BACKUP_URLS = {
            // 目前只有主服务器，如果有备用服务器可以在这里添加
            // "https://backup.lars-store.kz",
            // "https://mirror.lars-store.kz"
        };

        // =====================================================
        // API 端点配置
        // =====================================================

        /// <summary>
        /// 激活验证端点
        /// </summary>
        public const string ACTIVATION_ENDPOINT = "/api/products/api/drm/activate";

        /// <summary>
        /// 状态检查端点
        /// </summary>
        public const string STATUS_ENDPOINT = "/api/drm/status";

        /// <summary>
        /// 心跳检测端点
        /// </summary>
        public const string HEARTBEAT_ENDPOINT = "/api/drm/heartbeat";

        /// <summary>
        /// 许可证验证端点
        /// </summary>
        public const string LICENSE_ENDPOINT = "/api/drm/license";

        // =====================================================
        // 请求配置
        // =====================================================

        /// <summary>
        /// 请求超时时间（秒）
        /// </summary>
        public const int REQUEST_TIMEOUT_SECONDS = 30;

        /// <summary>
        /// 重试次数
        /// </summary>
        public const int MAX_RETRY_COUNT = 3;

        /// <summary>
        /// 重试间隔（毫秒）
        /// </summary>
        public const int RETRY_DELAY_MS = 2000;

        // =====================================================
        // 客户端信息
        // =====================================================

        /// <summary>
        /// 客户端版本
        /// </summary>
        public const string CLIENT_VERSION = "2.0.0";

        /// <summary>
        /// 用户代理字符串
        /// </summary>
        public const string USER_AGENT = "XPlane-DRM-Activator/2.0.0";

        /// <summary>
        /// API 版本
        /// </summary>
        public const string API_VERSION = "v1";

        // =====================================================
        // 安全配置
        // =====================================================

        /// <summary>
        /// 是否验证SSL证书
        /// </summary>
        public const bool VERIFY_SSL_CERTIFICATE = true;

        /// <summary>
        /// 是否启用请求签名
        /// </summary>
        public const bool ENABLE_REQUEST_SIGNING = true;

        /// <summary>
        /// API密钥（如果您的API需要）
        /// 注意：在生产环境中，这应该从安全的配置文件或环境变量中读取
        /// </summary>
        public const string API_KEY = ""; // 您需要在lars-store.kz获取API密钥

        // =====================================================
        // 动态配置方法
        // =====================================================

        /// <summary>
        /// 获取完整的API URL
        /// </summary>
        /// <param name="endpoint">API端点</param>
        /// <param name="baseUrl">基础URL，如果为空则使用默认主服务器</param>
        /// <returns>完整URL</returns>
        public static string GetApiUrl(string endpoint, string? baseUrl = null)
        {
            string serverUrl = baseUrl ?? BASE_URL;
            return $"{serverUrl.TrimEnd('/')}{endpoint}";
        }

        /// <summary>
        /// 获取所有可用的服务器URL（主服务器 + 备用服务器）
        /// </summary>
        /// <returns>服务器URL列表</returns>
        public static string[] GetAllServerUrls()
        {
            var urls = new List<string> { BASE_URL };
            urls.AddRange(BACKUP_URLS);
            return urls.ToArray();
        }

        /// <summary>
        /// 获取带版本的API URL
        /// </summary>
        /// <param name="endpoint">API端点</param>
        /// <param name="baseUrl">基础URL</param>
        /// <returns>带版本的完整URL</returns>
        public static string GetVersionedApiUrl(string endpoint, string? baseUrl = null)
        {
            string serverUrl = baseUrl ?? BASE_URL;
            return $"{serverUrl.TrimEnd('/')}/api/{API_VERSION}{endpoint}";
        }

        /// <summary>
        /// 获取默认请求头
        /// </summary>
        /// <returns>请求头字典</returns>
        public static Dictionary<string, string> GetDefaultHeaders()
        {
            var headers = new Dictionary<string, string>
            {
                ["User-Agent"] = USER_AGENT,
                ["Accept"] = "application/json",
                ["Content-Type"] = "application/json",
                ["X-Client-Version"] = CLIENT_VERSION,
                ["X-API-Version"] = API_VERSION
            };

            // 如果设置了API密钥，添加到请求头
            if (!string.IsNullOrEmpty(API_KEY))
            {
                headers["X-API-Key"] = API_KEY;
                // 或者使用 Authorization header
                // headers["Authorization"] = $"Bearer {API_KEY}";
            }

            return headers;
        }

        /// <summary>
        /// 创建激活请求数据
        /// </summary>
        /// <param name="activationCode">激活码</param>
        /// <param name="machineFingerprint">机器指纹</param>
        /// <returns>请求数据对象</returns>
        public static object CreateActivationRequest(string activationCode, string machineFingerprint)
        {
            return new
            {
                activation_code = activationCode,
                machine_fingerprint = machineFingerprint,
                client_version = CLIENT_VERSION,
                api_version = API_VERSION,
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                request_id = Guid.NewGuid().ToString(),
                platform = "windows",
                architecture = Environment.Is64BitProcess ? "x64" : "x86",
                os_version = Environment.OSVersion.ToString(),
                // 您可以根据lars-store.kz的API要求添加更多字段
                product = "xplane-drm",
                request_type = "activation"
            };
        }

        /// <summary>
        /// 创建状态检查请求数据
        /// </summary>
        /// <param name="machineFingerprint">机器指纹</param>
        /// <param name="activationToken">激活令牌（如果有）</param>
        /// <returns>请求数据对象</returns>
        public static object CreateStatusRequest(string machineFingerprint, string? activationToken = null)
        {
            var requestData = new
            {
                machine_fingerprint = machineFingerprint,
                client_version = CLIENT_VERSION,
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                request_type = "status_check"
            };

            // 如果有激活令牌，添加到请求中
            if (!string.IsNullOrEmpty(activationToken))
            {
                return new
                {
                    requestData.machine_fingerprint,
                    requestData.client_version,
                    requestData.timestamp,
                    requestData.request_type,
                    activation_token = activationToken
                };
            }

            return requestData;
        }

        /// <summary>
        /// 验证服务器响应格式
        /// </summary>
        /// <param name="response">服务器响应JSON</param>
        /// <returns>是否为有效响应</returns>
        public static bool IsValidResponse(string response)
        {
            if (string.IsNullOrEmpty(response))
                return false;

            try
            {
                var json = System.Text.Json.JsonDocument.Parse(response);
                var root = json.RootElement;

                // 检查必要的字段
                return root.TryGetProperty("success", out _) ||
                       root.TryGetProperty("status", out _) ||
                       root.TryGetProperty("error", out _) ||
                       root.TryGetProperty("token", out _);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 检查响应是否表示成功
        /// </summary>
        /// <param name="response">服务器响应JSON</param>
        /// <returns>是否成功</returns>
        public static bool IsSuccessResponse(string response)
        {
            try
            {
                var json = System.Text.Json.JsonDocument.Parse(response);
                var root = json.RootElement;

                // 检查success字段
                if (root.TryGetProperty("success", out var successProp) && successProp.GetBoolean())
                {
                    return true;
                }

                // 检查status字段
                if (root.TryGetProperty("status", out var statusProp))
                {
                    string status = statusProp.GetString() ?? "";
                    return status.Equals("success", StringComparison.OrdinalIgnoreCase) ||
                           status.Equals("activated", StringComparison.OrdinalIgnoreCase);
                }

                // 检查是否有token字段（通常表示成功）
                if (root.TryGetProperty("token", out var tokenProp) && !string.IsNullOrEmpty(tokenProp.GetString()))
                {
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 从响应中提取错误信息
        /// </summary>
        /// <param name="response">服务器响应JSON</param>
        /// <returns>错误信息</returns>
        public static string ExtractErrorMessage(string response)
        {
            try
            {
                var json = System.Text.Json.JsonDocument.Parse(response);
                var root = json.RootElement;

                if (root.TryGetProperty("error", out var errorProp))
                {
                    return errorProp.GetString() ?? "Unknown error";
                }

                if (root.TryGetProperty("message", out var messageProp))
                {
                    return messageProp.GetString() ?? "Unknown error";
                }

                return "Server returned an error";
            }
            catch
            {
                return "Failed to parse error response";
            }
        }

        /// <summary>
        /// 从响应中提取令牌
        /// </summary>
        /// <param name="response">服务器响应JSON</param>
        /// <returns>令牌字符串，如果没有找到返回null</returns>
        public static string? ExtractToken(string response)
        {
            try
            {
                var json = System.Text.Json.JsonDocument.Parse(response);
                var root = json.RootElement;

                // 尝试多种可能的令牌字段名
                string[] tokenFields = { "token", "activation_token", "access_token", "jwt_token" };

                foreach (string fieldName in tokenFields)
                {
                    if (root.TryGetProperty(fieldName, out var tokenProp))
                    {
                        string? token = tokenProp.GetString();
                        if (!string.IsNullOrEmpty(token))
                        {
                            return token;
                        }
                    }
                }

                // 检查嵌套的data字段
                if (root.TryGetProperty("data", out var dataProp))
                {
                    foreach (string fieldName in tokenFields)
                    {
                        if (dataProp.TryGetProperty(fieldName, out var dataTokenProp))
                        {
                            string? token = dataTokenProp.GetString();
                            if (!string.IsNullOrEmpty(token))
                            {
                                return token;
                            }
                        }
                    }
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 检查服务器是否在线
        /// </summary>
        /// <param name="serverUrl">服务器URL</param>
        /// <returns>是否在线</returns>
        public static async Task<bool> IsServerOnlineAsync(string serverUrl)
        {
            try
            {
                using var httpClient = new System.Net.Http.HttpClient();
                httpClient.Timeout = TimeSpan.FromSeconds(10);

                using var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Head, serverUrl);
                using var response = await httpClient.SendAsync(request);

                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 获取服务器状态信息
        /// </summary>
        /// <param name="serverUrl">服务器URL</param>
        /// <returns>服务器状态信息</returns>
        public static async Task<ServerStatus> GetServerStatusAsync(string serverUrl)
        {
            var status = new ServerStatus
            {
                ServerUrl = serverUrl,
                CheckTime = DateTime.Now
            };

            try
            {
                var startTime = DateTime.Now;
                status.IsOnline = await IsServerOnlineAsync(serverUrl);
                status.ResponseTime = (DateTime.Now - startTime).TotalMilliseconds;

                if (status.IsOnline)
                {
                    status.StatusMessage = "服务器在线";
                }
                else
                {
                    status.StatusMessage = "服务器离线或无响应";
                }
            }
            catch (Exception ex)
            {
                status.IsOnline = false;
                status.StatusMessage = $"检查失败: {ex.Message}";
                status.ResponseTime = -1;
            }

            return status;
        }

        /// <summary>
        /// 生成请求ID
        /// </summary>
        /// <returns>唯一的请求ID</returns>
        public static string GenerateRequestId()
        {
            return $"req_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}_{Guid.NewGuid().ToString("N")[..8]}";
        }

        /// <summary>
        /// 验证API密钥格式
        /// </summary>
        /// <param name="apiKey">API密钥</param>
        /// <returns>是否为有效格式</returns>
        public static bool IsValidApiKey(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                return false;

            // 简单的API密钥格式验证
            return apiKey.Length >= 16 && apiKey.Length <= 128;
        }
    }

    /// <summary>
    /// 服务器状态信息
    /// </summary>
    public class ServerStatus
    {
        public string ServerUrl { get; set; } = string.Empty;
        public bool IsOnline { get; set; }
        public double ResponseTime { get; set; } // 毫秒
        public string StatusMessage { get; set; } = string.Empty;
        public DateTime CheckTime { get; set; }

        public override string ToString()
        {
            string responseTimeText = ResponseTime >= 0 ? $"{ResponseTime:F0}ms" : "N/A";
            return $"{ServerUrl}: {(IsOnline ? "在线" : "离线")} ({responseTimeText})";
        }
    }
}