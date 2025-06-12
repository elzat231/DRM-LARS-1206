using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XPlaneActivator
{
    public class NetworkManager : IDisposable
    {
        private readonly HttpClient httpClient;
        private bool disposed = false;
        private string lastError = string.Empty;
        private bool isDllAvailable = false;

        // =====================================================
        // P/Invoke declarations - strictly match function signatures in header file
        // =====================================================

        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int TestNetworkConnection([MarshalAs(UnmanagedType.LPStr)] string serverUrl);

        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int GetNetworkLatency([MarshalAs(UnmanagedType.LPStr)] string serverUrl);

        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int CheckInternetConnection();

        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int CreateSecureActivationRequest(
            [MarshalAs(UnmanagedType.LPStr)] string activationCode,
            [MarshalAs(UnmanagedType.LPStr)] string machineFingerprint,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder requestBuffer,
            int bufferSize);

        // Send POST request - match header file signature
        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int SendSecurePostRequest(
            [MarshalAs(UnmanagedType.LPStr)] string url,
            [MarshalAs(UnmanagedType.LPStr)] string postData,
            int postDataLength,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder responseBuffer,
            int bufferSize);

        // Validate response format - match header file
        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ValidateResponseFormat(
            [MarshalAs(UnmanagedType.LPStr)] string response,
            int responseLength);

        // Note: Use actual function name declared in header file
        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ValidateServerResponseSignature(
            [MarshalAs(UnmanagedType.LPStr)] string response,
            int responseLength);

        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ExtractResponseStatusCode(
            [MarshalAs(UnmanagedType.LPStr)] string response,
            int responseLength);

        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ExtractJsonField(
            [MarshalAs(UnmanagedType.LPStr)] string response,
            [MarshalAs(UnmanagedType.LPStr)] string fieldName,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder valueBuffer,
            int bufferSize);

        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int GetLastNetworkError(
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder errorBuffer,
            int bufferSize);

        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int GetLastNetworkErrorCode();

        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int InitializeNetworkModule([MarshalAs(UnmanagedType.LPStr)] string userAgent);

        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void CleanupNetworkModule();

        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int GetNetworkModuleVersion(
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder versionBuffer,
            int bufferSize);

        // Optional advanced features (if implemented)
        [DllImport("network.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int SetRequestTimeout(int timeoutSeconds);

        public NetworkManager()
        {
            // First try to initialize network.dll
            isDllAvailable = InitializeNetworkDll();

            // Initialize HttpClient as fallback regardless of DLL availability
            httpClient = new HttpClient();

            // Set HTTP client properties
            httpClient.Timeout = TimeSpan.FromSeconds(ServerConfig.REQUEST_TIMEOUT_SECONDS);

            // Set default request headers
            var defaultHeaders = ServerConfig.GetDefaultHeaders();
            foreach (var header in defaultHeaders)
            {
                if (header.Key != "Content-Type")
                {
                    httpClient.DefaultRequestHeaders.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            // Set security protocols
            System.Net.ServicePointManager.SecurityProtocol =
                System.Net.SecurityProtocolType.Tls12 | System.Net.SecurityProtocolType.Tls13;

            System.Diagnostics.Debug.WriteLine($"[NetworkManager] Initialization complete, DLL available: {isDllAvailable}");
        }

        /// <summary>
        /// Initialize network.dll
        /// </summary>
        private bool InitializeNetworkDll()
        {
            try
            {
                // Try to call DLL initialization function
                int result = InitializeNetworkModule("XPlane-DRM-Activator/2.0.0");

                if (result == 1)
                {
                    // Set timeout
                    try
                    {
                        SetRequestTimeout(ServerConfig.REQUEST_TIMEOUT_SECONDS);
                    }
                    catch
                    {
                        // Ignore error if SetRequestTimeout is not implemented
                    }

                    // Get DLL version info to verify successful loading
                    var versionBuffer = new StringBuilder(64);
                    int versionLength = GetNetworkModuleVersion(versionBuffer, versionBuffer.Capacity);

                    if (versionLength > 0)
                    {
                        string version = versionBuffer.ToString();
                        System.Diagnostics.Debug.WriteLine($"[NetworkManager] network.dll version: {version}");
                        return true;
                    }
                }

                return false;
            }
            catch (DllNotFoundException)
            {
                System.Diagnostics.Debug.WriteLine("[NetworkManager] network.dll not found");
                return false;
            }
            catch (EntryPointNotFoundException ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NetworkManager] DLL function entry point not found: {ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NetworkManager] DLL initialization exception: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Send POST request to specified API endpoint
        /// </summary>
        public async Task<string> HttpPostAsync(string requestData, string endpoint, string baseUrl)
        {
            // If DLL is available, use DLL implementation first
            if (isDllAvailable)
            {
                return await HttpPostAsyncWithDll(requestData, endpoint, baseUrl);
            }

            // Fallback: Use C# HttpClient implementation
            return await HttpPostAsyncWithHttpClient(requestData, endpoint, baseUrl);
        }

        /// <summary>
        /// Send POST request using network.dll
        /// </summary>
        private async Task<string> HttpPostAsyncWithDll(string requestData, string endpoint, string baseUrl)
        {
            try
            {
                var url = baseUrl.TrimEnd('/') + endpoint;

                System.Diagnostics.Debug.WriteLine($"[NetworkManager] Sending request using network.dll to: {url}");

                // First test connection
                int connectionTest = TestNetworkConnection(baseUrl);

                if (connectionTest != 1)
                {
                    string dllError = GetDllLastError();
                    System.Diagnostics.Debug.WriteLine($"[NetworkManager] DLL connection test failed: {dllError}");
                    // Fall back to HttpClient when connection test fails
                    throw new Exception("DLL connection test failed, using fallback method");
                }

                // Send POST request using DLL
                var responseBuffer = new StringBuilder(10240); // 10KB buffer
                int responseLength = await Task.Run(() =>
                    SendSecurePostRequest(url, requestData, requestData.Length, responseBuffer, responseBuffer.Capacity)
                );

                if (responseLength > 0)
                {
                    string response = responseBuffer.ToString();
                    System.Diagnostics.Debug.WriteLine($"[NetworkManager] DLL POST request successful, response length: {responseLength}");

                    // Validate response format
                    int validationResult = ValidateResponseFormat(response, response.Length);
                    if (validationResult == 1)
                    {
                        System.Diagnostics.Debug.WriteLine("[NetworkManager] DLL response format validation passed");
                        return response;
                    }
                    else
                    {
                        System.Diagnostics.Debug.WriteLine("[NetworkManager] DLL response format validation failed, but returning response anyway");
                        return response; // Return response even if validation fails, let upper layer handle it
                    }
                }
                else
                {
                    string dllError = GetDllLastError();
                    throw new Exception($"DLL POST request failed: {dllError}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NetworkManager] DLL POST exception, falling back to HttpClient: {ex.Message}");
                // Fall back to HttpClient when DLL fails
                return await HttpPostAsyncWithHttpClient(requestData, endpoint, baseUrl);
            }
        }

        /// <summary>
        /// Send POST request using HttpClient (fallback method)
        /// </summary>
        private async Task<string> HttpPostAsyncWithHttpClient(string requestData, string endpoint, string baseUrl)
        {
            try
            {
                var url = baseUrl.TrimEnd('/') + endpoint;
                var content = new StringContent(requestData, Encoding.UTF8, "application/json");

                System.Diagnostics.Debug.WriteLine($"[NetworkManager] Sending request using C# HttpClient to: {url}");

                using var response = await httpClient.PostAsync(url, content);

                // Read response content regardless of status code
                string responseText = await response.Content.ReadAsStringAsync();

                System.Diagnostics.Debug.WriteLine($"[NetworkManager] Response status code: {response.StatusCode}");
                System.Diagnostics.Debug.WriteLine($"[NetworkManager] Response content: {responseText}");

                // Check if there's a valid JSON response
                if (!string.IsNullOrEmpty(responseText))
                {
                    try
                    {
                        // Try to parse JSON to validate format
                        var jsonDoc = System.Text.Json.JsonDocument.Parse(responseText);
                        var root = jsonDoc.RootElement;

                        // Check if it contains fields for successful response
                        if (root.TryGetProperty("success", out var successProp) ||
                            root.TryGetProperty("status", out var statusProp) ||
                            root.TryGetProperty("token", out var tokenProp))
                        {
                            System.Diagnostics.Debug.WriteLine("[NetworkManager] Response contains valid activation data, ignoring HTTP status code");
                            return responseText;
                        }
                    }
                    catch (System.Text.Json.JsonException)
                    {
                        // JSON parsing failed, might not be a valid response
                        System.Diagnostics.Debug.WriteLine("[NetworkManager] Response is not valid JSON format");
                    }
                }

                // If no valid JSON response, check HTTP status code
                if (!response.IsSuccessStatusCode)
                {
                    lastError = $"HTTP {(int)response.StatusCode} {response.StatusCode}: {responseText}";
                    throw new HttpRequestException($"Network request failed: HTTP {(int)response.StatusCode} {response.StatusCode}");
                }

                return responseText;
            }
            catch (HttpRequestException ex)
            {
                lastError = $"HTTP request exception: {ex.Message}";
                throw new HttpRequestException($"Network request failed: {ex.Message}", ex);
            }
            catch (TaskCanceledException ex)
            {
                lastError = "Request timeout";
                throw new TimeoutException("Network request timeout", ex);
            }
            catch (Exception ex)
            {
                lastError = $"Network exception: {ex.Message}";
                throw;
            }
        }

        /// <summary>
        /// Test connection to server
        /// </summary>
        public async Task<bool> TestServerConnectionAsync(string serverUrl)
        {
            // If DLL is available, use DLL first
            if (isDllAvailable)
            {
                try
                {
                    int result = await Task.Run(() => TestNetworkConnection(serverUrl));
                    System.Diagnostics.Debug.WriteLine($"[NetworkManager] DLL connection test {serverUrl}: {(result == 1 ? "success" : "failed")}");
                    return result == 1;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[NetworkManager] DLL connection test exception: {ex.Message}");
                    // If DLL test fails, fall back to HttpClient
                }
            }

            // Fallback: Use HttpClient
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Head, serverUrl);
                using var response = await httpClient.SendAsync(request);
                bool success = response.IsSuccessStatusCode;
                System.Diagnostics.Debug.WriteLine($"[NetworkManager] HttpClient connection test {serverUrl}: {(success ? "success" : "failed")}");
                return success;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Check if network DLL is available
        /// </summary>
        public bool IsNetworkDllAvailable()
        {
            return isDllAvailable;
        }

        /// <summary>
        /// Get network latency (if DLL is available)
        /// </summary>
        public async Task<int> GetNetworkLatencyAsync(string serverUrl)
        {
            if (isDllAvailable)
            {
                try
                {
                    int latency = await Task.Run(() => GetNetworkLatency(serverUrl));
                    System.Diagnostics.Debug.WriteLine($"[NetworkManager] Network latency {serverUrl}: {latency}ms");
                    return latency;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[NetworkManager] Get latency exception: {ex.Message}");
                    return -1;
                }
            }

            return -1; // Return -1 when DLL is not available
        }

        /// <summary>
        /// Create secure activation request using DLL
        /// </summary>
        public string CreateTestRequestDataWithDll(string activationCode)
        {
            if (isDllAvailable)
            {
                try
                {
                    string machineFingerprint = HardwareIdHelper.GetMachineFingerprint();
                    var requestBuffer = new StringBuilder(4096);

                    int length = CreateSecureActivationRequest(activationCode, machineFingerprint, requestBuffer, requestBuffer.Capacity);

                    if (length > 0)
                    {
                        string request = requestBuffer.ToString();
                        System.Diagnostics.Debug.WriteLine($"[NetworkManager] DLL request creation successful: {length} bytes");
                        return request;
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[NetworkManager] DLL request creation exception: {ex.Message}");
                }
            }

            // Fallback: Use C# implementation
            return CreateFallbackRequestData(activationCode);
        }

        /// <summary>
        /// Create test request data
        /// </summary>
        public string CreateTestRequestData(string activationCode)
        {
            // If DLL is available, use DLL first
            if (isDllAvailable)
            {
                string dllRequest = CreateTestRequestDataWithDll(activationCode);
                if (!string.IsNullOrEmpty(dllRequest))
                {
                    return dllRequest;
                }
            }

            // Fallback: C# implementation
            return CreateFallbackRequestData(activationCode);
        }

        /// <summary>
        /// Fallback method to create request data
        /// </summary>
        private string CreateFallbackRequestData(string activationCode)
        {
            var requestData = new
            {
                activation_code = activationCode,
                machine_fingerprint = HardwareIdHelper.GetMachineFingerprint(),
                client_version = "2.0.0",
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                request_id = Guid.NewGuid().ToString(),
                method = isDllAvailable ? "dll_fallback" : "csharp_only"
            };

            return System.Text.Json.JsonSerializer.Serialize(requestData);
        }

        /// <summary>
        /// Validate server response
        /// </summary>
        public async Task<bool> ValidateServerResponseAsync(string serverUrl, string requestData)
        {
            try
            {
                var response = await HttpPostAsync(requestData, "/api/validate", serverUrl);

                // If DLL is available, use DLL to validate response
                if (isDllAvailable)
                {
                    try
                    {
                        // Use actual function name declared in header file
                        int validationResult = ValidateServerResponseSignature(response, response.Length);
                        System.Diagnostics.Debug.WriteLine($"[NetworkManager] DLL response signature validation: {(validationResult == 1 ? "valid" : "invalid")}");

                        if (validationResult == 1)
                        {
                            return true;
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NetworkManager] DLL validation exception: {ex.Message}");
                    }
                }

                // Fallback validation: check response format
                return !string.IsNullOrEmpty(response) &&
                       (response.Contains("success") || response.Contains("token"));
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Perform complete network validation workflow
        /// </summary>
        public async Task<NetworkValidationResult> PerformFullValidationAsync(string activationCode, string serverUrl)
        {
            var result = new NetworkValidationResult
            {
                StartTime = DateTime.Now
            };

            try
            {
                // 1. Test connection
                result.ConnectionTest = await TestServerConnectionAsync(serverUrl);

                if (result.ConnectionTest)
                {
                    // 2. Create request data
                    string requestData = CreateTestRequestData(activationCode);

                    // 3. Send request and validate response
                    result.ValidationPassed = await ValidateServerResponseAsync(serverUrl, requestData);
                }

                result.EndTime = DateTime.Now;
                result.Duration = result.EndTime - result.StartTime;
                result.Success = result.ConnectionTest; // Modified: consider overall success if connection succeeds
            }
            catch (Exception ex)
            {
                result.EndTime = DateTime.Now;
                result.Duration = result.EndTime - result.StartTime;
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// Get last error information from DLL
        /// </summary>
        private string GetDllLastError()
        {
            if (!isDllAvailable) return "DLL not available";

            try
            {
                var errorBuffer = new StringBuilder(512);
                int length = GetLastNetworkError(errorBuffer, errorBuffer.Capacity);

                if (length > 0)
                {
                    return errorBuffer.ToString();
                }

                int errorCode = GetLastNetworkErrorCode();
                return $"Error code: {errorCode}";
            }
            catch (Exception ex)
            {
                return $"Failed to get DLL error info: {ex.Message}";
            }
        }

        /// <summary>
        /// Get last error information
        /// </summary>
        public string GetLastError()
        {
            if (isDllAvailable)
            {
                string dllError = GetDllLastError();
                if (!string.IsNullOrEmpty(dllError) && dllError != "No error")
                {
                    return $"DLL: {dllError}";
                }
            }

            return string.IsNullOrEmpty(lastError) ? "No error" : lastError;
        }

        /// <summary>
        /// Clear error information
        /// </summary>
        public void ClearLastError()
        {
            lastError = string.Empty;
        }

        /// <summary>
        /// Get network module information
        /// </summary>
        public string GetNetworkModuleInfo()
        {
            if (isDllAvailable)
            {
                try
                {
                    var versionBuffer = new StringBuilder(64);
                    int versionLength = GetNetworkModuleVersion(versionBuffer, versionBuffer.Capacity);

                    if (versionLength > 0)
                    {
                        string version = versionBuffer.ToString();
                        return $"network.dll v{version}";
                    }

                    return "network.dll (version unknown)";
                }
                catch (Exception ex)
                {
                    return $"network.dll (error: {ex.Message})";
                }
            }

            return "C# HttpClient";
        }

        public void Dispose()
        {
            if (!disposed)
            {
                // Clean up DLL resources
                if (isDllAvailable)
                {
                    try
                    {
                        CleanupNetworkModule();
                        System.Diagnostics.Debug.WriteLine("[NetworkManager] network.dll cleaned up");
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NetworkManager] DLL cleanup exception: {ex.Message}");
                    }
                }

                // Clean up HttpClient
                httpClient?.Dispose();
                disposed = true;

                System.Diagnostics.Debug.WriteLine("[NetworkManager] Disposed");
            }
        }
    }

    /// <summary>
    /// Network validation result
    /// </summary>
    public class NetworkValidationResult
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public bool Success { get; set; }
        public bool ConnectionTest { get; set; }
        public bool ValidationPassed { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
    }
}