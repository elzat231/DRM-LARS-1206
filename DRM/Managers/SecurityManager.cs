using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace XPlaneActivator
{
    public class SecurityThreatInfo
    {
        public bool DllAvailable { get; set; }
        public bool ThreatsDetected { get; set; }
        public int ThreatCount { get; set; }
        public bool XPlaneRunning { get; set; }
        public int XPlaneProcessCount { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class SecurityManager : IDisposable
    {
        private bool disposed = false;

        // P/Invoke 声明（简化版本，避免命名冲突）
        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int TestFunctionality();

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int DecryptWithToken(string token, byte[] outputBuffer, int bufferSize);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ValidateActivationCode(string activationCode, int codeLength);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int DecryptWithActivationCode(string activationCode, byte[] outputBuffer, int bufferSize);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int GetLastErrorCode();

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int GetLastErrorMessage(StringBuilder errorBuffer, int bufferSize);

        [DllImport("CryptoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void SecureMemoryCleanup();

        /// <summary>
        /// 使用服务器令牌解密（调试版本）
        /// </summary>
        public byte[]? DecryptWithToken(string serverToken)
        {
            System.Diagnostics.Debug.WriteLine($"[SecurityManager] === DecryptWithToken START ===");
            System.Diagnostics.Debug.WriteLine($"[SecurityManager] Token length: {serverToken?.Length ?? 0}");

            if (string.IsNullOrEmpty(serverToken))
            {
                System.Diagnostics.Debug.WriteLine("[SecurityManager] Token is null or empty - RETURNING NULL");
                return null;
            }

            try
            {
                // 强制使用C#回退进行测试
                System.Diagnostics.Debug.WriteLine("[SecurityManager] === FORCING C# FALLBACK FOR TESTING ===");
                var result = GenerateTestObjData("Server Token: " + serverToken.Substring(0, Math.Min(20, serverToken.Length)));

                if (result != null && result.Length > 0)
                {
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] C# fallback successful: {result.Length} bytes");

                    // 显示生成的内容预览
                    string preview = Encoding.UTF8.GetString(result, 0, Math.Min(200, result.Length));
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] Generated content preview: {preview}");

                    return result;
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine("[SecurityManager] C# fallback returned null/empty");
                    return null;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Exception in DecryptWithToken: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Stack trace: {ex.StackTrace}");
                return null;
            }
            finally
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] === DecryptWithToken END ===");
            }
        }

        /// <summary>
        /// 验证和解密激活码（调试版本）
        /// </summary>
        public byte[]? ValidateAndDecrypt(string activationCode)
        {
            System.Diagnostics.Debug.WriteLine($"[SecurityManager] === ValidateAndDecrypt START ===");
            System.Diagnostics.Debug.WriteLine($"[SecurityManager] Activation code: {activationCode}");

            if (string.IsNullOrEmpty(activationCode))
            {
                System.Diagnostics.Debug.WriteLine("[SecurityManager] Activation code is null or empty - RETURNING NULL");
                return null;
            }

            try
            {
                // 强制使用C#回退进行测试
                System.Diagnostics.Debug.WriteLine("[SecurityManager] === FORCING C# FALLBACK FOR ACTIVATION CODE ===");
                var result = GenerateTestObjData("Activation Code: " + activationCode);

                if (result != null && result.Length > 0)
                {
                    System.Diagnostics.Debug.WriteLine($"[SecurityManager] Activation code C# fallback successful: {result.Length} bytes");
                    return result;
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine("[SecurityManager] Activation code C# fallback returned null/empty");
                    return null;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Exception in ValidateAndDecrypt: {ex.Message}");
                return null;
            }
            finally
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] === ValidateAndDecrypt END ===");
            }
        }

        /// <summary>
        /// 生成测试OBJ数据
        /// </summary>
        private byte[] GenerateTestObjData(string source)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Generating test OBJ data for: {source}");

                var content = new StringBuilder();
                content.AppendLine("# X-Plane Object File");
                content.AppendLine("# Generated by SecurityManager Debug Version");
                content.AppendLine($"# Source: {source}");
                content.AppendLine($"# Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                content.AppendLine($"# Token Hash: {CalculateSimpleHash(source)}");
                content.AppendLine();

                // 添加基本几何数据
                content.AppendLine("# Vertices");
                content.AppendLine("v -1.0 -1.0 -1.0");
                content.AppendLine("v 1.0 -1.0 -1.0");
                content.AppendLine("v 1.0 1.0 -1.0");
                content.AppendLine("v -1.0 1.0 -1.0");
                content.AppendLine("v -1.0 -1.0 1.0");
                content.AppendLine("v 1.0 -1.0 1.0");
                content.AppendLine("v 1.0 1.0 1.0");
                content.AppendLine("v -1.0 1.0 1.0");

                content.AppendLine();
                content.AppendLine("# Texture coordinates");
                content.AppendLine("vt 0.0 0.0");
                content.AppendLine("vt 1.0 0.0");
                content.AppendLine("vt 1.0 1.0");
                content.AppendLine("vt 0.0 1.0");

                content.AppendLine();
                content.AppendLine("# Faces");
                content.AppendLine("f 1/1 2/2 3/3 4/4");
                content.AppendLine("f 5/1 8/4 7/3 6/2");
                content.AppendLine("f 1/1 5/2 6/3 2/4");
                content.AppendLine("f 3/1 7/2 8/3 4/4");

                byte[] result = Encoding.UTF8.GetBytes(content.ToString());
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Generated {result.Length} bytes of OBJ data");

                return result;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Exception generating test data: {ex.Message}");
                return new byte[0];
            }
        }

        /// <summary>
        /// 计算简单哈希
        /// </summary>
        private string CalculateSimpleHash(string input)
        {
            try
            {
                using (var md5 = MD5.Create())
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                    byte[] hashBytes = md5.ComputeHash(inputBytes);
                    return Convert.ToHexString(hashBytes).ToLower().Substring(0, 16);
                }
            }
            catch
            {
                return input.GetHashCode().ToString("x8");
            }
        }

        /// <summary>
        /// 检查DLL是否可用
        /// </summary>
        public bool IsCryptoDllAvailable()
        {
            try
            {
                // 暂时返回false，强制使用C#回退
                System.Diagnostics.Debug.WriteLine("[SecurityManager] IsCryptoDllAvailable: Forcing FALSE for testing");
                return false;

                /*
                int result = TestFunctionality();
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] DLL test result: {result}");
                return result == 1;
                */
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] DLL test exception: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 验证解密数据完整性
        /// </summary>
        public bool ValidateDecryptedData(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                System.Diagnostics.Debug.WriteLine("[SecurityManager] ValidateDecryptedData: data is null or empty");
                return false;
            }

            try
            {
                string content = Encoding.UTF8.GetString(data);
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Validating data, length: {data.Length}");

                // 检查OBJ文件基本格式
                bool hasObjHeader = content.Contains("# X-Plane") || content.Contains("# Object");
                bool hasVertices = content.Contains("v ");
                bool hasFaces = content.Contains("f ");

                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Validation - Header: {hasObjHeader}, Vertices: {hasVertices}, Faces: {hasFaces}");

                bool isValid = hasObjHeader && (hasVertices || hasFaces);
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Data validation result: {isValid}");

                return isValid;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SecurityManager] Data validation exception: {ex.Message}");
                return false;
            }
        }

        // 其他必需的方法（简化实现）
        public bool TestCryptoDll() => IsCryptoDllAvailable();
        public bool ValidateProcessSecurity() => true;
        public string GetDecryptionMethod() => "C# Debug Fallback";
        public void PerformSecureCleanup() { }
        public string CalculateDataHash(byte[] data) => "";
        public SecurityThreatInfo CheckSecurityThreats() => new SecurityThreatInfo();

        public void Dispose()
        {
            if (!disposed)
            {
                PerformSecureCleanup();
                disposed = true;
                System.Diagnostics.Debug.WriteLine("[SecurityManager] Disposed");
            }
        }
    }
}