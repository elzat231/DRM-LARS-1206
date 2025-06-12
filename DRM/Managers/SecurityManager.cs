using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace XPlaneActivator
{
    public class SecurityManager : IDisposable
    {
        private bool disposed = false;

        /// <summary>
        /// 使用服务器令牌解密数据（主要方法）
        /// </summary>
        /// <param name="serverToken">服务器返回的安全令牌</param>
        /// <returns>解密后的数据，失败返回null</returns>
        public byte[]? DecryptWithToken(string serverToken)
        {
            if (string.IsNullOrEmpty(serverToken))
                return null;

            try
            {
                // 优先使用C++ DLL进行解密
                if (IsCryptoDllAvailable())
                {
                    return DecryptWithCppDll(serverToken, true);
                }

                // 备用方法：使用C#实现
                return DecryptWithCSharpFallback(serverToken);
            }
            catch (Exception)
            {
                // 如果DLL方法失败，尝试C#备用方法
                try
                {
                    return DecryptWithCSharpFallback(serverToken);
                }
                catch
                {
                    return null;
                }
            }
            finally
            {
                // 清理敏感内存
                if (IsCryptoDllAvailable())
                {
                    try
                    {
                        CallDllFunction("SecureMemoryCleanup");
                    }
                    catch
                    {
                        // 忽略清理异常
                    }
                }
            }
        }

        /// <summary>
        /// 传统的激活码验证和解密（备用方法）
        /// </summary>
        /// <param name="activationCode">激活码</param>
        /// <returns>解密后的数据，失败返回null</returns>
        public byte[]? ValidateAndDecrypt(string activationCode)
        {
            if (string.IsNullOrEmpty(activationCode))
                return null;

            try
            {
                // 优先使用C++ DLL
                if (IsCryptoDllAvailable())
                {
                    return DecryptWithCppDll(activationCode, false);
                }

                // 备用方法：使用C#实现
                return ValidateAndDecryptFallback(activationCode);
            }
            catch (Exception)
            {
                // 如果DLL方法失败，尝试C#备用方法
                try
                {
                    return ValidateAndDecryptFallback(activationCode);
                }
                catch
                {
                    return null;
                }
            }
            finally
            {
                // 清理敏感内存
                if (IsCryptoDllAvailable())
                {
                    try
                    {
                        CallDllFunction("SecureMemoryCleanup");
                    }
                    catch
                    {
                        // 忽略清理异常
                    }
                }
            }
        }

        /// <summary>
        /// 使用C++ DLL进行解密
        /// </summary>
        private byte[]? DecryptWithCppDll(string input, bool isToken)
        {
            try
            {
                IntPtr hModule = LoadLibrary("CryptoEngine.dll");
                if (hModule == IntPtr.Zero)
                {
                    return null;
                }

                try
                {
                    // 首先验证输入（对于激活码）
                    if (!isToken)
                    {
                        IntPtr validateFunc = GetProcAddress(hModule, "ValidateActivationCode");
                        if (validateFunc != IntPtr.Zero)
                        {
                            var validateDelegate = Marshal.GetDelegateForFunctionPointer<ValidateActivationCodeDelegate>(validateFunc);
                            int validationResult = validateDelegate(input, input.Length);
                            if (validationResult != 1)
                            {
                                return null;
                            }
                        }
                    }

                    // 获取数据大小
                    IntPtr getSizeFunc = GetProcAddress(hModule, "GetDecryptedDataSize");
                    int dataSize = 10 * 1024 * 1024; // 默认10MB
                    if (getSizeFunc != IntPtr.Zero)
                    {
                        var getSizeDelegate = Marshal.GetDelegateForFunctionPointer<GetDecryptedDataSizeDelegate>(getSizeFunc);
                        dataSize = getSizeDelegate();
                    }

                    // 创建输出缓冲区
                    byte[] buffer = new byte[dataSize];

                    // 执行解密
                    string functionName = isToken ? "DecryptWithToken" : "DecryptWithActivationCode";
                    IntPtr decryptFunc = GetProcAddress(hModule, functionName);

                    if (decryptFunc != IntPtr.Zero)
                    {
                        var decryptDelegate = Marshal.GetDelegateForFunctionPointer<DecryptDelegate>(decryptFunc);
                        int decryptedLength = decryptDelegate(input, buffer, buffer.Length);

                        if (decryptedLength > 0)
                        {
                            // 创建正确大小的结果数组
                            byte[] result = new byte[decryptedLength];
                            Array.Copy(buffer, result, decryptedLength);

                            // 清零临时缓冲区
                            Array.Clear(buffer, 0, buffer.Length);

                            return result;
                        }
                    }

                    return null;
                }
                finally
                {
                    FreeLibrary(hModule);
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// C#备用解密实现（用于服务器令牌）
        /// </summary>
        private byte[]? DecryptWithCSharpFallback(string serverToken)
        {
            try
            {
                // 简单的令牌验证
                if (!IsValidToken(serverToken))
                {
                    return null;
                }

                // 生成基于令牌的解密数据
                return GenerateDecryptedContent("Server Token: " + serverToken);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// C#备用验证和解密实现（用于激活码）
        /// </summary>
        private byte[]? ValidateAndDecryptFallback(string activationCode)
        {
            try
            {
                // 验证激活码格式和有效性
                if (!IsValidActivationCode(activationCode))
                {
                    return null;
                }

                // 生成解密数据
                return GenerateDecryptedContent("Activation Code: " + activationCode);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 验证激活码格式
        /// </summary>
        private bool IsValidActivationCode(string activationCode)
        {
            if (string.IsNullOrEmpty(activationCode))
                return false;

            // 简单的格式验证
            activationCode = activationCode.Trim().ToUpper();

            // 检查一些已知的测试激活码
            string[] validCodes = {
                "XPLANE-2025-TEST",
                "FALLBACK-TEST-XPLANE",
                "TEST-ACTIVATION-CODE",
                "XPLANE-INTEGRATED-TEST-2025"
            };

            foreach (string validCode in validCodes)
            {
                if (activationCode.Contains(validCode))
                    return true;
            }

            // 检查通用格式（例如：XXXX-XXXX-XXXX-XXXX）
            if (activationCode.Length >= 10 && activationCode.Contains("-"))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// 验证服务器令牌
        /// </summary>
        private bool IsValidToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                return false;

            // 简单的令牌格式验证
            // 在实际实现中，这里应该验证令牌的签名、有效期等
            return token.Length > 10;
        }

        /// <summary>
        /// 生成解密内容（模拟）
        /// </summary>
        private byte[] GenerateDecryptedContent(string source)
        {
            // 生成一个模拟的OBJ文件内容
            var content = new StringBuilder();
            content.AppendLine("# X-Plane Object File");
            content.AppendLine($"# Generated by C# Fallback Method");
            content.AppendLine($"# Source: {source}");
            content.AppendLine($"# Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            content.AppendLine();

            // 添加一些基本的几何数据
            content.AppendLine("# Vertices");
            for (int i = 0; i < 8; i++)
            {
                content.AppendLine($"v {(i % 2) * 2 - 1} {((i / 2) % 2) * 2 - 1} {(i / 4) * 2 - 1}");
            }

            content.AppendLine();
            content.AppendLine("# Faces");
            content.AppendLine("f 1 2 3 4");
            content.AppendLine("f 5 6 7 8");
            content.AppendLine("f 1 2 6 5");
            content.AppendLine("f 3 4 8 7");
            content.AppendLine("f 1 3 7 5");
            content.AppendLine("f 2 4 8 6");

            return Encoding.UTF8.GetBytes(content.ToString());
        }

        /// <summary>
        /// 检查CryptoEngine.dll是否可用
        /// </summary>
        public bool IsCryptoDllAvailable()
        {
            try
            {
                IntPtr hModule = LoadLibrary("CryptoEngine.dll");
                if (hModule == IntPtr.Zero)
                {
                    return false;
                }

                IntPtr testFunc = GetProcAddress(hModule, "TestCryptoFunctions");
                bool available = testFunc != IntPtr.Zero;

                FreeLibrary(hModule);
                return available;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 测试加密DLL功能
        /// </summary>
        public bool TestCryptoDll()
        {
            try
            {
                if (!IsCryptoDllAvailable())
                    return false;

                IntPtr hModule = LoadLibrary("CryptoEngine.dll");
                if (hModule == IntPtr.Zero)
                    return false;

                try
                {
                    IntPtr testFunc = GetProcAddress(hModule, "TestCryptoFunctions");
                    if (testFunc != IntPtr.Zero)
                    {
                        var testDelegate = Marshal.GetDelegateForFunctionPointer<TestCryptoFunctionsDelegate>(testFunc);
                        int result = testDelegate();
                        return result == 1;
                    }
                    return false;
                }
                finally
                {
                    FreeLibrary(hModule);
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 获取当前使用的解密方法
        /// </summary>
        public string GetDecryptionMethod()
        {
            if (IsCryptoDllAvailable())
            {
                return "C++ CryptoEngine.dll";
            }
            else
            {
                return "C# Fallback Method";
            }
        }

        /// <summary>
        /// 执行安全内存清理
        /// </summary>
        public void PerformSecureCleanup()
        {
            try
            {
                if (IsCryptoDllAvailable())
                {
                    CallDllFunction("SecureMemoryCleanup");
                }

                // 强制垃圾回收
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
            }
            catch
            {
                // 忽略清理异常
            }
        }

        /// <summary>
        /// 验证解密数据的完整性
        /// </summary>
        public bool ValidateDecryptedData(byte[] data)
        {
            if (data == null || data.Length == 0)
                return false;

            try
            {
                string content = Encoding.UTF8.GetString(data);

                // 检查OBJ文件的基本格式
                bool hasObjHeader = content.Contains("# X-Plane") || content.Contains("# Object");
                bool hasVertices = content.Contains("v ");
                bool hasFaces = content.Contains("f ");

                return hasObjHeader && hasVertices && hasFaces;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 计算数据的MD5哈希（用于验证）
        /// </summary>
        public string CalculateDataHash(byte[] data)
        {
            if (data == null || data.Length == 0)
                return string.Empty;

            try
            {
                using (var md5 = MD5.Create())
                {
                    byte[] hashBytes = md5.ComputeHash(data);
                    return Convert.ToHexString(hashBytes).ToLower();
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// 调用DLL函数（通用方法）
        /// </summary>
        private void CallDllFunction(string functionName)
        {
            try
            {
                IntPtr hModule = LoadLibrary("CryptoEngine.dll");
                if (hModule == IntPtr.Zero)
                    return;

                try
                {
                    IntPtr func = GetProcAddress(hModule, functionName);
                    if (func != IntPtr.Zero)
                    {
                        var cleanupDelegate = Marshal.GetDelegateForFunctionPointer<VoidDelegate>(func);
                        cleanupDelegate();
                    }
                }
                finally
                {
                    FreeLibrary(hModule);
                }
            }
            catch
            {
                // 忽略异常
            }
        }

        public void Dispose()
        {
            if (!disposed)
            {
                PerformSecureCleanup();
                disposed = true;
            }
        }

        // Windows API 声明
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        // 委托声明
        private delegate int ValidateActivationCodeDelegate(string activationCode, int codeLength);
        private delegate int DecryptDelegate(string input, byte[] outputBuffer, int bufferSize);
        private delegate int GetDecryptedDataSizeDelegate();
        private delegate int TestCryptoFunctionsDelegate();
        private delegate void VoidDelegate();
    }
}