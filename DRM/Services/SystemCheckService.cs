// =====================================================
// 文件2: Services/SystemCheckService.cs
// =====================================================
using System;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace XPlaneActivator.Services
{
    public interface ISystemCheckService
    {
        Task<SystemCheckResult> PerformSystemCheckAsync();
        Task<DokanCheckResult> CheckDokanInstallationAsync();
        bool IsRunningAsAdministrator();
        string GetSystemInfo();
    }

    public class SystemCheckService : ISystemCheckService
    {
        private readonly SecurityManager securityManager;

        public SystemCheckService(SecurityManager securityManager)
        {
            this.securityManager = securityManager;
        }

        public async Task<SystemCheckResult> PerformSystemCheckAsync()
        {
            var result = new SystemCheckResult();

            await Task.Run(() =>
            {
                // 管理员权限检查
                result.IsAdmin = IsRunningAsAdministrator();

                // Dokan驱动检查
                result.DokanCheck = CheckDokanInstallation();

                // 加密引擎检查
                result.CryptoEngineAvailable = securityManager.IsCryptoDllAvailable();
                result.CryptoEngineTest = securityManager.TestCryptoDll();

                // 硬件环境检查
                result.HardwareCheck = HardwareIdHelper.CheckHardwareEnvironment();

                // 计算总体状态
                result.OverallStatus = CalculateOverallStatus(result);
            });

            return result;
        }

        public async Task<DokanCheckResult> CheckDokanInstallationAsync()
        {
            return await Task.Run(() => CheckDokanInstallation());
        }

        public bool IsRunningAsAdministrator()
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

        public string GetSystemInfo()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"操作系统: {Environment.OSVersion}");
            sb.AppendLine($"机器名: {Environment.MachineName}");
            sb.AppendLine($"用户名: {Environment.UserName}");
            sb.AppendLine($"64位系统: {Environment.Is64BitOperatingSystem}");
            sb.AppendLine($"64位进程: {Environment.Is64BitProcess}");
            sb.AppendLine($".NET版本: {Environment.Version}");
            return sb.ToString();
        }

        private DokanCheckResult CheckDokanInstallation()
        {
            var result = new DokanCheckResult();

            try
            {
                // 检查注册表
                bool registryCheck1 = false;
                try
                {
                    using var key1 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Dokan\DokanLibrary");
                    registryCheck1 = key1 != null;
                }
                catch { }

                bool registryCheck2 = false;
                try
                {
                    using var key2 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Dokan\DokanLibrary");
                    registryCheck2 = key2 != null;
                }
                catch { }

                result.RegistryFound = registryCheck1 || registryCheck2;

                // 检查系统文件
                string[] dokanPaths = {
                    @"C:\Windows\System32\drivers\dokan2.sys",
                    @"C:\Windows\System32\drivers\dokan1.sys",
                    @"C:\Windows\System32\dokan2.dll",
                    @"C:\Windows\System32\dokan1.dll",
                    @"C:\Windows\SysWOW64\dokan2.dll",
                    @"C:\Windows\SysWOW64\dokan1.dll"
                };

                foreach (string path in dokanPaths)
                {
                    if (File.Exists(path))
                    {
                        result.FilesFound = true;
                        result.DetectedFiles.Add(path);
                    }
                }

                // 检查服务
                try
                {
                    var services = ServiceController.GetServices();
                    result.ServiceFound = services.Any(s =>
                        s.ServiceName.ToLower().Contains("dokan") ||
                        s.DisplayName.ToLower().Contains("dokan"));
                }
                catch { }

                // 检查DokanNet.dll
                string dokanNetPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "DokanNet.dll");
                result.DokanNetFound = File.Exists(dokanNetPath);

                // 设置整体状态
                if (result.DokanNetFound && (result.RegistryFound || result.FilesFound || result.ServiceFound))
                {
                    result.IsInstalled = true;
                    result.Status = DokanStatus.FullyInstalled;
                    result.Message = "Dokan驱动完全安装";
                }
                else if (result.DokanNetFound)
                {
                    result.IsInstalled = true;
                    result.Status = DokanStatus.DokanNetOnly;
                    result.Message = "找到DokanNet但驱动可能缺失";
                }
                else if (result.RegistryFound || result.FilesFound || result.ServiceFound)
                {
                    result.IsInstalled = false;
                    result.Status = DokanStatus.PartialInstallation;
                    result.Message = "Dokan部分安装";
                }
                else
                {
                    result.IsInstalled = false;
                    result.Status = DokanStatus.NotInstalled;
                    result.Message = "Dokan驱动未安装";
                }

                // 添加详细信息
                var details = new System.Collections.Generic.List<string>();
                if (result.RegistryFound) details.Add("注册表: 找到");
                if (result.FilesFound) details.Add($"文件: 找到 ({result.DetectedFiles.Count})");
                if (result.ServiceFound) details.Add("服务: 找到");
                if (result.DokanNetFound) details.Add("DokanNet.dll: 找到");

                if (details.Any())
                {
                    result.Details = string.Join(", ", details);
                }
                else
                {
                    result.Details = "未检测到Dokan组件";
                }

                return result;
            }
            catch (Exception ex)
            {
                result.IsInstalled = false;
                result.Status = DokanStatus.CheckError;
                result.Message = $"检查Dokan安装时出错: {ex.Message}";
                result.Details = ex.Message;
                return result;
            }
        }

        private SystemStatus CalculateOverallStatus(SystemCheckResult result)
        {
            int score = 0;

            if (result.IsAdmin) score += 25;
            if (result.DokanCheck.IsInstalled) score += 30;
            if (result.CryptoEngineAvailable) score += 20;
            if (result.CryptoEngineTest) score += 15;
            if (result.HardwareCheck.IsReliable) score += 10;

            return score switch
            {
                >= 90 => SystemStatus.Excellent,
                >= 70 => SystemStatus.Good,
                >= 50 => SystemStatus.NeedsAttention,
                _ => SystemStatus.HasIssues
            };
        }
    }

    // 支持类
    public enum SystemStatus
    {
        Excellent,
        Good,
        NeedsAttention,
        HasIssues
    }

    public enum DokanStatus
    {
        NotInstalled,
        PartialInstallation,
        DokanNetOnly,
        FullyInstalled,
        CheckError
    }

    public class SystemCheckResult
    {
        public bool IsAdmin { get; set; }
        public DokanCheckResult DokanCheck { get; set; } = new DokanCheckResult();
        public bool CryptoEngineAvailable { get; set; }
        public bool CryptoEngineTest { get; set; }
        public HardwareEnvironmentCheck HardwareCheck { get; set; } = new HardwareEnvironmentCheck();
        public SystemStatus OverallStatus { get; set; }
    }

    public class DokanCheckResult
    {
        public bool IsInstalled { get; set; }
        public DokanStatus Status { get; set; }
        public string Message { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public bool RegistryFound { get; set; }
        public bool FilesFound { get; set; }
        public bool ServiceFound { get; set; }
        public bool DokanNetFound { get; set; }
        public System.Collections.Generic.List<string> DetectedFiles { get; set; } = new System.Collections.Generic.List<string>();
    }
}
