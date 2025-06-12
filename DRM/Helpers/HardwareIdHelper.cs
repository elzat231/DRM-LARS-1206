using System;
using System.Linq;
using System.Management; // Need to add reference to System.Management
using System.Security.Cryptography;
using System.Text;

namespace XPlaneActivator
{
    public static class HardwareIdHelper
    {
        /// <summary>
        /// Generate a unique machine code based on multiple hardware identifiers.
        /// </summary>
        /// <returns>Machine code string.</returns>
        public static string GetMachineFingerprint()
        {
            try
            {
                StringBuilder sb = new StringBuilder();

                // 1. Get CPU ID
                sb.Append(GetHardwareInfo("Win32_Processor", "ProcessorId"));

                // 2. Get motherboard serial number
                sb.Append(GetHardwareInfo("Win32_BaseBoard", "SerialNumber"));

                // 3. Get BIOS serial number
                sb.Append(GetHardwareInfo("Win32_BIOS", "SerialNumber"));

                // 4. Get hard disk serial number (select first physical disk)
                sb.Append(GetHardwareInfo("Win32_DiskDrive", "SerialNumber"));

                // 5. Get MAC address of first active network adapter
                sb.Append(GetMacAddress());

                // Hash the combined string to generate a fixed-length fingerprint
                return CalculateMd5Hash(sb.ToString());
            }
            catch (Exception ex)
            {
                // If error occurs, log and return a default or empty fingerprint, allowing program to continue
                // but may affect activation stability. In actual application, more robust error handling may be needed
                System.Diagnostics.Debug.WriteLine($"[HardwareIdHelper] {R.GetFormatted("MachineCodeGenerationError", ex.Message)}");
                return CalculateMd5Hash(Environment.MachineName + Environment.UserName); // Fallback
            }
        }

        /// <summary>
        /// Get hardware information from WMI for specified class and property.
        /// </summary>
        /// <param name="className">WMI class name (e.g., "Win32_Processor")</param>
        /// <param name="propertyName">WMI property name (e.g., "ProcessorId")</param>
        /// <returns>Retrieved information string, empty string if retrieval fails.</returns>
        private static string GetHardwareInfo(string className, string propertyName)
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher($"SELECT {propertyName} FROM {className}"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj[propertyName] != null)
                        {
                            return obj[propertyName].ToString()?.Trim() ?? string.Empty;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[HardwareIdHelper] Error getting WMI info ({className}.{propertyName}): {ex.Message}");
            }
            return string.Empty;
        }

        /// <summary>
        /// Get MAC address of first active network adapter.
        /// </summary>
        /// <returns>MAC address string, empty string if retrieval fails.</returns>
        private static string GetMacAddress()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["MacAddress"] != null)
                        {
                            return obj["MacAddress"].ToString()?.Replace(":", "") ?? string.Empty;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[HardwareIdHelper] Error getting MAC address: {ex.Message}");
            }
            return string.Empty;
        }

        /// <summary>
        /// Calculate MD5 hash value of given string.
        /// </summary>
        /// <param name="input">String to calculate hash for.</param>
        /// <returns>MD5 hash string.</returns>
        private static string CalculateMd5Hash(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("x2")); // "x2" means hexadecimal format, two digits
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// Get detailed hardware information (for debugging and diagnostics)
        /// </summary>
        /// <returns>Hardware information details</returns>
        public static HardwareInfo GetDetailedHardwareInfo()
        {
            var info = new HardwareInfo();

            try
            {
                info.CpuId = GetHardwareInfo("Win32_Processor", "ProcessorId");
                info.CpuName = GetHardwareInfo("Win32_Processor", "Name");
                info.MotherboardId = GetHardwareInfo("Win32_BaseBoard", "SerialNumber");
                info.MotherboardManufacturer = GetHardwareInfo("Win32_BaseBoard", "Manufacturer");
                info.BiosId = GetHardwareInfo("Win32_BIOS", "SerialNumber");
                info.BiosVersion = GetHardwareInfo("Win32_BIOS", "Version");
                info.MacAddress = GetMacAddress();
                info.MachineName = Environment.MachineName;
                info.UserName = Environment.UserName;
                info.OsVersion = Environment.OSVersion.ToString();

                // Get disk information
                info.DiskSerials = GetAllDiskSerials();

                // Generate final fingerprint
                info.Fingerprint = GetMachineFingerprint();
            }
            catch (Exception ex)
            {
                info.ErrorMessage = ex.Message;
            }

            return info;
        }

        /// <summary>
        /// Get all disk serial numbers
        /// </summary>
        private static string[] GetAllDiskSerials()
        {
            try
            {
                var serials = new System.Collections.Generic.List<string>();

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_DiskDrive"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["SerialNumber"] != null)
                        {
                            string serial = obj["SerialNumber"].ToString()?.Trim();
                            if (!string.IsNullOrEmpty(serial))
                            {
                                serials.Add(serial);
                            }
                        }
                    }
                }

                return serials.ToArray();
            }
            catch
            {
                return new string[0];
            }
        }

        /// <summary>
        /// Verify machine code stability (for testing)
        /// </summary>
        /// <returns>Whether consecutively generated machine codes are consistent</returns>
        public static bool TestFingerprintStability()
        {
            try
            {
                string fingerprint1 = GetMachineFingerprint();
                System.Threading.Thread.Sleep(100); // Brief delay
                string fingerprint2 = GetMachineFingerprint();

                return fingerprint1 == fingerprint2;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Get human-readable version of machine code (first 8 digits + ...)
        /// </summary>
        /// <returns>Truncated machine code</returns>
        public static string GetDisplayFingerprint()
        {
            try
            {
                string fullFingerprint = GetMachineFingerprint();
                if (fullFingerprint.Length >= 8)
                {
                    return fullFingerprint.Substring(0, 8) + "...";
                }
                return fullFingerprint;
            }
            catch
            {
                return "UNKNOWN...";
            }
        }

        /// <summary>
        /// Check if hardware environment is suitable for generating stable machine code
        /// </summary>
        /// <returns>Environment check result</returns>
        public static HardwareEnvironmentCheck CheckHardwareEnvironment()
        {
            var check = new HardwareEnvironmentCheck();

            try
            {
                // Check CPU information
                string cpuId = GetHardwareInfo("Win32_Processor", "ProcessorId");
                check.HasCpuId = !string.IsNullOrEmpty(cpuId);

                // Check motherboard information
                string motherboardId = GetHardwareInfo("Win32_BaseBoard", "SerialNumber");
                check.HasMotherboardId = !string.IsNullOrEmpty(motherboardId);

                // Check BIOS information
                string biosId = GetHardwareInfo("Win32_BIOS", "SerialNumber");
                check.HasBiosId = !string.IsNullOrEmpty(biosId);

                // Check network adapter information
                string macAddress = GetMacAddress();
                check.HasMacAddress = !string.IsNullOrEmpty(macAddress);

                // Check disk information
                string diskSerial = GetHardwareInfo("Win32_DiskDrive", "SerialNumber");
                check.HasDiskSerial = !string.IsNullOrEmpty(diskSerial);

                // Check WMI availability
                check.WmiAvailable = true;

                // Calculate reliability score
                int reliabilityScore = 0;
                if (check.HasCpuId) reliabilityScore += 20;
                if (check.HasMotherboardId) reliabilityScore += 25;
                if (check.HasBiosId) reliabilityScore += 20;
                if (check.HasMacAddress) reliabilityScore += 20;
                if (check.HasDiskSerial) reliabilityScore += 15;

                check.ReliabilityScore = reliabilityScore;
                check.IsReliable = reliabilityScore >= 60; // Need at least 60 points to be considered reliable

                // Generate suggestions
                if (!check.IsReliable)
                {
                    var suggestions = new System.Collections.Generic.List<string>();
                    if (!check.HasCpuId) suggestions.Add("Cannot get CPU ID");
                    if (!check.HasMotherboardId) suggestions.Add("Cannot get motherboard serial number");
                    if (!check.HasBiosId) suggestions.Add("Cannot get BIOS serial number");
                    if (!check.HasMacAddress) suggestions.Add("Cannot get MAC address");
                    if (!check.HasDiskSerial) suggestions.Add("Cannot get disk serial number");

                    check.Suggestions = suggestions.ToArray();
                }
            }
            catch (Exception ex)
            {
                check.WmiAvailable = false;
                check.ErrorMessage = ex.Message;
                check.IsReliable = false;
                check.Suggestions = new[] { "WMI service unavailable, please check system configuration" };
            }

            return check;
        }
    }

    /// <summary>
    /// Hardware information details
    /// </summary>
    public class HardwareInfo
    {
        public string CpuId { get; set; } = string.Empty;
        public string CpuName { get; set; } = string.Empty;
        public string MotherboardId { get; set; } = string.Empty;
        public string MotherboardManufacturer { get; set; } = string.Empty;
        public string BiosId { get; set; } = string.Empty;
        public string BiosVersion { get; set; } = string.Empty;
        public string MacAddress { get; set; } = string.Empty;
        public string[] DiskSerials { get; set; } = new string[0];
        public string MachineName { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string OsVersion { get; set; } = string.Empty;
        public string Fingerprint { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
    }

    /// <summary>
    /// Hardware environment check result
    /// </summary>
    public class HardwareEnvironmentCheck
    {
        public bool HasCpuId { get; set; }
        public bool HasMotherboardId { get; set; }
        public bool HasBiosId { get; set; }
        public bool HasMacAddress { get; set; }
        public bool HasDiskSerial { get; set; }
        public bool WmiAvailable { get; set; }
        public bool IsReliable { get; set; }
        public int ReliabilityScore { get; set; }
        public string[] Suggestions { get; set; } = new string[0];
        public string ErrorMessage { get; set; } = string.Empty;
    }
}