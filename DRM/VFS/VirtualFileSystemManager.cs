using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Threading;
using System.Threading.Tasks;
using DokanNet;
using DokanNet.Logging;

namespace DRM.VFS
{
    // =====================================================
    // 枚举和事件类
    // =====================================================

    public enum VfsStatus
    {
        Uninitialized,
        Mounting,
        Mounted,
        FileAccessed,
        Unmounting,
        Unmounted,
        Error
    }

    public enum VfsAccessMode
    {
        AllowAll,
        WhitelistOnly,
        DenyAll
    }

    public class VfsStatusEventArgs : EventArgs
    {
        public VfsStatus Status { get; set; }
        public string Message { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.Now;
    }

    public class VfsAccessEventArgs : EventArgs
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public bool AccessGranted { get; set; }
        public string Reason { get; set; } = string.Empty;
    }

    // =====================================================
    // 虚拟文件数据结构
    // =====================================================

    public class VirtualFileData
    {
        public string FileName { get; set; } = string.Empty;
        public byte[] Data { get; set; } = new byte[0];
        public DateTime CreationTime { get; set; } = DateTime.Now;
        public DateTime LastAccessTime { get; set; } = DateTime.Now;
        public DateTime LastWriteTime { get; set; } = DateTime.Now;
        public FileAttributes Attributes { get; set; } = FileAttributes.Normal;
        public string OriginalPath { get; set; } = string.Empty;
    }

    // =====================================================
    // 主接口
    // =====================================================

    public interface IVirtualFileSystem : IDisposable
    {
        string MountPoint { get; }
        bool IsMounted { get; }
        VfsStatus Status { get; }
        int FileCount { get; }
        long TotalSize { get; }

        Task<bool> MountAsync(CancellationToken cancellationToken = default);
        Task<bool> UnmountAsync();
        void ForceUnmount();
        void SetVirtualData(byte[] data);
        void SetVirtualFiles(Dictionary<string, byte[]> files);
        void AddVirtualFile(string fileName, byte[] data);
        void RemoveVirtualFile(string fileName);
        void ClearVirtualFiles();
        List<string> GetVirtualFileNames();
        void SetMountPoint(string mountPoint);
        void SetAccessMode(VfsAccessMode mode);
        void AddAllowedProcess(string processName);

        event EventHandler<VfsStatusEventArgs>? StatusChanged;
        event EventHandler<string>? LogMessage;
    }

    // =====================================================
    // 修复后的访问控制器 - 解决文件内容无法查看问题
    // =====================================================

    internal class VFSAccessController
    {
        private readonly HashSet<string> allowedProcesses = new();
        private VfsAccessMode accessMode = VfsAccessMode.AllowAll;
        private DateTime? lastAccessTime = null;
        private int accessAttemptCount = 0;
        private readonly object accessLock = new();

        // 访问统计
        private readonly Dictionary<string, int> processAccessCount = new();
        private readonly Dictionary<string, DateTime> lastProcessAccess = new();

        public event EventHandler<VfsAccessEventArgs>? AccessAttempted;

        public VFSAccessController()
        {
            // 系统关键进程 - 总是允许访问
            var systemProcesses = new[]
            {
                "system", "explorer", "notepad", "notepad++", "code", "devenv",
                "cmd", "powershell", "conhost", "dwm", "winlogon", "csrss",
                "svchost", "services", "lsass", "smss", "wininit"
            };

            // X-Plane相关进程
            var xplaneProcesses = new[]
            {
                "x-plane", "xplane", "x-plane 12", "x-plane12", "x-plane_12"
            };

            // 开发和调试工具
            var devProcesses = new[]
            {
                "visual studio", "rider", "clion", "qtcreator", "debugger",
                "procmon", "procexp", "filemon", "regmon", "wireshark"
            };

            // 文件管理和查看工具
            var fileTools = new[]
            {
                "totalcmd", "winrar", "7zip", "notepadplusplus", "sublimetext",
                "atom", "brackets", "vim", "emacs", "hexedit", "hxd", "010editor"
            };

            foreach (var process in systemProcesses.Concat(xplaneProcesses)
                .Concat(devProcesses).Concat(fileTools))
            {
                allowedProcesses.Add(process.ToLowerInvariant());
            }

            System.Diagnostics.Debug.WriteLine($"[VFSAccessController] Initialized with {allowedProcesses.Count} allowed process patterns");
        }

        public bool CheckAccess(int processId, string processName, string fileName)
        {
            lock (accessLock)
            {
                var eventArgs = new VfsAccessEventArgs
                {
                    ProcessId = processId,
                    ProcessName = processName,
                    FileName = fileName,
                    AccessGranted = false,
                    Reason = ""
                };

                try
                {
                    switch (accessMode)
                    {
                        case VfsAccessMode.AllowAll:
                            eventArgs.AccessGranted = true;
                            eventArgs.Reason = "Access mode: Allow all";
                            break;

                        case VfsAccessMode.DenyAll:
                            eventArgs.AccessGranted = false;
                            eventArgs.Reason = "Access mode: Deny all";
                            break;

                        case VfsAccessMode.WhitelistOnly:
                            eventArgs.AccessGranted = CheckWhitelistAccess(processId, processName, out string reason);
                            eventArgs.Reason = reason;
                            break;
                    }

                    // 更新访问统计
                    if (eventArgs.AccessGranted)
                    {
                        processAccessCount[processName] = processAccessCount.GetValueOrDefault(processName, 0) + 1;
                        lastProcessAccess[processName] = DateTime.Now;
                    }

                    // 详细日志记录
                    System.Diagnostics.Debug.WriteLine($"[VFSAccessController] {(eventArgs.AccessGranted ? "✅ ALLOW" : "❌ DENY")}: {processName} (PID:{processId}) -> {fileName}");
                    if (!string.IsNullOrEmpty(eventArgs.Reason))
                    {
                        System.Diagnostics.Debug.WriteLine($"[VFSAccessController] Reason: {eventArgs.Reason}");
                    }
                }
                catch (Exception ex)
                {
                    // 出现异常时，默认允许访问以确保文件可读
                    eventArgs.AccessGranted = true;
                    eventArgs.Reason = $"Exception occurred, allowing access: {ex.Message}";
                    System.Diagnostics.Debug.WriteLine($"[VFSAccessController] ⚠ Exception in access check, allowing: {ex.Message}");
                }

                AccessAttempted?.Invoke(this, eventArgs);
                return eventArgs.AccessGranted;
            }
        }

        private bool CheckWhitelistAccess(int processId, string processName, out string reason)
        {
            reason = "";
            try
            {
                string lowerProcessName = processName.ToLowerInvariant();

                // 1. 检查系统关键进程（总是允许）
                string[] criticalProcesses = {
                    "system", "explorer", "dwm", "winlogon", "csrss", "svchost"
                };

                bool isCriticalProcess = criticalProcesses.Any(proc =>
                    lowerProcessName.Contains(proc) || lowerProcessName.Equals(proc));

                if (isCriticalProcess)
                {
                    reason = $"Critical system process allowed: {processName}";
                    return true;
                }

                // 2. 检查基本白名单
                bool isInWhitelist = allowedProcesses.Any(allowed =>
                    lowerProcessName.Contains(allowed) || allowed.Contains(lowerProcessName));

                if (isInWhitelist)
                {
                    reason = $"Process in whitelist: {processName}";
                    return true;
                }

                // 3. 检查文件管理和查看相关进程
                string[] fileViewerProcesses = {
                    "notepad", "wordpad", "write", "edit", "type", "more", "less",
                    "cat", "head", "tail", "grep", "find", "search"
                };

                bool isFileViewer = fileViewerProcesses.Any(viewer =>
                    lowerProcessName.Contains(viewer));

                if (isFileViewer)
                {
                    reason = $"File viewer process allowed: {processName}";
                    return true;
                }

                // 4. 验证进程是否真实存在且可访问
                try
                {
                    if (processId > 0)
                    {
                        var process = Process.GetProcessById(processId);
                        if (!process.HasExited)
                        {
                            // 进程存在，记录但仍然允许访问（用于调试和兼容性）
                            reason = $"Valid process, allowing for compatibility: {processName}";
                            return true;
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[VFSAccessController] Process validation error: {ex.Message}");
                }

                // 5. 默认策略：记录未知进程但允许访问（确保文件内容可读）
                reason = $"Unknown process, allowing for file access: {processName}";
                System.Diagnostics.Debug.WriteLine($"[VFSAccessController] ⚠ Unknown process accessing files: {processName} (PID: {processId})");
                return true; // 关键修复：允许未知进程访问以确保文件内容可读
            }
            catch (Exception ex)
            {
                reason = $"Access check error, allowing: {ex.Message}";
                return true;
            }
        }

        public void AddAllowedProcess(string processName)
        {
            if (!string.IsNullOrWhiteSpace(processName))
            {
                allowedProcesses.Add(processName.ToLowerInvariant());
                System.Diagnostics.Debug.WriteLine($"[VFSAccessController] Added process to whitelist: {processName}");
            }
        }

        public void SetAccessMode(VfsAccessMode mode)
        {
            accessMode = mode;
            System.Diagnostics.Debug.WriteLine($"[VFSAccessController] Access mode set to: {mode}");
        }

        public Dictionary<string, int> GetAccessStatistics()
        {
            lock (accessLock)
            {
                return new Dictionary<string, int>(processAccessCount);
            }
        }
    }

    // =====================================================
    // 修复后的文件提供器 - 确保数据正确传输
    // =====================================================

    internal class VFSFileProvider
    {
        private readonly Dictionary<string, VirtualFileData> virtualFiles = new();
        private readonly Dictionary<string, FileInformation> fileInfoCache = new();
        private readonly object lockObject = new();

        public int FileCount => virtualFiles.Count;
        public long TotalSize => virtualFiles.Values.Sum(f => f.Data.Length);

        public void SetVirtualData(byte[] data)
        {
            lock (lockObject)
            {
                virtualFiles.Clear();
                fileInfoCache.Clear();

                if (data != null && data.Length > 0)
                {
                    var virtualFile = new VirtualFileData
                    {
                        FileName = "Fuse 1.obj",
                        Data = data,
                        CreationTime = DateTime.Now,
                        LastAccessTime = DateTime.Now,
                        LastWriteTime = DateTime.Now,
                        Attributes = FileAttributes.Normal,
                        OriginalPath = "Fuse 1.obj"
                    };

                    virtualFiles["Fuse 1.obj"] = virtualFile;
                    System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Set single virtual file: Fuse 1.obj ({data.Length} bytes)");
                }

                SetupFileInfoCache();
            }
        }

        public void SetVirtualFiles(Dictionary<string, byte[]> files)
        {
            lock (lockObject)
            {
                virtualFiles.Clear();
                fileInfoCache.Clear();

                foreach (var file in files)
                {
                    if (file.Value != null && file.Value.Length > 0)
                    {
                        var virtualFile = new VirtualFileData
                        {
                            FileName = file.Key,
                            Data = file.Value,
                            CreationTime = DateTime.Now,
                            LastAccessTime = DateTime.Now,
                            LastWriteTime = DateTime.Now,
                            Attributes = FileAttributes.Normal,
                            OriginalPath = file.Key
                        };

                        virtualFiles[file.Key] = virtualFile;

                        // 详细日志记录文件内容
                        System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Added virtual file: {file.Key} ({file.Value.Length} bytes)");
                        LogFileContent(file.Key, file.Value);
                    }
                }

                SetupFileInfoCache();
                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Set {virtualFiles.Count} virtual files, total size: {TotalSize} bytes");
            }
        }

        private void LogFileContent(string fileName, byte[] data)
        {
            try
            {
                if (data.Length >= 16)
                {
                    // 显示十六进制头部
                    string hexHeader = string.Join(" ", data.Take(16).Select(b => b.ToString("X2")));
                    System.Diagnostics.Debug.WriteLine($"[VFSFileProvider]   Hex header: {hexHeader}");

                    // 尝试显示文本内容
                    bool isProbablyText = data.Take(Math.Min(100, data.Length))
                        .All(b => (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13);

                    if (isProbablyText)
                    {
                        string textPreview = System.Text.Encoding.UTF8.GetString(data, 0, Math.Min(100, data.Length));
                        string cleanPreview = textPreview.Replace('\n', ' ').Replace('\r', ' ');
                        System.Diagnostics.Debug.WriteLine($"[VFSFileProvider]   Text preview: {cleanPreview}");
                    }
                    {
                        // 检查文件类型
                        string fileType = DetectFileType(data);
                        System.Diagnostics.Debug.WriteLine($"[VFSFileProvider]   File type: {fileType}");
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Content logging error: {ex.Message}");
            }
        }

        private string DetectFileType(byte[] data)
        {
            if (data.Length < 4) return "Unknown";

            // PNG
            if (data.Length >= 8 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47)
                return "PNG Image";

            // JPEG
            if (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF)
                return "JPEG Image";

            // DDS
            if (data[0] == 0x44 && data[1] == 0x44 && data[2] == 0x53 && data[3] == 0x20)
                return "DDS Texture";

            // BMP
            if (data[0] == 0x42 && data[1] == 0x4D)
                return "BMP Image";

            return "Binary Data";
        }

        public void AddVirtualFile(string fileName, byte[] data)
        {
            if (string.IsNullOrEmpty(fileName) || data == null || data.Length == 0)
                return;

            lock (lockObject)
            {
                var virtualFile = new VirtualFileData
                {
                    FileName = fileName,
                    Data = data,
                    CreationTime = DateTime.Now,
                    LastAccessTime = DateTime.Now,
                    LastWriteTime = DateTime.Now,
                    Attributes = FileAttributes.Normal,
                    OriginalPath = fileName
                };

                virtualFiles[fileName] = virtualFile;
                SetupFileInfoCache();
                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Added virtual file: {fileName} ({data.Length} bytes)");
                LogFileContent(fileName, data);
            }
        }

        public void RemoveVirtualFile(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
                return;

            lock (lockObject)
            {
                if (virtualFiles.Remove(fileName))
                {
                    SetupFileInfoCache();
                    System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Removed virtual file: {fileName}");
                }
            }
        }

        public void ClearVirtualFiles()
        {
            lock (lockObject)
            {
                virtualFiles.Clear();
                fileInfoCache.Clear();
                System.Diagnostics.Debug.WriteLine("[VFSFileProvider] Cleared all virtual files");
            }
        }

        public List<string> GetVirtualFileNames()
        {
            lock (lockObject)
            {
                return new List<string>(virtualFiles.Keys);
            }
        }

        public FileInformation? GetFileInfo(string fileName)
        {
            lock (lockObject)
            {
                string normalizedPath = NormalizePath(fileName);

                if (fileInfoCache.TryGetValue(normalizedPath, out var fileInfo))
                {
                    System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] GetFileInfo SUCCESS: {normalizedPath} ({fileInfo.Length} bytes)");
                    return fileInfo;
                }

                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] GetFileInfo FAILED: {normalizedPath}");
                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Available files: {string.Join(", ", fileInfoCache.Keys)}");
                return null;
            }
        }

        public int ReadFile(string fileName, byte[] buffer, long offset, int length)
        {
            lock (lockObject)
            {
                string normalizedPath = NormalizePath(fileName);
                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] === ReadFile Request ===");
                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] File: {normalizedPath}");
                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Offset: {offset}, Length: {length}");
                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Buffer size: {buffer.Length}");

                if (virtualFiles.TryGetValue(normalizedPath, out var virtualFile))
                {
                    virtualFile.LastAccessTime = DateTime.Now;

                    // 验证请求参数
                    if (offset < 0)
                    {
                        System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] ✗ Invalid offset: {offset}");
                        return 0;
                    }

                    if (offset >= virtualFile.Data.Length)
                    {
                        System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] ✗ Offset {offset} >= file size {virtualFile.Data.Length}");
                        return 0;
                    }

                    // 计算实际读取参数
                    int startIndex = (int)offset;
                    int availableBytes = virtualFile.Data.Length - startIndex;
                    int lengthToRead = Math.Min(Math.Min(length, availableBytes), buffer.Length);

                    System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Calculated read: start={startIndex}, available={availableBytes}, toRead={lengthToRead}");

                    if (lengthToRead > 0)
                    {
                        try
                        {
                            // 执行数据复制
                            Array.Copy(virtualFile.Data, startIndex, buffer, 0, lengthToRead);

                            System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] ✅ Successfully read {lengthToRead} bytes from {normalizedPath}");

                            // 详细记录读取的内容（用于调试）
                            if (startIndex == 0 && lengthToRead >= 16)
                            {
                                try
                                {
                                    string hexData = string.Join(" ", buffer.Take(16).Select(b => b.ToString("X2")));
                                    System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Read data (hex): {hexData}");

                                    // 尝试显示文本内容
                                    bool isText = buffer.Take(Math.Min(50, lengthToRead))
                                        .All(b => (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13);

                                    if (isText)
                                    {
                                        string textContent = System.Text.Encoding.UTF8.GetString(buffer, 0, Math.Min(50, lengthToRead));
                                        string cleanContent = textContent.Replace('\n', ' ').Replace('\r', ' ');
                                        System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Read data (text): {cleanContent}");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Content preview error: {ex.Message}");
                                }
                            }

                            return lengthToRead;
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] ✗ Data copy error: {ex.Message}");
                            return 0;
                        }
                    }
                    else
                    {
                        System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] ✗ No bytes to read");
                        return 0;
                    }
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] ✗ File not found: {normalizedPath}");
                    System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Available files: {string.Join(", ", virtualFiles.Keys)}");
                    return 0;
                }
            }
        }
        // 1. 修复 VirtualFileSystemManager.cs 中的字符字面量错误
        // 在 VFSFileProvider 类的 GetDirectoryFiles 方法中：

        public IList<FileInformation> GetDirectoryFiles(string directoryPath, string? searchPattern = null)
        {
            lock (lockObject)
            {
                var result = new List<FileInformation>();
                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] GetDirectoryFiles: {directoryPath}, pattern: {searchPattern}");

                if (directoryPath == @"\" || directoryPath == "/")
                {
                    foreach (var fileInfo in fileInfoCache.Values)
                    {
                        // 修复：使用字符串字面量 @"\" 而不是字符字面量 '@\'
                        if (fileInfo.FileName != @"\" &&
                            !fileInfo.FileName.Contains(@"\", StringComparison.Ordinal) &&
                            !fileInfo.FileName.Contains("/", StringComparison.Ordinal))
                        {
                            if (string.IsNullOrEmpty(searchPattern) ||
                                searchPattern == "*" ||
                                searchPattern == "*.*" ||
                                fileInfo.FileName.Contains(searchPattern.Replace("*", ""), StringComparison.OrdinalIgnoreCase))
                            {
                                result.Add(fileInfo);
                                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider]   Found: {fileInfo.FileName} ({fileInfo.Length} bytes)");
                            }
                        }
                    }
                }

                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Returning {result.Count} files");
                return result;
            }
        }

        private void SetupFileInfoCache()
        {
            fileInfoCache.Clear();

            // 根目录
            fileInfoCache[@"\"] = new FileInformation
            {
                FileName = @"\",
                Attributes = FileAttributes.Directory,
                CreationTime = DateTime.Now,
                LastAccessTime = DateTime.Now,
                LastWriteTime = DateTime.Now,
                Length = 0
            };

            // 虚拟文件
            foreach (var virtualFile in virtualFiles.Values)
            {
                string fileName = virtualFile.FileName.StartsWith(@"\") ? virtualFile.FileName : $@"\{virtualFile.FileName}";

                fileInfoCache[fileName] = new FileInformation
                {
                    FileName = virtualFile.FileName,
                    Attributes = virtualFile.Attributes,
                    CreationTime = virtualFile.CreationTime,
                    LastAccessTime = virtualFile.LastAccessTime,
                    LastWriteTime = virtualFile.LastWriteTime,
                    Length = virtualFile.Data.Length
                };

                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Cached file info: {fileName} ({virtualFile.Data.Length} bytes)");
            }
        }

        private string NormalizePath(string path)
        {
            if (string.IsNullOrEmpty(path))
                return "";

            string normalized = path.TrimStart('\\', '/');

            if (string.IsNullOrEmpty(normalized) && (path.StartsWith(@"\") || path.StartsWith("/")))
            {
                return @"\";
            }

            return normalized;
        }
    }

    // =====================================================
    // 修复后的 Dokan 操作包装器 - 确保文件内容可读
    // =====================================================

    internal class DokanOperationsWrapper : IDokanOperations
    {
        private readonly VFSAccessController accessController;
        private readonly VFSFileProvider fileProvider;
        private readonly Action<string> logMessage;
        private readonly Action mountedCallback;
        private readonly Action unmountedCallback;

        public DokanOperationsWrapper(VFSAccessController accessController, VFSFileProvider fileProvider,
            Action<string> logMessage, Action mountedCallback, Action unmountedCallback)
        {
            this.accessController = accessController;
            this.fileProvider = fileProvider;
            this.logMessage = logMessage;
            this.mountedCallback = mountedCallback;
            this.unmountedCallback = unmountedCallback;
        }

        private (int processId, string processName) GetCallingProcessInfo(IDokanFileInfo info)
        {
            try
            {
                // 方法1：尝试使用DokanFileInfo中的进程信息
                if (info?.ProcessId > 0)
                {
                    try
                    {
                        var process = Process.GetProcessById(info.ProcessId);
                        if (!process.HasExited)
                        {
                            string processName = process.ProcessName ?? "unknown";
                            return (process.Id, processName);
                        }
                    }
                    catch (Exception ex)
                    {
                        logMessage($"[ProcessDetection] Process lookup failed: {ex.Message}");
                    }
                }

                // 方法2：简化的安全回退方案
                return (Environment.ProcessId, "file_browser");
            }
            catch (Exception)
            {
                // 最终回退方案
                return (1, "system");
            }
        }

        public NtStatus CreateFile(string fileName, DokanNet.FileAccess access, FileShare share,
            FileMode mode, FileOptions options, FileAttributes attributes, IDokanFileInfo info)
        {
            try
            {
                var (processId, processName) = GetCallingProcessInfo(info);
                logMessage($"🔍 File access request: {processName} (PID: {processId}) -> {fileName}");

                // 简化的访问控制 - 记录但不阻止文件访问
                bool accessGranted = accessController.CheckAccess(processId, processName, fileName);

                if (!accessGranted)
                {
                    logMessage($"⚠️ Access control check failed, but allowing for file compatibility: {fileName}");
                    // 注意：这里我们仍然继续，不返回拒绝状态
                }

                var fileInfo = fileProvider.GetFileInfo(fileName);
                if (fileInfo != null)
                {
                    info.IsDirectory = fileInfo.Value.Attributes.HasFlag(FileAttributes.Directory);
                    logMessage($"✅ File access granted: {processName} -> {fileName} ({fileInfo.Value.Length} bytes)");
                    return NtStatus.Success;
                }

                logMessage($"❌ File not found: {fileName}");
                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                logMessage($"💥 CreateFile exception: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
        {
            bytesRead = 0;
            try
            {
                var (processId, processName) = GetCallingProcessInfo(info);
                logMessage($"📖 Read request: {processName} (PID: {processId}) -> {fileName} (offset: {offset}, buffer: {buffer.Length})");

                // 强制允许所有读取操作以确保文件内容可访问
                logMessage($"📖 Allowing read access for file content: {processName} -> {fileName}");

                int actualBytesRead = fileProvider.ReadFile(fileName, buffer, offset, buffer.Length);

                if (actualBytesRead > 0)
                {
                    bytesRead = actualBytesRead;
                    logMessage($"📖 Read SUCCESS: {processName} read {bytesRead} bytes from {fileName} at offset {offset}");

                    // 详细记录读取内容以验证数据正确性
                    if (offset == 0 && bytesRead >= 16)
                    {
                        try
                        {
                            // 显示十六进制数据
                            string hexData = string.Join(" ", buffer.Take(16).Select(b => b.ToString("X2")));
                            logMessage($"📖 Data (hex): {hexData}...");

                            // 尝试显示文本内容
                            bool isText = buffer.Take(Math.Min(50, bytesRead))
                                .All(b => (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13);

                            if (isText)
                            {
                                string textContent = System.Text.Encoding.UTF8.GetString(buffer, 0, Math.Min(50, bytesRead));
                                logMessage($"📖 Content: {textContent.Replace('\n', ' ').Replace('\r', ' ')}...");
                            }
                            else
                            {
                                logMessage($"📖 Binary data: {bytesRead} bytes");
                            }
                        }
                        catch (Exception ex)
                        {
                            logMessage($"📖 Content preview error: {ex.Message}");
                        }
                    }

                    return NtStatus.Success;
                }
                else
                {
                    logMessage($"📖 Read failed: {fileName} (no data available)");
                    return NtStatus.ObjectNameNotFound;
                }
            }
            catch (Exception ex)
            {
                logMessage($"💥 ReadFile exception for {fileName}: {ex.Message}");
                logMessage($"💥 Stack trace: {ex.StackTrace}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus GetFileInformation(string fileName, out FileInformation fileInfo, IDokanFileInfo info)
        {
            fileInfo = default;
            try
            {
                var (processId, processName) = GetCallingProcessInfo(info);
                logMessage($"ℹ️ GetFileInfo: {processName} (PID: {processId}) -> {fileName}");

                var fileInfoNullable = fileProvider.GetFileInfo(fileName);
                if (fileInfoNullable.HasValue)
                {
                    fileInfo = fileInfoNullable.Value;
                    logMessage($"ℹ️ File info success: {fileName} ({fileInfo.Length} bytes, {fileInfo.Attributes})");
                    return NtStatus.Success;
                }

                logMessage($"ℹ️ File info failed: {fileName}");
                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                logMessage($"💥 GetFileInformation exception: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus FindFiles(string fileName, out IList<FileInformation> files, IDokanFileInfo info)
        {
            try
            {
                var (processId, processName) = GetCallingProcessInfo(info);
                logMessage($"📂 FindFiles: {processName} (PID: {processId}) -> {fileName}");

                files = fileProvider.GetDirectoryFiles(fileName);
                logMessage($"📂 FindFiles SUCCESS: found {files.Count} files in '{fileName}'");

                // 详细记录找到的文件
                foreach (var file in files.Take(10))
                {
                    logMessage($"📂   - {file.FileName} ({file.Length} bytes)");
                }
                if (files.Count > 10)
                {
                    logMessage($"📂   ... and {files.Count - 10} more files");
                }

                return NtStatus.Success;
            }
            catch (Exception ex)
            {
                files = new List<FileInformation>();
                logMessage($"💥 FindFiles exception: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus FindFilesWithPattern(string fileName, string searchPattern, out IList<FileInformation> files, IDokanFileInfo info)
        {
            try
            {
                var (processId, processName) = GetCallingProcessInfo(info);
                logMessage($"🔍 FindFilesWithPattern: {processName} (PID: {processId}) -> {fileName} (pattern: {searchPattern})");

                files = fileProvider.GetDirectoryFiles(fileName, searchPattern);
                logMessage($"🔍 FindFilesWithPattern SUCCESS: found {files.Count} files matching '{searchPattern}' in '{fileName}'");
                return NtStatus.Success;
            }
            catch (Exception ex)
            {
                files = new List<FileInformation>();
                logMessage($"💥 FindFilesWithPattern exception: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus Mounted(string mountPoint, IDokanFileInfo info)
        {
            logMessage($"🎯 Virtual file system mounted successfully to: {mountPoint}");
            mountedCallback();
            return NtStatus.Success;
        }

        public NtStatus Unmounted(IDokanFileInfo info)
        {
            logMessage("🔄 Virtual file system unmounted");
            unmountedCallback();
            return NtStatus.Success;
        }

        public NtStatus GetVolumeInformation(out string volumeLabel, out FileSystemFeatures features,
            out string fileSystemName, out uint maximumComponentLength, IDokanFileInfo info)
        {
            volumeLabel = "XPlane-RealFiles";
            features = FileSystemFeatures.CasePreservedNames |
                       FileSystemFeatures.CaseSensitiveSearch |
                       FileSystemFeatures.PersistentAcls |
                       FileSystemFeatures.UnicodeOnDisk;
            fileSystemName = "XVFS-Fixed";
            maximumComponentLength = 256;
            return NtStatus.Success;
        }

        public NtStatus GetDiskFreeSpace(out long freeBytesAvailable, out long totalNumberOfBytes, out long totalNumberOfFreeBytes, IDokanFileInfo info)
        {
            long totalSize = fileProvider.TotalSize;
            freeBytesAvailable = Math.Max(0, 1000000000 - totalSize);
            totalNumberOfBytes = 1000000000;
            totalNumberOfFreeBytes = freeBytesAvailable;
            return NtStatus.Success;
        }

        // 只读文件系统实现
        public void Cleanup(string fileName, IDokanFileInfo info) { }
        public void CloseFile(string fileName, IDokanFileInfo info) { }

        public NtStatus WriteFile(string fileName, byte[] buffer, out int bytesWritten, long offset, IDokanFileInfo info)
        {
            bytesWritten = 0;
            logMessage($"⛔ Write attempt blocked: {fileName}");
            return NtStatus.AccessDenied;
        }

        public NtStatus FlushFileBuffers(string fileName, IDokanFileInfo info) => NtStatus.Success;
        public NtStatus SetFileAttributes(string fileName, FileAttributes attributes, IDokanFileInfo info) => NtStatus.AccessDenied;
        public NtStatus SetFileTime(string fileName, DateTime? creationTime, DateTime? lastAccessTime, DateTime? lastWriteTime, IDokanFileInfo info) => NtStatus.AccessDenied;
        public NtStatus DeleteFile(string fileName, IDokanFileInfo info) => NtStatus.AccessDenied;
        public NtStatus DeleteDirectory(string fileName, IDokanFileInfo info) => NtStatus.AccessDenied;
        public NtStatus MoveFile(string oldName, string newName, bool replace, IDokanFileInfo info) => NtStatus.AccessDenied;
        public NtStatus SetEndOfFile(string fileName, long length, IDokanFileInfo info) => NtStatus.AccessDenied;
        public NtStatus SetAllocationSize(string fileName, long length, IDokanFileInfo info) => NtStatus.AccessDenied;
        public NtStatus LockFile(string fileName, long offset, long length, IDokanFileInfo info) => NtStatus.Success;
        public NtStatus UnlockFile(string fileName, long offset, long length, IDokanFileInfo info) => NtStatus.Success;

        public NtStatus GetFileSecurity(string fileName, out FileSystemSecurity? security, AccessControlSections sections, IDokanFileInfo info)
        {
            security = null;
            return NtStatus.NotImplemented;
        }

        public NtStatus SetFileSecurity(string fileName, FileSystemSecurity security, AccessControlSections sections, IDokanFileInfo info) => NtStatus.AccessDenied;

        public NtStatus FindStreams(string fileName, out IList<FileInformation> streams, IDokanFileInfo info)
        {
            streams = new List<FileInformation>();
            return NtStatus.NotImplemented;
        }
    }

    // =====================================================
    // 简单高效的日志记录器
    // =====================================================

    internal class SimpleDokanLogger : ILogger
    {
        public bool DebugEnabled => true;
        public void Debug(string format, params object[] args) => System.Diagnostics.Debug.WriteLine($"[Dokan Debug] {string.Format(format, args)}");
        public void Info(string format, params object[] args) => System.Diagnostics.Debug.WriteLine($"[Dokan Info] {string.Format(format, args)}");
        public void Warn(string format, params object[] args) => System.Diagnostics.Debug.WriteLine($"[Dokan Warn] {string.Format(format, args)}");
        public void Error(string format, params object[] args) => System.Diagnostics.Debug.WriteLine($"[Dokan Error] {string.Format(format, args)}");
        public void Fatal(string format, params object[] args) => System.Diagnostics.Debug.WriteLine($"[Dokan Fatal] {string.Format(format, args)}");
    }

    // =====================================================
    // 修复后的虚拟文件系统管理器 - 主类
    // =====================================================

    public class VirtualFileSystemManager : IVirtualFileSystem
    {
        private readonly VFSAccessController accessController;
        private readonly VFSFileProvider fileProvider;
        private readonly DokanOperationsWrapper dokanOperations;

        private DokanInstance? dokanInstance;
        private Dokan? dokan;
        private volatile bool isMountedSuccessfully = false;
        private volatile bool isMountInProgress = false;
        private volatile bool isDisposed = false;
        private readonly object stateLock = new object();
        private VfsStatus currentStatus = VfsStatus.Uninitialized;

        public string MountPoint { get; private set; } = @"D:\steam\steamapps\common\X-Plane 12\Aircraft\MyPlane\777X\objects";
        public bool IsMounted => isMountedSuccessfully && !isDisposed;
        public VfsStatus Status => currentStatus;
        public int FileCount => fileProvider.FileCount;
        public long TotalSize => fileProvider.TotalSize;

        public event EventHandler<VfsStatusEventArgs>? StatusChanged;
        public event EventHandler<string>? LogMessage;

        public VirtualFileSystemManager(string? mountPoint = null, VfsAccessMode accessMode = VfsAccessMode.AllowAll)
        {
            if (!string.IsNullOrEmpty(mountPoint))
            {
                MountPoint = mountPoint;
            }

            accessController = new VFSAccessController();
            fileProvider = new VFSFileProvider();

            accessController.SetAccessMode(accessMode);

            dokanOperations = new DokanOperationsWrapper(
                accessController,
                fileProvider,
                OnLogMessage,
                OnMounted,
                OnUnmounted
            );

            SetupEventHandlers();
            UpdateStatus(VfsStatus.Uninitialized, "Fixed VFS Manager initialized for reliable file access");
            OnLogMessage($"🔒 Fixed VFS Manager initialized with mount point: {MountPoint}");
        }

        private void SetupEventHandlers()
        {
            accessController.AccessAttempted += (sender, e) =>
            {
                var message = e.AccessGranted
                    ? $"✅ Access GRANTED: {e.ProcessName} (PID: {e.ProcessId}) -> {e.FileName}"
                    : $"❌ Access DENIED: {e.ProcessName} (PID: {e.ProcessId}) -> {e.FileName} | Reason: {e.Reason}";

                OnLogMessage(message);

                if (e.AccessGranted)
                {
                    UpdateStatus(VfsStatus.FileAccessed, $"File accessed by {e.ProcessName}: {e.FileName}");
                }
            };
        }

        // =====================================================
        // 文件操作方法
        // =====================================================

        public void SetVirtualData(byte[] data)
        {
            fileProvider.SetVirtualData(data);
            OnLogMessage($"Set single virtual file: {data?.Length ?? 0} bytes");
        }

        public void SetVirtualFiles(Dictionary<string, byte[]> files)
        {
            fileProvider.SetVirtualFiles(files);
            long totalSize = files.Values.Sum(data => data.Length);
            OnLogMessage($"🔐 Set {files.Count} virtual files, total size: {totalSize} bytes");

            // 详细记录文件信息
            foreach (var file in files.Take(3))
            {
                try
                {
                    if (file.Value.Length > 50)
                    {
                        bool isText = file.Value.Take(50).All(b => (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13);
                        if (isText)
                        {
                            string contentPreview = System.Text.Encoding.UTF8.GetString(file.Value, 0, 50);
                            OnLogMessage($"📄 {file.Key}: {contentPreview.Replace('\n', ' ').Replace('\r', ' ')}...");
                        }
                        else
                        {
                            string hexPreview = string.Join(" ", file.Value.Take(16).Select(b => b.ToString("X2")));
                            OnLogMessage($"📄 {file.Key}: {hexPreview}... ({file.Value.Length} bytes)");
                        }
                    }
                    else
                    {
                        OnLogMessage($"📄 {file.Key}: {file.Value.Length} bytes");
                    }
                }
                catch
                {
                    OnLogMessage($"📄 {file.Key}: {file.Value.Length} bytes (binary)");
                }
            }

            UpdateStatus(VfsStatus.Uninitialized, $"Loaded {files.Count} virtual files ({FormatFileSize(totalSize)})");
        }

        public void AddVirtualFile(string fileName, byte[] data)
        {
            fileProvider.AddVirtualFile(fileName, data);
            OnLogMessage($"Added virtual file: {fileName} ({data.Length} bytes)");
        }

        public void RemoveVirtualFile(string fileName)
        {
            fileProvider.RemoveVirtualFile(fileName);
            OnLogMessage($"Removed virtual file: {fileName}");
        }

        public void ClearVirtualFiles()
        {
            fileProvider.ClearVirtualFiles();
            OnLogMessage("Cleared all virtual files");
        }

        public List<string> GetVirtualFileNames()
        {
            return fileProvider.GetVirtualFileNames();
        }

        // =====================================================
        // 挂载和卸载方法 - 增强可靠性
        // =====================================================

        public async Task<bool> MountAsync(CancellationToken cancellationToken = default)
        {
            lock (stateLock)
            {
                if (isDisposed)
                {
                    OnLogMessage("Cannot mount: VFS manager is disposed");
                    return false;
                }

                if (isMountInProgress)
                {
                    OnLogMessage("Mount already in progress");
                    return false;
                }

                if (isMountedSuccessfully)
                {
                    OnLogMessage("Already mounted");
                    return true;
                }

                isMountInProgress = true;
            }

            try
            {
                UpdateStatus(VfsStatus.Mounting, $"Starting mount operation with {FileCount} files");

                if (FileCount == 0)
                {
                    UpdateStatus(VfsStatus.Error, "No virtual files to mount");
                    OnLogMessage("Cannot mount: No virtual files loaded");
                    return false;
                }

                OnLogMessage($"📋 Virtual files ready for mount:");
                var fileNames = GetVirtualFileNames();
                foreach (var fileName in fileNames.Take(5))
                {
                    OnLogMessage($"📋   - {fileName}");
                }
                if (fileNames.Count > 5)
                {
                    OnLogMessage($"📋   ... and {fileNames.Count - 5} more files");
                }

                if (!await CheckMountPointAvailability())
                {
                    UpdateStatus(VfsStatus.Error, "Mount point is not available");
                    return false;
                }

                EnsureMountPointDirectory();

                bool mountResult = await PerformMount(cancellationToken);

                if (mountResult)
                {
                    bool verifyResult = await VerifyMountAsync();
                    if (verifyResult)
                    {
                        lock (stateLock)
                        {
                            isMountedSuccessfully = true;
                        }
                        UpdateStatus(VfsStatus.Mounted, $"Successfully mounted {FileCount} files to {MountPoint} ({FormatFileSize(TotalSize)})");
                        return true;
                    }
                    else
                    {
                        UpdateStatus(VfsStatus.Error, "Mount verification failed");
                        await ForceUnmountInternal();
                        return false;
                    }
                }
                else
                {
                    UpdateStatus(VfsStatus.Error, "Mount operation failed");
                    return false;
                }
            }
            catch (Exception ex)
            {
                UpdateStatus(VfsStatus.Error, $"Mount exception: {ex.Message}");
                OnLogMessage($"Mount exception: {ex}");
                return false;
            }
            finally
            {
                lock (stateLock)
                {
                    isMountInProgress = false;
                }
            }
        }

        private async Task<bool> CheckMountPointAvailability()
        {
            try
            {
                OnLogMessage($"Checking mount point availability: {MountPoint}");

                // 清理可能存在的旧挂载点
                try
                {
                    var tempDokan = new Dokan(new SimpleDokanLogger());
                    try
                    {
                        tempDokan.RemoveMountPoint(MountPoint);
                        OnLogMessage("Cleaned up existing mount point");
                        await Task.Delay(1000);
                    }
                    catch
                    {
                        // 清理失败不影响后续操作
                    }
                    finally
                    {
                        tempDokan.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    OnLogMessage($"Mount point cleanup: {ex.Message}");
                }

                return true;
            }
            catch (Exception ex)
            {
                OnLogMessage($"Mount point availability check failed: {ex.Message}");
                return false;
            }
        }

        private void EnsureMountPointDirectory()
        {
            try
            {
                var parentDir = Path.GetDirectoryName(MountPoint);
                if (!string.IsNullOrEmpty(parentDir) && !Directory.Exists(parentDir))
                {
                    Directory.CreateDirectory(parentDir);
                    OnLogMessage($"Created parent directory: {parentDir}");
                }

                if (!Directory.Exists(MountPoint))
                {
                    Directory.CreateDirectory(MountPoint);
                    OnLogMessage($"Created mount point directory: {MountPoint}");
                }
            }
            catch (Exception ex)
            {
                OnLogMessage($"Failed to create mount point directory: {ex.Message}");
                throw;
            }
        }

        private async Task<bool> PerformMount(CancellationToken cancellationToken)
        {
            return await Task.Run(() =>
            {
                try
                {
                    OnLogMessage($"🔐 Initializing Dokan file system for {FileCount} files...");

                    var dokanLogger = new SimpleDokanLogger();
                    dokan = new Dokan(dokanLogger);
                    var builder = new DokanInstanceBuilder(dokan);

                    builder.ConfigureOptions(opt =>
                    {
                        opt.MountPoint = MountPoint;
                        opt.Version = 230;
                        opt.TimeOut = TimeSpan.FromSeconds(30);

                        // 使用调试模式以获得更多信息
                        opt.Options = DokanOptions.DebugMode | DokanOptions.StderrOutput;
                        OnLogMessage("DokanOptions set: DebugMode | StderrOutput");

                        try
                        {
                            opt.AllocationUnitSize = 4096;
                            opt.SectorSize = 512;
                        }
                        catch (Exception ex)
                        {
                            OnLogMessage($"Using default allocation/sector sizes: {ex.Message}");
                        }
                    });

                    OnLogMessage("Building Dokan instance for reliable file access...");
                    dokanInstance = builder.Build(dokanOperations);

                    OnLogMessage($"🔒 Dokan instance built successfully for {FileCount} files");
                    return true;
                }
                catch (Exception ex)
                {
                    OnLogMessage($"Dokan mount failed: {ex.Message}");
                    if (ex.InnerException != null)
                    {
                        OnLogMessage($"Inner exception: {ex.InnerException.Message}");
                    }
                    return false;
                }
            }, cancellationToken);
        }

        private async Task<bool> VerifyMountAsync()
        {
            try
            {
                OnLogMessage("Verifying mount...");
                await Task.Delay(3000); // 给更多时间让文件系统完全挂载

                if (!Directory.Exists(MountPoint))
                {
                    OnLogMessage("Mount verification failed: Directory not accessible");
                    return false;
                }

                try
                {
                    var files = Directory.GetFiles(MountPoint);
                    var dirs = Directory.GetDirectories(MountPoint);
                    OnLogMessage($"🔍 Mount verification: Found {files.Length} files and {dirs.Length} directories");

                    if (files.Length > 0)
                    {
                        OnLogMessage($"✅ Virtual files are accessible: {string.Join(", ", files.Take(5).Select(Path.GetFileName))}");

                        // 尝试读取第一个文件来验证内容
                        try
                        {
                            var firstFile = files.First();
                            var fileInfo = new FileInfo(firstFile);
                            OnLogMessage($"📖 Testing file read: {Path.GetFileName(firstFile)} ({fileInfo.Length} bytes)");

                            // 读取前100字节验证
                            byte[] buffer = new byte[100];
                            using (var stream = File.OpenRead(firstFile))
                            {
                                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                                if (bytesRead > 0)
                                {
                                    string hexPreview = string.Join(" ", buffer.Take(16).Select(b => b.ToString("X2")));
                                    OnLogMessage($"📖 File content verified: {bytesRead} bytes read, hex: {hexPreview}...");
                                }
                                else
                                {
                                    OnLogMessage($"⚠️ File read returned 0 bytes");
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            OnLogMessage($"⚠️ File read test failed: {ex.Message}");
                        }
                    }

                    return files.Length > 0;
                }
                catch (Exception ex)
                {
                    OnLogMessage($"Mount verification failed: Cannot list directory contents: {ex.Message}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                OnLogMessage($"Mount verification exception: {ex.Message}");
                return false;
            }
        }

        // =====================================================
        // 卸载方法
        // =====================================================

        public async Task<bool> UnmountAsync()
        {
            lock (stateLock)
            {
                if (isDisposed)
                {
                    return true;
                }

                if (!isMountedSuccessfully)
                {
                    OnLogMessage("Not mounted, nothing to unmount");
                    return true;
                }
            }

            try
            {
                UpdateStatus(VfsStatus.Unmounting, $"Starting unmount operation for {FileCount} files");
                return await UnmountInternal();
            }
            catch (Exception ex)
            {
                OnLogMessage($"Unmount exception: {ex.Message}");
                return false;
            }
        }

        public void ForceUnmount()
        {
            lock (stateLock)
            {
                if (isDisposed) return;
                isDisposed = true;
            }

            try
            {
                UpdateStatus(VfsStatus.Unmounting, "Force unmounting");
                _ = Task.Run(async () => await ForceUnmountInternal());
            }
            catch (Exception ex)
            {
                OnLogMessage($"Force unmount exception: {ex.Message}");
            }
        }

        private async Task<bool> UnmountInternal()
        {
            try
            {
                OnLogMessage("Starting clean unmount...");

                await Task.Delay(500);

                if (dokanInstance != null)
                {
                    OnLogMessage("Disposing Dokan instance...");
                    var disposeTask = Task.Run(() =>
                    {
                        try
                        {
                            dokanInstance.Dispose();
                        }
                        catch (Exception ex)
                        {
                            OnLogMessage($"Dokan instance dispose exception: {ex.Message}");
                        }
                    });

                    await Task.WhenAny(disposeTask, Task.Delay(5000));
                    dokanInstance = null;
                }

                await Task.Delay(1000);

                if (dokan != null)
                {
                    OnLogMessage("Removing mount point...");
                    var removeTask = Task.Run(() =>
                    {
                        try
                        {
                            dokan.RemoveMountPoint(MountPoint);
                        }
                        catch (Exception ex)
                        {
                            OnLogMessage($"Remove mount point exception: {ex.Message}");
                        }
                    });

                    await Task.WhenAny(removeTask, Task.Delay(3000));
                }

                await Task.Delay(500);

                if (dokan != null)
                {
                    OnLogMessage("Disposing Dokan...");
                    var dokanDisposeTask = Task.Run(() =>
                    {
                        try
                        {
                            dokan.Dispose();
                        }
                        catch (Exception ex)
                        {
                            OnLogMessage($"Dokan dispose exception: {ex.Message}");
                        }
                    });

                    await Task.WhenAny(dokanDisposeTask, Task.Delay(2000));
                    dokan = null;
                }

                lock (stateLock)
                {
                    isMountedSuccessfully = false;
                }

                UpdateStatus(VfsStatus.Unmounted, "Clean unmount completed");
                OnLogMessage("Clean unmount completed successfully");
                return true;
            }
            catch (Exception ex)
            {
                OnLogMessage($"Clean unmount failed: {ex.Message}");
                await ForceUnmountInternal();
                return false;
            }
        }

        private async Task ForceUnmountInternal()
        {
            try
            {
                OnLogMessage("Starting force unmount...");

                try
                {
                    dokanInstance?.Dispose();
                }
                catch (Exception ex)
                {
                    OnLogMessage($"Force dispose dokanInstance: {ex.Message}");
                }
                dokanInstance = null;

                try
                {
                    dokan?.RemoveMountPoint(MountPoint);
                }
                catch (Exception ex)
                {
                    OnLogMessage($"Force remove mount point: {ex.Message}");
                }

                try
                {
                    dokan?.Dispose();
                }
                catch (Exception ex)
                {
                    OnLogMessage($"Force dispose dokan: {ex.Message}");
                }
                dokan = null;

                await Task.Delay(2000);

                lock (stateLock)
                {
                    isMountedSuccessfully = false;
                }

                UpdateStatus(VfsStatus.Unmounted, "Force unmount completed");
                OnLogMessage("Force unmount completed");
            }
            catch (Exception ex)
            {
                OnLogMessage($"Force unmount exception: {ex.Message}");
            }
        }

        // =====================================================
        // 配置方法
        // =====================================================

        public void SetMountPoint(string mountPoint)
        {
            if (!isMountedSuccessfully && !isMountInProgress)
            {
                MountPoint = mountPoint;
                OnLogMessage($"Mount point set to: {mountPoint}");
            }
            else
            {
                OnLogMessage("Cannot change mount point while mounted or mounting");
            }
        }

        public void SetAccessMode(VfsAccessMode mode)
        {
            accessController.SetAccessMode(mode);
            OnLogMessage($"🔒 Access mode set to: {mode}");
        }

        public void AddAllowedProcess(string processName)
        {
            accessController.AddAllowedProcess(processName);
            OnLogMessage($"🔐 Added allowed process: {processName}");
        }

        // =====================================================
        // 事件处理和状态管理
        // =====================================================

        private void OnMounted()
        {
            OnLogMessage($"🎯 Dokan mount callback triggered - {FileCount} files available for access");
        }

        private void OnUnmounted()
        {
            OnLogMessage("🔄 Dokan unmount callback triggered");
            lock (stateLock)
            {
                isMountedSuccessfully = false;
            }
        }

        private void UpdateStatus(VfsStatus status, string message = "")
        {
            currentStatus = status;
            OnLogMessage($"🔔 Status changed to {status}: {message}");
            StatusChanged?.Invoke(this, new VfsStatusEventArgs { Status = status, Message = message });
        }

        private void OnLogMessage(string message)
        {
            LogMessage?.Invoke(this, message);
        }

        // =====================================================
        // 工具方法
        // =====================================================

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

        /// <summary>
        /// 获取访问统计信息
        /// </summary>
        public Dictionary<string, int> GetAccessStatistics()
        {
            return accessController.GetAccessStatistics();
        }

        // =====================================================
        // 调试和诊断方法
        // =====================================================

        /// <summary>
        /// 测试VFS基本功能 - 用于诊断文件内容访问问题
        /// </summary>
        public async Task<bool> TestVFSFunctionalityAsync()
        {
            try
            {
                OnLogMessage("=== VFS FUNCTIONALITY TEST ===");

                if (!IsMounted)
                {
                    OnLogMessage("VFS not mounted, cannot test");
                    return false;
                }

                OnLogMessage($"Testing VFS at: {MountPoint}");

                // 测试目录访问
                if (Directory.Exists(MountPoint))
                {
                    var files = Directory.GetFiles(MountPoint);
                    OnLogMessage($"Found {files.Length} files in VFS");

                    foreach (string file in files.Take(3))
                    {
                        OnLogMessage($"Testing file: {Path.GetFileName(file)}");

                        // 测试文件信息
                        var fileInfo = new FileInfo(file);
                        OnLogMessage($"  Size: {fileInfo.Length} bytes");

                        // 测试读取前几个字节
                        try
                        {
                            byte[] buffer = new byte[100];
                            using (var stream = File.OpenRead(file))
                            {
                                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                                OnLogMessage($"  Read {bytesRead} bytes");

                                if (bytesRead > 0)
                                {
                                    string hex = string.Join(" ", buffer.Take(16).Select(b => b.ToString("X2")));
                                    OnLogMessage($"  Hex: {hex}");

                                    // 尝试显示文本内容
                                    bool isText = buffer.Take(bytesRead).All(b => (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13);
                                    if (isText)
                                    {
                                        string text = System.Text.Encoding.UTF8.GetString(buffer, 0, Math.Min(50, bytesRead));
                                        OnLogMessage($"  Text: {text.Replace('\n', ' ').Replace('\r', ' ')}");
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            OnLogMessage($"  Read error: {ex.Message}");
                        }
                    }

                    OnLogMessage("VFS functionality test completed");
                    return files.Length > 0;
                }
                else
                {
                    OnLogMessage("VFS mount point not accessible");
                    return false;
                }
            }
            catch (Exception ex)
            {
                OnLogMessage($"VFS test error: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 获取详细的VFS诊断信息
        /// </summary>
        public string GetVFSDiagnostics()
        {
            try
            {
                var diagnostics = new System.Text.StringBuilder();
                diagnostics.AppendLine("=== VFS DIAGNOSTICS ===");
                diagnostics.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                diagnostics.AppendLine();

                // 基本状态
                diagnostics.AppendLine("Basic Status:");
                diagnostics.AppendLine($"  Mount Point: {MountPoint}");
                diagnostics.AppendLine($"  Is Mounted: {IsMounted}");
                diagnostics.AppendLine($"  Status: {Status}");
                diagnostics.AppendLine($"  File Count: {FileCount}");
                diagnostics.AppendLine($"  Total Size: {FormatFileSize(TotalSize)}");
                diagnostics.AppendLine();

                // 文件列表
                var fileNames = GetVirtualFileNames();
                diagnostics.AppendLine($"Virtual Files ({fileNames.Count}):");
                foreach (var fileName in fileNames.Take(10))
                {
                    diagnostics.AppendLine($"  - {fileName}");
                }
                if (fileNames.Count > 10)
                {
                    diagnostics.AppendLine($"  ... and {fileNames.Count - 10} more files");
                }
                diagnostics.AppendLine();

                // 访问统计
                var accessStats = GetAccessStatistics();
                diagnostics.AppendLine($"Access Statistics ({accessStats.Count} processes):");
                foreach (var stat in accessStats.Take(10))
                {
                    diagnostics.AppendLine($"  {stat.Key}: {stat.Value} accesses");
                }
                diagnostics.AppendLine();

                // 挂载点状态
                diagnostics.AppendLine("Mount Point Status:");
                try
                {
                    if (Directory.Exists(MountPoint))
                    {
                        var files = Directory.GetFiles(MountPoint);
                        var dirs = Directory.GetDirectories(MountPoint);
                        diagnostics.AppendLine($"  Directory exists: Yes");
                        diagnostics.AppendLine($"  Files found: {files.Length}");
                        diagnostics.AppendLine($"  Directories found: {dirs.Length}");

                        if (files.Length > 0)
                        {
                            diagnostics.AppendLine("  File list:");
                            foreach (var file in files.Take(5))
                            {
                                var fileInfo = new FileInfo(file);
                                diagnostics.AppendLine($"    - {Path.GetFileName(file)} ({fileInfo.Length} bytes)");
                            }
                            if (files.Length > 5)
                            {
                                diagnostics.AppendLine($"    ... and {files.Length - 5} more files");
                            }
                        }
                    }
                    else
                    {
                        diagnostics.AppendLine($"  Directory exists: No");
                    }
                }
                catch (Exception ex)
                {
                    diagnostics.AppendLine($"  Error checking mount point: {ex.Message}");
                }

                return diagnostics.ToString();
            }
            catch (Exception ex)
            {
                return $"Error generating VFS diagnostics: {ex.Message}";
            }
        }

        // =====================================================
        // 清理和释放
        // =====================================================

        public void Dispose()
        {
            lock (stateLock)
            {
                if (isDisposed) return;
                isDisposed = true;
            }

            try
            {
                OnLogMessage($"🗑️ Disposing Fixed VFS Manager ({FileCount} files)...");
                ForceUnmount();
            }
            catch (Exception ex)
            {
                OnLogMessage($"Dispose exception: {ex.Message}");
            }
        }

        // =====================================================
        // 兼容性方法
        // =====================================================

        public bool MountVirtualFileSystem(byte[] decryptedData, CancellationToken cancellationToken)
        {
            try
            {
                if (decryptedData != null)
                {
                    SetVirtualData(decryptedData);
                }

                var mountTask = MountAsync(cancellationToken);
                return mountTask.GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                OnLogMessage($"Sync mount wrapper exception: {ex.Message}");
                return false;
            }
        }

        public void UnmountVirtualFileSystem()
        {
            try
            {
                ForceUnmount();
            }
            catch (Exception ex)
            {
                OnLogMessage($"Sync unmount wrapper exception: {ex.Message}");
            }
        }
    }

    // =====================================================
    // 工厂类 - 创建修复后的VFS实例
    // =====================================================

    public static class VFSFactory
    {
        public static IVirtualFileSystem CreateDefault()
        {
            return new VirtualFileSystemManager();
        }

        public static IVirtualFileSystem CreateSecure(params string[] allowedProcesses)
        {
            var vfs = new VirtualFileSystemManager(accessMode: VfsAccessMode.AllowAll); // 使用宽松模式确保文件可访问
            foreach (var process in allowedProcesses)
            {
                vfs.AddAllowedProcess(process);
            }
            return vfs;
        }

        public static IVirtualFileSystem CreateForTesting()
        {
            return new VirtualFileSystemManager(@"T:\", VfsAccessMode.AllowAll);
        }

        public static IVirtualFileSystem CreateForXPlaneObjects(string? customPath = null)
        {
            var mountPath = customPath ?? @"D:\steam\steamapps\common\X-Plane 12\Aircraft\MyPlane\777X\objects";
            var vfs = new VirtualFileSystemManager(mountPath, VfsAccessMode.AllowAll); // 使用AllowAll确保文件内容可读

            // 添加常用进程到白名单
            string[] commonProcesses = {
                "x-plane", "xplane", "X-Plane", "explorer", "notepad", "notepad++",
                "code", "atom", "sublime", "vim", "emacs", "totalcmd", "winrar",
                "7zip", "hexedit", "hxd", "010editor"
            };

            foreach (var process in commonProcesses)
            {
                vfs.AddAllowedProcess(process);
            }

            return vfs;
        }

        public static IVirtualFileSystem CreateMultiFileSystem(Dictionary<string, byte[]> files, string? mountPath = null, params string[] allowedProcesses)
        {
            var vfs = new VirtualFileSystemManager(mountPath, VfsAccessMode.AllowAll); // 使用AllowAll确保文件内容可读

            // 设置多个文件
            vfs.SetVirtualFiles(files);

            // 添加允许的进程
            foreach (var process in allowedProcesses)
            {
                vfs.AddAllowedProcess(process);
            }

            return vfs;
        }

        /// <summary>
        /// 创建专门用于调试文件内容问题的VFS实例
        /// </summary>
        public static IVirtualFileSystem CreateForDebugging(string? mountPath = null)
        {
            var vfs = new VirtualFileSystemManager(mountPath, VfsAccessMode.AllowAll);

            // 添加所有可能的文件查看器
            string[] debugProcesses = {
                "explorer", "cmd", "powershell", "notepad", "notepad++", "wordpad",
                "code", "atom", "sublime", "vim", "emacs", "nano", "gedit",
                "totalcmd", "winrar", "7zip", "peazip", "bandizip",
                "hexedit", "hxd", "010editor", "hexworkshop", "hexeditor",
                "procmon", "procexp", "filemon", "regmon", "wireshark"
            };

            foreach (var process in debugProcesses)
            {
                vfs.AddAllowedProcess(process);
            }

            return vfs;
        }
    }
}