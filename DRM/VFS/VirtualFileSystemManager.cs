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
        void SetVirtualData(byte[] data); // 单文件兼容
        void SetVirtualFiles(Dictionary<string, byte[]> files); // 多文件支持
        void AddVirtualFile(string fileName, byte[] data); // 添加单个文件
        void RemoveVirtualFile(string fileName); // 移除文件
        void ClearVirtualFiles(); // 清除所有文件
        List<string> GetVirtualFileNames(); // 获取所有文件名
        void SetMountPoint(string mountPoint);
        void SetAccessMode(VfsAccessMode mode);
        void AddAllowedProcess(string processName);

        event EventHandler<VfsStatusEventArgs>? StatusChanged;
        event EventHandler<string>? LogMessage;
    }

    // =====================================================
    // 修复后的访问控制器 - 更宽松的权限控制以便看到文件内容
    // =====================================================

    internal class VFSAccessController
    {
        private readonly HashSet<string> allowedProcesses = new();
        private VfsAccessMode accessMode = VfsAccessMode.AllowAll; // 改为更宽松的默认模式
        private DateTime? lastAccessTime = null;
        private int accessAttemptCount = 0;
        private readonly object accessLock = new();

        // 访问统计
        private readonly Dictionary<string, int> processAccessCount = new();
        private readonly Dictionary<string, DateTime> lastProcessAccess = new();

        public event EventHandler<VfsAccessEventArgs>? AccessAttempted;

        public VFSAccessController()
        {
            // 允许更多进程以便调试和查看文件内容
            allowedProcesses.Add("x-plane");
            allowedProcesses.Add("xplane");
            allowedProcesses.Add("x-plane 12");
            allowedProcesses.Add("drm");
            allowedProcesses.Add("xplaneactivator");
            allowedProcesses.Add("system");
            allowedProcesses.Add("explorer");
            allowedProcesses.Add("notepad");
            allowedProcesses.Add("notepad++");
            allowedProcesses.Add("code");
            allowedProcesses.Add("devenv");
            allowedProcesses.Add("cmd");
            allowedProcesses.Add("powershell");
            allowedProcesses.Add("conhost");

            System.Diagnostics.Debug.WriteLine("[VFSAccessController] Initialized with relaxed whitelist for file content access");
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

                    // 更宽松的速率限制检查
                    if (eventArgs.AccessGranted && !CheckRateLimit(processName))
                    {
                        // 不阻止访问，只记录警告
                        System.Diagnostics.Debug.WriteLine($"[VFSAccessController] Rate limit warning for {processName}, but allowing access");
                    }

                    // 更新访问统计
                    if (eventArgs.AccessGranted)
                    {
                        processAccessCount[processName] = processAccessCount.GetValueOrDefault(processName, 0) + 1;
                        lastProcessAccess[processName] = DateTime.Now;
                    }
                }
                catch (Exception ex)
                {
                    // 出现异常时，默认允许访问以便调试
                    eventArgs.AccessGranted = true;
                    eventArgs.Reason = $"Exception occurred, allowing access: {ex.Message}";
                    System.Diagnostics.Debug.WriteLine($"[VFSAccessController] Access check exception: {ex.Message}");
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
                // 检查进程名是否在白名单中
                string lowerProcessName = processName.ToLowerInvariant();
                bool isInWhitelist = allowedProcesses.Any(allowed =>
                    lowerProcessName.Contains(allowed.ToLowerInvariant()) ||
                    allowed.ToLowerInvariant().Contains(lowerProcessName));

                if (!isInWhitelist)
                {
                    // 对于未知进程，也允许访问但记录日志
                    reason = $"Process '{processName}' not in whitelist, but allowing for debugging";
                    System.Diagnostics.Debug.WriteLine($"[VFSAccessController] Unknown process access: {processName} (PID: {processId})");
                    return true; // 改为允许访问
                }

                // 额外验证：检查进程是否真实存在且可访问
                try
                {
                    var process = Process.GetProcessById(processId);
                    if (process.HasExited)
                    {
                        reason = $"Process '{processName}' has exited, but allowing access";
                        return true; // 改为允许访问
                    }

                    reason = $"Process '{processName}' (PID: {processId}) verified and allowed";
                    return true;
                }
                catch (Exception ex)
                {
                    reason = $"Process verification failed, but allowing access: {ex.Message}";
                    return true; // 改为允许访问
                }
            }
            catch (Exception ex)
            {
                reason = $"Whitelist check error, allowing access: {ex.Message}";
                return true; // 改为允许访问
            }
        }

        private bool CheckRateLimit(string processName)
        {
            var currentTime = DateTime.Now;

            // 更宽松的速率限制
            if (lastProcessAccess.TryGetValue(processName, out DateTime lastAccess))
            {
                if ((currentTime - lastAccess).TotalMilliseconds < 1) // 1ms 限制（更宽松）
                {
                    int accessCount = processAccessCount.GetValueOrDefault(processName, 0);
                    if (accessCount > 1000) // 每1ms最多1000次访问（更宽松）
                    {
                        return false;
                    }
                }
                else
                {
                    // 重置计数器
                    processAccessCount[processName] = 0;
                }
            }

            return true;
        }

        public void AddAllowedProcess(string processName)
        {
            if (!string.IsNullOrWhiteSpace(processName))
            {
                allowedProcesses.Add(processName.ToLowerInvariant());
                System.Diagnostics.Debug.WriteLine($"[VFSAccessController] Added allowed process: {processName}");
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
    // 多文件提供器 - 保持不变
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
                    }
                }

                SetupFileInfoCache();
                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Set {virtualFiles.Count} virtual files, total size: {TotalSize} bytes");
            }
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
                return fileInfoCache.TryGetValue(normalizedPath, out var fileInfo) ? fileInfo : null;
            }
        }

        public int ReadFile(string fileName, byte[] buffer, long offset, int length)
        {
            lock (lockObject)
            {
                string normalizedPath = NormalizePath(fileName);

                if (virtualFiles.TryGetValue(normalizedPath, out var virtualFile))
                {
                    virtualFile.LastAccessTime = DateTime.Now;

                    int startIndex = (int)Math.Min(offset, virtualFile.Data.Length);
                    int lengthToRead = Math.Min(length, virtualFile.Data.Length - startIndex);

                    if (lengthToRead > 0)
                    {
                        Array.Copy(virtualFile.Data, startIndex, buffer, 0, lengthToRead);

                        // 记录读取的文件内容（用于调试）
                        if (startIndex == 0 && lengthToRead >= 50)
                        {
                            try
                            {
                                string contentPreview = System.Text.Encoding.UTF8.GetString(virtualFile.Data, 0, Math.Min(100, virtualFile.Data.Length));
                                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Reading content from {fileName}: {contentPreview.Replace('\n', ' ').Replace('\r', ' ')}...");
                            }
                            catch
                            {
                                System.Diagnostics.Debug.WriteLine($"[VFSFileProvider] Reading binary content from {fileName}: {lengthToRead} bytes");
                            }
                        }

                        return lengthToRead;
                    }
                }

                return 0;
            }
        }

        public IList<FileInformation> GetDirectoryFiles(string directoryPath, string? searchPattern = null)
        {
            lock (lockObject)
            {
                var result = new List<FileInformation>();

                if (directoryPath == @"\" || directoryPath == "/")
                {
                    foreach (var fileInfo in fileInfoCache.Values)
                    {
                        if (fileInfo.FileName != @"\" && !fileInfo.FileName.Contains(@"\", StringComparison.Ordinal) && !fileInfo.FileName.Contains("/", StringComparison.Ordinal))
                        {
                            if (string.IsNullOrEmpty(searchPattern) || searchPattern == "*" || searchPattern == "*.*" ||
                                fileInfo.FileName.Contains(searchPattern.Replace("*", ""), StringComparison.OrdinalIgnoreCase))
                            {
                                result.Add(fileInfo);
                            }
                        }
                    }
                }

                return result;
            }
        }

        private void SetupFileInfoCache()
        {
            fileInfoCache.Clear();

            fileInfoCache[@"\"] = new FileInformation
            {
                FileName = @"\",
                Attributes = FileAttributes.Directory,
                CreationTime = DateTime.Now,
                LastAccessTime = DateTime.Now,
                LastWriteTime = DateTime.Now,
                Length = 0
            };

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
    // 修复后的 Dokan操作包装器 - 简化进程检测以确保文件内容可访问
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

        /// <summary>
        /// 简化的进程信息获取 - 更可靠的实现
        /// </summary>
        private (int processId, string processName) GetCallingProcessInfo(IDokanFileInfo info)
        {
            try
            {
                // 方法1：尝试使用DokanFileInfo中的进程信息
                if (info != null && info.ProcessId != 0)
                {
                    try
                    {
                        var process = Process.GetProcessById(info.ProcessId);
                        if (!process.HasExited)
                        {
                            logMessage($"[ProcessDetection] Found process: {process.ProcessName} (PID: {process.Id})");
                            return (process.Id, process.ProcessName);
                        }
                    }
                    catch (Exception ex)
                    {
                        logMessage($"[ProcessDetection] Method 1 failed: {ex.Message}");
                    }
                }

                // 方法2：使用当前进程信息（简化的回退方案）
                var currentProcess = Process.GetCurrentProcess();
                logMessage($"[ProcessDetection] Using current process as fallback: {currentProcess.ProcessName} (PID: {currentProcess.Id})");
                return (currentProcess.Id, currentProcess.ProcessName);
            }
            catch (Exception ex)
            {
                logMessage($"[ProcessDetection] All methods failed: {ex.Message}");
                // 最终回退方案
                return (0, "unknown");
            }
        }

        public NtStatus CreateFile(string fileName, DokanNet.FileAccess access, FileShare share,
            FileMode mode, FileOptions options, FileAttributes attributes, IDokanFileInfo info)
        {
            try
            {
                // 获取调用进程信息
                var (processId, processName) = GetCallingProcessInfo(info);
                logMessage($"🔍 File access attempt: {processName} (PID: {processId}) -> {fileName}");

                if (!accessController.CheckAccess(processId, processName, fileName))
                {
                    logMessage($"❌ Access DENIED: {processName} (PID: {processId}) -> {fileName}");
                    // 即使访问控制拒绝，也允许访问以便调试
                    logMessage($"⚠️ Override: Allowing access for debugging purposes");
                }

                var fileInfo = fileProvider.GetFileInfo(fileName);
                if (fileInfo != null)
                {
                    info.IsDirectory = fileInfo.Value.Attributes.HasFlag(FileAttributes.Directory);
                    logMessage($"✅ Access GRANTED: {processName} (PID: {processId}) -> {fileName}");
                    return NtStatus.Success;
                }

                logMessage($"📁 File not found: {fileName}");
                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                logMessage($"💥 CreateFile error: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
        {
            bytesRead = 0;
            try
            {
                // 获取调用进程信息
                var (processId, processName) = GetCallingProcessInfo(info);

                // 简化访问控制 - 总是允许读取以便查看文件内容
                logMessage($"📖 Read request: {processName} (PID: {processId}) -> {fileName} (offset: {offset}, buffer: {buffer.Length})");

                bytesRead = fileProvider.ReadFile(fileName, buffer, offset, buffer.Length);
                if (bytesRead > 0)
                {
                    logMessage($"📖 Read SUCCESS: {processName} read {bytesRead} bytes from {fileName} at offset {offset}");

                    // 如果是文本文件，记录部分内容
                    if (offset == 0 && bytesRead >= 10)
                    {
                        try
                        {
                            string contentPreview = System.Text.Encoding.UTF8.GetString(buffer, 0, Math.Min(50, bytesRead));
                            logMessage($"📖 Content preview: {contentPreview.Replace('\n', ' ').Replace('\r', ' ')}...");
                        }
                        catch
                        {
                            logMessage($"📖 Binary content: {bytesRead} bytes read");
                        }
                    }

                    return NtStatus.Success;
                }

                logMessage($"📖 Read failed: {fileName} (no data available)");
                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                logMessage($"💥 ReadFile error for {fileName}: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus GetFileInformation(string fileName, out FileInformation fileInfo, IDokanFileInfo info)
        {
            fileInfo = default;
            try
            {
                // 获取调用进程信息
                var (processId, processName) = GetCallingProcessInfo(info);

                // 简化访问控制 - 总是允许获取文件信息
                logMessage($"ℹ️ GetFileInfo: {processName} (PID: {processId}) -> {fileName}");

                var fileInfoNullable = fileProvider.GetFileInfo(fileName);
                if (fileInfoNullable.HasValue)
                {
                    fileInfo = fileInfoNullable.Value;
                    logMessage($"ℹ️ File info: {fileName} ({fileInfo.Length} bytes)");
                    return NtStatus.Success;
                }

                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                logMessage($"💥 GetFileInformation error: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus FindFiles(string fileName, out IList<FileInformation> files, IDokanFileInfo info)
        {
            try
            {
                // 获取调用进程信息
                var (processId, processName) = GetCallingProcessInfo(info);

                // 简化访问控制 - 总是允许列出文件
                logMessage($"📂 FindFiles: {processName} (PID: {processId}) -> {fileName}");

                files = fileProvider.GetDirectoryFiles(fileName);
                logMessage($"📂 FindFiles SUCCESS: {processName} found {files.Count} files in '{fileName}'");

                // 记录找到的文件
                foreach (var file in files.Take(5))
                {
                    logMessage($"📂   - {file.FileName} ({file.Length} bytes)");
                }
                if (files.Count > 5)
                {
                    logMessage($"📂   ... and {files.Count - 5} more files");
                }

                return NtStatus.Success;
            }
            catch (Exception ex)
            {
                files = new List<FileInformation>();
                logMessage($"💥 FindFiles error: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus FindFilesWithPattern(string fileName, string searchPattern, out IList<FileInformation> files, IDokanFileInfo info)
        {
            try
            {
                // 获取调用进程信息
                var (processId, processName) = GetCallingProcessInfo(info);

                // 简化访问控制 - 总是允许搜索文件
                logMessage($"🔍 FindFilesWithPattern: {processName} (PID: {processId}) -> {fileName} (pattern: {searchPattern})");

                files = fileProvider.GetDirectoryFiles(fileName, searchPattern);
                logMessage($"🔍 FindFilesWithPattern SUCCESS: {processName} found {files.Count} files matching '{searchPattern}' in '{fileName}'");
                return NtStatus.Success;
            }
            catch (Exception ex)
            {
                files = new List<FileInformation>();
                logMessage($"💥 FindFilesWithPattern error: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus Mounted(string mountPoint, IDokanFileInfo info)
        {
            logMessage($"🎯 Virtual file system mounted to: {mountPoint}");
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
            fileSystemName = "XVFS-RealFiles";
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
    // 简单Dokan日志记录器
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
    // 多文件VFS管理器 - 主类
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
            UpdateStatus(VfsStatus.Uninitialized, "Real file VFS Manager initialized for content access");
            OnLogMessage($"🔒 Real file VFS Manager initialized with mount point: {MountPoint}");
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
        // 多文件支持方法
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
            OnLogMessage($"🔐 Set {files.Count} real virtual files, total size: {totalSize} bytes");

            // 记录文件内容概览
            foreach (var file in files.Take(3))
            {
                try
                {
                    if (file.Value.Length > 50)
                    {
                        string contentPreview = System.Text.Encoding.UTF8.GetString(file.Value, 0, 50);
                        OnLogMessage($"📄 {file.Key}: {contentPreview.Replace('\n', ' ').Replace('\r', ' ')}...");
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

            UpdateStatus(VfsStatus.Uninitialized, $"Loaded {files.Count} real virtual files ({FormatFileSize(totalSize)})");
        }

        public void AddVirtualFile(string fileName, byte[] data)
        {
            fileProvider.AddVirtualFile(fileName, data);
            OnLogMessage($"Added real virtual file: {fileName} ({data.Length} bytes)");
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
        // 挂载和卸载方法 - 保持原有逻辑
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
                UpdateStatus(VfsStatus.Mounting, $"Starting real file mount operation with {FileCount} files");

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
                    UpdateStatus(VfsStatus.Error, "Mount point is not available or already in use");
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
                        UpdateStatus(VfsStatus.Mounted, $"Successfully mounted {FileCount} real files to {MountPoint} ({FormatFileSize(TotalSize)})");
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

                if (Directory.Exists(MountPoint))
                {
                    try
                    {
                        var entries = Directory.GetFileSystemEntries(MountPoint);
                        foreach (var entry in entries)
                        {
                            if (Path.GetFileName(entry).ToLower().Contains("dokan") ||
                                Path.GetFileName(entry).ToLower().Contains("vfs"))
                            {
                                OnLogMessage("Mount point appears to be already mounted by another VFS");
                                return false;
                            }
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        OnLogMessage("Mount point access denied - may be in use");
                        return false;
                    }
                    catch (DirectoryNotFoundException)
                    {
                        // 目录不存在，这是正常的
                    }
                    catch (Exception ex)
                    {
                        OnLogMessage($"Mount point check warning: {ex.Message}");
                    }
                }

                try
                {
                    bool wasAlreadyMounted = false;
                    var tempDokan = new Dokan(new SimpleDokanLogger());
                    try
                    {
                        tempDokan.RemoveMountPoint(MountPoint);
                        wasAlreadyMounted = true;
                        OnLogMessage("Removed existing mount point");
                        await Task.Delay(1000);
                    }
                    catch
                    {
                        // 如果移除失败，说明可能没有挂载
                    }
                    finally
                    {
                        tempDokan.Dispose();
                    }

                    if (wasAlreadyMounted)
                    {
                        OnLogMessage("Previous mount point cleaned up");
                    }
                }
                catch (Exception ex)
                {
                    OnLogMessage($"Mount point cleanup attempt: {ex.Message}");
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
                    OnLogMessage($"🔐 Initializing Dokan file system for {FileCount} real files...");

                    var dokanLogger = new SimpleDokanLogger();
                    dokan = new Dokan(dokanLogger);
                    var builder = new DokanInstanceBuilder(dokan);

                    builder.ConfigureOptions(opt =>
                    {
                        opt.MountPoint = MountPoint;
                        opt.Version = 230;
                        opt.TimeOut = TimeSpan.FromSeconds(30);

                        try
                        {
                            opt.Options = DokanOptions.DebugMode;
                            OnLogMessage("DokanOptions set: DebugMode");
                        }
                        catch (Exception ex)
                        {
                            OnLogMessage($"Warning: Cannot set DebugMode: {ex.Message}");
                            opt.Options = 0;
                        }

                        try
                        {
                            opt.AllocationUnitSize = 4096;
                            opt.SectorSize = 512;
                        }
                        catch (Exception ex)
                        {
                            OnLogMessage($"Info: Using default allocation/sector sizes: {ex.Message}");
                        }
                    });

                    OnLogMessage("Building Dokan instance for real file access...");
                    dokanInstance = builder.Build(dokanOperations);

                    OnLogMessage($"🔒 Dokan instance built successfully for {FileCount} real files");
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
                await Task.Delay(2000);

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
                        OnLogMessage($"✅ Real virtual files are accessible: {string.Join(", ", files.Take(5).Select(Path.GetFileName))}");

                        // 尝试读取第一个文件的部分内容
                        try
                        {
                            var firstFile = files.First();
                            var content = File.ReadAllText(firstFile);
                            string preview = content.Length > 100 ? content.Substring(0, 100) : content;
                            OnLogMessage($"📖 Content preview from {Path.GetFileName(firstFile)}: {preview.Replace('\n', ' ').Replace('\r', ' ')}...");
                        }
                        catch (Exception ex)
                        {
                            OnLogMessage($"⚠️ Cannot read file content: {ex.Message}");
                        }
                    }

                    return true;
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
        // 卸载方法 - 保持原有逻辑
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
            OnLogMessage($"🎯 Dokan mount callback triggered - {FileCount} real files available for access");
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
                OnLogMessage($"🗑️ Disposing Real file VFS Manager ({FileCount} files)...");
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
    // 工厂类 - 更新支持多文件
    // =====================================================

    public static class VFSFactory
    {
        public static IVirtualFileSystem CreateDefault()
        {
            return new VirtualFileSystemManager();
        }

        public static IVirtualFileSystem CreateSecure(params string[] allowedProcesses)
        {
            var vfs = new VirtualFileSystemManager(accessMode: VfsAccessMode.WhitelistOnly);
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
            var vfs = new VirtualFileSystemManager(mountPath, VfsAccessMode.AllowAll); // 改为允许所有访问

            vfs.AddAllowedProcess("x-plane");
            vfs.AddAllowedProcess("xplane");
            vfs.AddAllowedProcess("X-Plane");
            vfs.AddAllowedProcess("explorer");
            vfs.AddAllowedProcess("notepad");
            vfs.AddAllowedProcess("code");

            return vfs;
        }

        public static IVirtualFileSystem CreateMultiFileSystem(Dictionary<string, byte[]> files, string? mountPath = null, params string[] allowedProcesses)
        {
            var vfs = new VirtualFileSystemManager(mountPath, VfsAccessMode.AllowAll); // 改为允许所有访问

            // 设置多个文件
            vfs.SetVirtualFiles(files);

            // 添加允许的进程
            foreach (var process in allowedProcesses)
            {
                vfs.AddAllowedProcess(process);
            }

            return vfs;
        }
    }
}