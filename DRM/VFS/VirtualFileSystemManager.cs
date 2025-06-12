using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
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
    // 主接口
    // =====================================================

    public interface IVirtualFileSystem : IDisposable
    {
        string MountPoint { get; }
        bool IsMounted { get; }
        VfsStatus Status { get; }

        Task<bool> MountAsync(CancellationToken cancellationToken = default);
        Task<bool> UnmountAsync();
        void ForceUnmount();
        void SetVirtualData(byte[] data);
        void SetMountPoint(string mountPoint);
        void SetAccessMode(VfsAccessMode mode);
        void AddAllowedProcess(string processName);

        event EventHandler<VfsStatusEventArgs>? StatusChanged;
        event EventHandler<string>? LogMessage;
    }

    // =====================================================
    // 访问控制器
    // =====================================================

    internal class VFSAccessController
    {
        private readonly HashSet<string> allowedProcesses = new();
        private VfsAccessMode accessMode = VfsAccessMode.WhitelistOnly;
        private DateTime? lastAccessTime = null;
        private int accessAttemptCount = 0;
        private readonly object accessLock = new();

        public event EventHandler<VfsAccessEventArgs>? AccessAttempted;

        public VFSAccessController()
        {
            allowedProcesses.Add("x-plane");
            allowedProcesses.Add("xplane");
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

                    if (eventArgs.AccessGranted && !CheckRateLimit())
                    {
                        eventArgs.AccessGranted = false;
                        eventArgs.Reason = "Rate limit exceeded";
                    }
                }
                catch (Exception ex)
                {
                    eventArgs.AccessGranted = false;
                    eventArgs.Reason = $"Access check error: {ex.Message}";
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
                var processes = Process.GetProcesses()
                    .Where(p =>
                    {
                        try
                        {
                            string name = p.ProcessName.ToLowerInvariant();
                            return allowedProcesses.Any(allowed => name.Contains(allowed.ToLowerInvariant()));
                        }
                        catch { return false; }
                    })
                    .ToList();

                if (!processes.Any())
                {
                    reason = "No valid allowed processes found";
                    return false;
                }

                bool isAllowed = processes.Any(p => p.Id == processId);
                reason = isAllowed ? $"Process {processName} is in whitelist" : $"Process {processName} not in whitelist";
                return isAllowed;
            }
            catch (Exception ex)
            {
                reason = $"Process check error: {ex.Message}";
                return false;
            }
        }

        private bool CheckRateLimit()
        {
            var currentTime = DateTime.Now;
            if (lastAccessTime.HasValue && (currentTime - lastAccessTime.Value).TotalMilliseconds < 50)
            {
                accessAttemptCount++;
                if (accessAttemptCount > 10) return false;
            }
            else
            {
                accessAttemptCount = 0;
            }
            lastAccessTime = currentTime;
            return true;
        }

        public void AddAllowedProcess(string processName)
        {
            if (!string.IsNullOrWhiteSpace(processName))
            {
                allowedProcesses.Add(processName.ToLowerInvariant());
            }
        }

        public void SetAccessMode(VfsAccessMode mode)
        {
            accessMode = mode;
        }
    }

    // =====================================================
    // 文件提供器
    // =====================================================

    internal class VFSFileProvider
    {
        private byte[]? fuseObjData;
        private readonly Dictionary<string, FileInformation> files = new();
        private readonly object lockObject = new();

        public void SetVirtualData(byte[] data)
        {
            lock (lockObject)
            {
                fuseObjData = data;
                SetupVirtualFiles();
            }
        }

        public FileInformation? GetFileInfo(string fileName)
        {
            lock (lockObject)
            {
                return files.TryGetValue(fileName, out var fileInfo) ? fileInfo : null;
            }
        }

        public int ReadFile(string fileName, byte[] buffer, long offset, int length)
        {
            lock (lockObject)
            {
                if (fileName == @"\Fuse 1.obj" && fuseObjData != null)
                {
                    int startIndex = (int)Math.Min(offset, fuseObjData.Length);
                    int lengthToRead = Math.Min(length, fuseObjData.Length - startIndex);

                    if (lengthToRead > 0)
                    {
                        Array.Copy(fuseObjData, startIndex, buffer, 0, lengthToRead);
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
                if (directoryPath == @"\")
                {
                    foreach (var file in files.Values)
                    {
                        if (file.FileName != @"\" && !file.FileName.Contains(@"\", StringComparison.Ordinal))
                        {
                            if (string.IsNullOrEmpty(searchPattern) || searchPattern == "*" || searchPattern == "*.*" ||
                                file.FileName.Contains(searchPattern.Replace("*", ""), StringComparison.OrdinalIgnoreCase))
                            {
                                result.Add(file);
                            }
                        }
                    }
                }
                return result;
            }
        }

        private void SetupVirtualFiles()
        {
            files.Clear();

            files[@"\"] = new FileInformation
            {
                FileName = @"\",
                Attributes = FileAttributes.Directory,
                CreationTime = DateTime.Now,
                LastAccessTime = DateTime.Now,
                LastWriteTime = DateTime.Now,
                Length = 0
            };

            files[@"\Fuse 1.obj"] = new FileInformation
            {
                FileName = "Fuse 1.obj",
                Attributes = FileAttributes.Normal,
                CreationTime = DateTime.Now,
                LastAccessTime = DateTime.Now,
                LastWriteTime = DateTime.Now,
                Length = fuseObjData?.Length ?? 0
            };
        }
    }

    // =====================================================
    // Dokan操作包装器
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

        public NtStatus CreateFile(string fileName, DokanNet.FileAccess access, FileShare share,
            FileMode mode, FileOptions options, FileAttributes attributes, IDokanFileInfo info)
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                if (!accessController.CheckAccess(currentProcess.Id, currentProcess.ProcessName, fileName))
                {
                    logMessage($"Access denied: {currentProcess.ProcessName} -> {fileName}");
                    return NtStatus.AccessDenied;
                }

                var fileInfo = fileProvider.GetFileInfo(fileName);
                if (fileInfo != null)
                {
                    info.IsDirectory = fileInfo.Value.Attributes.HasFlag(FileAttributes.Directory);
                    logMessage($"File access granted: {fileName}");
                    return NtStatus.Success;
                }

                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                logMessage($"CreateFile error: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
        {
            bytesRead = 0;
            try
            {
                bytesRead = fileProvider.ReadFile(fileName, buffer, offset, buffer.Length);
                if (bytesRead > 0)
                {
                    logMessage($"Read {bytesRead} bytes from {fileName}");
                    return NtStatus.Success;
                }
                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                logMessage($"ReadFile error: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus GetFileInformation(string fileName, out FileInformation fileInfo, IDokanFileInfo info)
        {
            fileInfo = default;
            try
            {
                var fileInfoNullable = fileProvider.GetFileInfo(fileName);
                if (fileInfoNullable.HasValue)
                {
                    fileInfo = fileInfoNullable.Value;
                    return NtStatus.Success;
                }
                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                logMessage($"GetFileInformation error: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus FindFiles(string fileName, out IList<FileInformation> files, IDokanFileInfo info)
        {
            try
            {
                files = fileProvider.GetDirectoryFiles(fileName);
                return NtStatus.Success;
            }
            catch (Exception ex)
            {
                files = new List<FileInformation>();
                logMessage($"FindFiles error: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus FindFilesWithPattern(string fileName, string searchPattern, out IList<FileInformation> files, IDokanFileInfo info)
        {
            try
            {
                files = fileProvider.GetDirectoryFiles(fileName, searchPattern);
                return NtStatus.Success;
            }
            catch (Exception ex)
            {
                files = new List<FileInformation>();
                logMessage($"FindFilesWithPattern error: {ex.Message}");
                return NtStatus.InternalError;
            }
        }

        public NtStatus Mounted(string mountPoint, IDokanFileInfo info)
        {
            logMessage($"File system mounted to: {mountPoint}");
            mountedCallback();
            return NtStatus.Success;
        }

        public NtStatus Unmounted(IDokanFileInfo info)
        {
            logMessage("File system unmounted");
            unmountedCallback();
            return NtStatus.Success;
        }

        // 只读文件系统实现
        public void Cleanup(string fileName, IDokanFileInfo info) { }
        public void CloseFile(string fileName, IDokanFileInfo info) { }
        public NtStatus WriteFile(string fileName, byte[] buffer, out int bytesWritten, long offset, IDokanFileInfo info)
        {
            bytesWritten = 0;
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

        public NtStatus GetDiskFreeSpace(out long freeBytesAvailable, out long totalNumberOfBytes, out long totalNumberOfFreeBytes, IDokanFileInfo info)
        {
            freeBytesAvailable = 1000000000;
            totalNumberOfBytes = 2000000000;
            totalNumberOfFreeBytes = 1000000000;
            return NtStatus.Success;
        }

        public NtStatus GetVolumeInformation(out string volumeLabel, out FileSystemFeatures features, out string fileSystemName, out uint maximumComponentLength, IDokanFileInfo info)
        {
            volumeLabel = "XPlane-VFS";
            features = FileSystemFeatures.None;
            fileSystemName = "XVFS";
            maximumComponentLength = 256;
            return NtStatus.Success;
        }

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
    // 主VFS管理器
    // =====================================================

    public class VirtualFileSystemManager : IVirtualFileSystem
    {
        private readonly VFSAccessController accessController;
        private readonly VFSFileProvider fileProvider;
        private readonly DokanOperationsWrapper dokanOperations;

        private DokanInstance? dokanInstance;
        private Dokan? dokan;
        private readonly ManualResetEventSlim mountedEvent = new(false);
        private volatile bool isMountedSuccessfully = false;
        private volatile bool isMountInProgress = false;
        private Exception? mountException = null;
        private readonly CancellationTokenSource disposalCancellationTokenSource = new();
        private volatile bool isDisposing = false;
        private readonly object disposeLock = new();
        private VfsStatus currentStatus = VfsStatus.Uninitialized;

        public string MountPoint { get; private set; } = @"V:\";
        public bool IsMounted => isMountedSuccessfully;
        public VfsStatus Status => currentStatus;

        public event EventHandler<VfsStatusEventArgs>? StatusChanged;
        public event EventHandler<string>? LogMessage;

        public VirtualFileSystemManager(string mountPoint = @"V:\", VfsAccessMode accessMode = VfsAccessMode.WhitelistOnly)
        {
            MountPoint = mountPoint;
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
            UpdateStatus(VfsStatus.Uninitialized, "VFS Manager initialized");
        }

        private void SetupEventHandlers()
        {
            accessController.AccessAttempted += (sender, e) =>
            {
                var message = e.AccessGranted
                    ? $"Access granted to {e.ProcessName} for {e.FileName}"
                    : $"Access denied to {e.ProcessName} for {e.FileName}: {e.Reason}";

                OnLogMessage(message);

                if (e.AccessGranted)
                {
                    UpdateStatus(VfsStatus.FileAccessed, $"File accessed by {e.ProcessName}");
                }
            };
        }

        public async Task<bool> MountAsync(CancellationToken cancellationToken = default)
        {
            if (isMountInProgress)
            {
                OnLogMessage("Mount already in progress");
                return false;
            }

            isMountInProgress = true;
            UpdateStatus(VfsStatus.Mounting, "Starting mount operation");

            try
            {
                mountedEvent.Reset();
                isMountedSuccessfully = false;
                mountException = null;

                using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken, disposalCancellationTokenSource.Token);

                _ = Task.Run(() =>
                {
                    try
                    {
                        var dokanLogger = new SimpleDokanLogger();
                        dokan = new Dokan(dokanLogger);
                        var builder = new DokanInstanceBuilder(dokan);

                        builder.ConfigureOptions(opt =>
                        {
                            opt.MountPoint = MountPoint;
                            opt.Options = DokanOptions.DebugMode | DokanOptions.StderrOutput;
                            opt.Version = 230;
                            opt.TimeOut = TimeSpan.FromSeconds(30);
                            opt.AllocationUnitSize = 4096;
                            opt.SectorSize = 512;
                        });

                        dokanInstance = builder.Build(dokanOperations);
                    }
                    catch (Exception ex)
                    {
                        mountException = ex;
                        mountedEvent.Set();
                    }
                }, combinedCts.Token);

                bool completed = mountedEvent.Wait(30000, combinedCts.Token);

                if (combinedCts.Token.IsCancellationRequested)
                {
                    UpdateStatus(VfsStatus.Error, "Mount cancelled");
                    return false;
                }

                if (!completed)
                {
                    UpdateStatus(VfsStatus.Error, "Mount timeout");
                    return false;
                }

                if (mountException != null)
                {
                    UpdateStatus(VfsStatus.Error, $"Mount failed: {mountException.Message}");
                    return false;
                }

                if (isMountedSuccessfully)
                {
                    bool accessible = await VerifyMountPointAsync();
                    if (accessible)
                    {
                        UpdateStatus(VfsStatus.Mounted, $"Mounted to {MountPoint}");
                        return true;
                    }
                }

                UpdateStatus(VfsStatus.Error, "Mount verification failed");
                return false;
            }
            catch (Exception ex)
            {
                UpdateStatus(VfsStatus.Error, $"Mount exception: {ex.Message}");
                return false;
            }
            finally
            {
                isMountInProgress = false;
            }
        }

        public async Task<bool> UnmountAsync()
        {
            if (isDisposing) return true;

            // 先检查和设置状态
            lock (disposeLock)
            {
                if (isDisposing) return true;
                isDisposing = true;
            }

            try
            {
                UpdateStatus(VfsStatus.Unmounting, "Starting unmount");
                disposalCancellationTokenSource.Cancel();
                isMountedSuccessfully = false;
                isMountInProgress = false;

                // 在lock外面调用async方法
                return await UnmountInternalAsync();
            }
            catch
            {
                return false;
            }
        }

        public void ForceUnmount()
        {
            if (isDisposing) return;

            lock (disposeLock)
            {
                if (isDisposing) return;
                isDisposing = true;

                try
                {
                    UpdateStatus(VfsStatus.Unmounting, "Force unmounting");
                    disposalCancellationTokenSource.Cancel();
                    isMountedSuccessfully = false;
                    mountedEvent?.Set();

                    Task.Run(async () =>
                    {
                        try
                        {
                            if (dokanInstance != null)
                            {
                                var quickDisposeTask = Task.Run(() => { try { dokanInstance.Dispose(); } catch { } });
                                await Task.WhenAny(quickDisposeTask, Task.Delay(1000));
                                dokanInstance = null;
                            }

                            if (dokan != null)
                            {
                                var quickDokanTask = Task.Run(() => { try { dokan.Dispose(); } catch { } });
                                await Task.WhenAny(quickDokanTask, Task.Delay(500));
                                dokan = null;
                            }
                        }
                        catch { }
                    });

                    UpdateStatus(VfsStatus.Unmounted, "Force unmount completed");
                }
                catch { }
            }
        }

        public void SetVirtualData(byte[] data)
        {
            fileProvider.SetVirtualData(data);
            OnLogMessage($"Virtual data set: {data.Length} bytes");
        }

        public void SetMountPoint(string mountPoint)
        {
            MountPoint = mountPoint;
            OnLogMessage($"Mount point set to: {mountPoint}");
        }

        public void SetAccessMode(VfsAccessMode mode)
        {
            accessController.SetAccessMode(mode);
            OnLogMessage($"Access mode set to: {mode}");
        }

        public void AddAllowedProcess(string processName)
        {
            accessController.AddAllowedProcess(processName);
            OnLogMessage($"Added allowed process: {processName}");
        }

        private async Task<bool> VerifyMountPointAsync()
        {
            for (int i = 0; i < 5; i++)
            {
                try
                {
                    if (Directory.Exists(MountPoint))
                        return true;
                }
                catch { }
                await Task.Delay(500);
            }
            return false;
        }

        private async Task<bool> UnmountInternalAsync()
        {
            try
            {
                if (dokanInstance != null)
                {
                    var disposeTask = Task.Run(() => { try { dokanInstance.Dispose(); } catch { } });
                    await Task.WhenAny(disposeTask, Task.Delay(3000));
                    dokanInstance = null;
                }

                await Task.Delay(500);

                if (dokan != null && !string.IsNullOrEmpty(MountPoint))
                {
                    var unmountTask = Task.Run(() => { try { dokan.RemoveMountPoint(MountPoint); } catch { } });
                    await Task.WhenAny(unmountTask, Task.Delay(2000));
                }

                if (dokan != null)
                {
                    var dokanDisposeTask = Task.Run(() => { try { dokan.Dispose(); } catch { } });
                    await Task.WhenAny(dokanDisposeTask, Task.Delay(1000));
                    dokan = null;
                }

                UpdateStatus(VfsStatus.Unmounted, "Unmount completed");
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void OnMounted()
        {
            isMountedSuccessfully = true;
            mountedEvent.Set();
        }

        private void OnUnmounted()
        {
            isMountedSuccessfully = false;
        }

        private void UpdateStatus(VfsStatus status, string message = "")
        {
            currentStatus = status;
            StatusChanged?.Invoke(this, new VfsStatusEventArgs { Status = status, Message = message });
        }

        private void OnLogMessage(string message)
        {
            LogMessage?.Invoke(this, message);
        }

        public void Dispose()
        {
            ForceUnmount();
            mountedEvent?.Dispose();
            disposalCancellationTokenSource?.Dispose();
        }

        // ===== 兼容性方法 =====
        public bool MountVirtualFileSystem(byte[] decryptedData, CancellationToken cancellationToken)
        {
            SetVirtualData(decryptedData);
            return MountAsync(cancellationToken).GetAwaiter().GetResult();
        }

        public void UnmountVirtualFileSystem()
        {
            ForceUnmount();
        }
    }

    // =====================================================
    // 工厂类
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
    }
}