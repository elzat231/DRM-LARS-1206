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

namespace XPlaneActivator
{
    public enum VfsStatus
    {
        Mounting,
        Mounted,
        FileAccessed,
        Error,
        Unmounted
    }

    public class VfsStatusEventArgs : EventArgs
    {
        public VfsStatus Status { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class VirtualFileSystemManager : IDokanOperations, IDisposable
    {
        private byte[]? fuseObjData;
        private DokanInstance? dokanInstance;
        private Dokan? dokan;
        private readonly Dictionary<string, FileInformation> files;
        private readonly object lockObject = new object();
        private bool disposed = false;
        private CancellationToken cancellationToken;

        // Mount synchronization related fields
        private readonly ManualResetEventSlim mountedEvent = new ManualResetEventSlim(false);
        private volatile bool isMountedSuccessfully = false;
        private Exception? mountException = null;
        private volatile bool isMountInProgress = false;

        // Unmount related fields
        private readonly CancellationTokenSource disposalCancellationTokenSource = new CancellationTokenSource();
        private volatile bool isDisposing = false;
        private readonly object disposeLock = new object();

        public string MountPoint { get; private set; } = @"V:\";

        public event EventHandler<VfsStatusEventArgs>? StatusChanged;
        public event EventHandler<string>? LogMessage;

        public VirtualFileSystemManager()
        {
            files = new Dictionary<string, FileInformation>();
        }

        public bool MountVirtualFileSystem(byte[] decryptedData, CancellationToken token)
        {
            try
            {
                // Prevent duplicate mounting
                if (isMountInProgress)
                {
                    OnLogMessage(R.Get("VFSMountInProgress"));
                    return false;
                }

                isMountInProgress = true;
                cancellationToken = token;
                fuseObjData = decryptedData;

                // Reset status
                mountedEvent.Reset();
                isMountedSuccessfully = false;
                mountException = null;

                OnStatusChanged(VfsStatus.Mounting, R.Get("StartingVirtualFileSystem"));
                OnLogMessage(R.Get("VFSPreparing"));

                // Setup virtual files
                SetupVirtualFiles();

                // Create combined cancellation token
                using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(
                    token,
                    disposalCancellationTokenSource.Token
                );

                // Start Dokan in background thread
                Task.Run(() =>
                {
                    try
                    {
                        OnLogMessage(R.GetFormatted("VFSMountingToPoint", MountPoint));
                        OnStatusChanged(VfsStatus.Mounting, R.GetFormatted("VFSMountingToPoint", MountPoint));

                        // Create Dokan logger
                        var dokanLogger = new SimpleDokanLogger();

                        // Create Dokan instance
                        dokan = new Dokan(dokanLogger);

                        // Create Dokan instance builder
                        var builder = new DokanInstanceBuilder(dokan);

                        // Configure Dokan options
                        builder.ConfigureOptions(opt =>
                        {
                            opt.MountPoint = MountPoint;
                            opt.Options = DokanOptions.DebugMode | DokanOptions.StderrOutput;
                            opt.Version = 230; // Dokan 2.3.0
                            opt.TimeOut = TimeSpan.FromSeconds(30);
                            opt.AllocationUnitSize = 4096;
                            opt.SectorSize = 512;
                        });

                        // Build Dokan instance - this is a blocking call
                        dokanInstance = builder.Build(this);

                        // If we reach here without exception, Dokan started successfully
                        // But actual mount completion will be confirmed in Mounted callback
                        OnLogMessage(R.Get("VFSDokanInstanceCreated"));
                    }
                    catch (DokanException ex)
                    {
                        mountException = ex;
                        OnLogMessage(R.GetFormatted("VFSDokanError", ex.Message));
                        OnStatusChanged(VfsStatus.Error, R.GetFormatted("VFSDokanError", ex.Message));
                        mountedEvent.Set(); // Ensure main thread doesn't wait indefinitely
                    }
                    catch (Exception ex)
                    {
                        mountException = ex;
                        OnLogMessage(R.GetFormatted("VFSSystemError", ex.Message));
                        OnStatusChanged(VfsStatus.Error, R.GetFormatted("VFSSystemError", ex.Message));
                        mountedEvent.Set(); // Ensure main thread doesn't wait indefinitely
                    }
                }, combinedCts.Token);

                // Wait for mount completion, support cancellation
                OnLogMessage(R.Get("VFSWaitingForMount"));
                bool completed = mountedEvent.Wait(30000, combinedCts.Token);

                if (combinedCts.Token.IsCancellationRequested)
                {
                    OnStatusChanged(VfsStatus.Error, R.Get("VFSMountCancelled"));
                    OnLogMessage(R.Get("VFSMountCancelled"));
                    return false;
                }

                if (!completed)
                {
                    OnStatusChanged(VfsStatus.Error, R.Get("VFSMountTimeout"));
                    OnLogMessage(R.Get("VFSMountTimeout"));
                    return false;
                }

                // Check for exceptions
                if (mountException != null)
                {
                    OnStatusChanged(VfsStatus.Error, R.GetFormatted("VFSMountFailed", mountException.Message));
                    OnLogMessage(R.GetFormatted("VFSMountException", mountException.Message));
                    return false;
                }

                // Check if successfully mounted
                if (isMountedSuccessfully)
                {
                    // Final verification that mount point is accessible
                    bool mountPointExists = false;
                    for (int i = 0; i < 5; i++) // Retry up to 5 times
                    {
                        try
                        {
                            if (Directory.Exists(MountPoint))
                            {
                                mountPointExists = true;
                                break;
                            }
                        }
                        catch
                        {
                            // Ignore exception, continue retry
                        }
                        Thread.Sleep(500); // Wait 500ms before retry
                    }

                    if (mountPointExists)
                    {
                        OnStatusChanged(VfsStatus.Mounted, R.Get("VFSMountSuccess"));
                        OnLogMessage(R.VFSMountedSuccess(MountPoint));
                        return true;
                    }
                    else
                    {
                        OnStatusChanged(VfsStatus.Error, R.Get("VFSMountPointVerificationFailed"));
                        OnLogMessage(R.Get("VFSMountCompletedButInaccessible"));
                        return false;
                    }
                }
                else
                {
                    OnStatusChanged(VfsStatus.Error, R.Get("VFSMountNotCompleted"));
                    OnLogMessage(R.Get("VFSMountProcessNotCompleted"));
                    return false;
                }
            }
            catch (OperationCanceledException)
            {
                OnStatusChanged(VfsStatus.Error, R.Get("VFSMountCancelled"));
                OnLogMessage(R.Get("VFSMountOperationCancelled"));
                return false;
            }
            catch (Exception ex)
            {
                OnStatusChanged(VfsStatus.Error, R.GetFormatted("VFSMountFailed", ex.Message));
                OnLogMessage(R.GetFormatted("VFSMountError", ex.Message));
                return false;
            }
            finally
            {
                isMountInProgress = false;
            }
        }

        public void UnmountVirtualFileSystem()
        {
            if (isDisposing) return;

            lock (disposeLock)
            {
                if (isDisposing) return;
                isDisposing = true;

                try
                {
                    OnLogMessage(R.Get("VFSUnmounting"));

                    // Cancel all waiting operations
                    disposalCancellationTokenSource.Cancel();

                    // Reset mount status
                    isMountedSuccessfully = false;
                    isMountInProgress = false;

                    // Async unmount to avoid blocking main thread
                    Task.Run(() => UnmountAsync()).Wait(5000); // Wait max 5 seconds
                }
                catch (Exception ex)
                {
                    OnLogMessage(R.GetFormatted("VFSUnmountError", ex.Message));
                }
            }
        }

        private async Task UnmountAsync()
        {
            try
            {
                // If has Dokan instance, try normal release
                if (dokanInstance != null)
                {
                    OnLogMessage(R.Get("VFSReleasingDokanInstance"));

                    // Set timeout task
                    var disposeTask = Task.Run(() =>
                    {
                        try
                        {
                            dokanInstance.Dispose();
                        }
                        catch (Exception ex)
                        {
                            OnLogMessage(R.GetFormatted("VFSDokanInstanceDisposeError", ex.Message));
                        }
                    });

                    // Wait max 3 seconds
                    if (await Task.WhenAny(disposeTask, Task.Delay(3000)) == disposeTask)
                    {
                        OnLogMessage(R.Get("VFSDokanInstanceReleased"));
                    }
                    else
                    {
                        OnLogMessage(R.Get("VFSDokanInstanceDisposeTimeout"));
                    }

                    dokanInstance = null;
                }

                // Brief wait for resource release
                await Task.Delay(500);

                // Try using Dokan API to force unmount
                if (dokan != null && !string.IsNullOrEmpty(MountPoint))
                {
                    try
                    {
                        OnLogMessage(R.GetFormatted("VFSRemovingMountPoint", MountPoint));

                        var unmountTask = Task.Run(() =>
                        {
                            try
                            {
                                dokan.RemoveMountPoint(MountPoint);
                            }
                            catch (Exception ex)
                            {
                                OnLogMessage(R.GetFormatted("VFSRemoveMountPointError", ex.Message));
                            }
                        });

                        // Wait max 2 seconds
                        if (await Task.WhenAny(unmountTask, Task.Delay(2000)) == unmountTask)
                        {
                            OnLogMessage(R.Get("VFSMountPointRemoved"));
                        }
                        else
                        {
                            OnLogMessage(R.Get("VFSMountPointRemoveTimeout"));
                        }
                    }
                    catch (Exception ex)
                    {
                        OnLogMessage(R.GetFormatted("VFSRemoveMountPointError", ex.Message));
                    }
                }

                // Release Dokan object
                if (dokan != null)
                {
                    try
                    {
                        var dokanDisposeTask = Task.Run(() =>
                        {
                            try
                            {
                                dokan.Dispose();
                            }
                            catch (Exception ex)
                            {
                                OnLogMessage(R.GetFormatted("VFSDokanObjectDisposeError", ex.Message));
                            }
                        });

                        // Wait max 1 second
                        if (await Task.WhenAny(dokanDisposeTask, Task.Delay(1000)) == dokanDisposeTask)
                        {
                            OnLogMessage(R.Get("VFSDokanObjectReleased"));
                        }
                        else
                        {
                            OnLogMessage(R.Get("VFSDokanObjectDisposeTimeout"));
                        }

                        dokan = null;
                    }
                    catch (Exception ex)
                    {
                        OnLogMessage(R.GetFormatted("VFSDokanObjectDisposeError", ex.Message));
                    }
                }

                OnStatusChanged(VfsStatus.Unmounted, R.Get("VFSUnmounted"));
                OnLogMessage(R.Get("VFSUnmountedSuccess"));
            }
            catch (Exception ex)
            {
                OnLogMessage(R.GetFormatted("VFSAsyncUnmountError", ex.Message));
            }
        }

        /// <summary>
        /// Force unmount, used when program closes
        /// </summary>
        private void ForceUnmount()
        {
            if (isDisposing) return;

            lock (disposeLock)
            {
                if (isDisposing) return;
                isDisposing = true;

                try
                {
                    OnLogMessage(R.Get("VFSForceUnmounting"));

                    // Cancel all waiting operations
                    disposalCancellationTokenSource.Cancel();

                    // Set status
                    isMountedSuccessfully = false;
                    mountedEvent?.Set(); // Release any waiting threads

                    // Quick resource release, don't wait
                    Task.Run(async () =>
                    {
                        try
                        {
                            // Try quick release, max 1 second
                            if (dokanInstance != null)
                            {
                                var quickDisposeTask = Task.Run(() =>
                                {
                                    try { dokanInstance.Dispose(); } catch { }
                                });
                                await Task.WhenAny(quickDisposeTask, Task.Delay(1000));
                                dokanInstance = null;
                            }

                            if (dokan != null)
                            {
                                var quickDokanTask = Task.Run(() =>
                                {
                                    try { dokan.Dispose(); } catch { }
                                });
                                await Task.WhenAny(quickDokanTask, Task.Delay(500));
                                dokan = null;
                            }
                        }
                        catch
                        {
                            // Ignore all exceptions
                        }
                    });

                    OnLogMessage(R.Get("VFSForceUnmountComplete"));
                }
                catch
                {
                    // Ignore all exceptions
                }
            }
        }

        private void SetupVirtualFiles()
        {
            lock (lockObject)
            {
                files.Clear();

                // Root directory
                files[@"\"] = new FileInformation
                {
                    FileName = @"\",
                    Attributes = FileAttributes.Directory,
                    CreationTime = DateTime.Now,
                    LastAccessTime = DateTime.Now,
                    LastWriteTime = DateTime.Now,
                    Length = 0
                };

                // Fuse 1.obj file
                files[@"\Fuse 1.obj"] = new FileInformation
                {
                    FileName = "Fuse 1.obj",
                    Attributes = FileAttributes.Normal,
                    CreationTime = DateTime.Now,
                    LastAccessTime = DateTime.Now,
                    LastWriteTime = DateTime.Now,
                    Length = fuseObjData?.Length ?? 0
                };

                OnLogMessage(R.GetFormatted("VFSSetupVirtualFiles", fuseObjData?.Length ?? 0));
            }
        }

        private bool IsXPlaneProcess()
        {
            try
            {
                // Check calling process name
                var processes = Process.GetProcesses();
                var xplaneProcess = processes.FirstOrDefault(p =>
                    p.ProcessName.ToLower().Contains("x-plane") ||
                    p.ProcessName.ToLower().Contains("xplane"));

                if (xplaneProcess != null)
                {
                    OnLogMessage(R.GetFormatted("VFSFoundXPlaneProcess", xplaneProcess.ProcessName));
                    return true;
                }

                // For demonstration, allow all access for now
                return true;
            }
            catch (Exception ex)
            {
                OnLogMessage(R.GetFormatted("VFSProcessCheckError", ex.Message));
                return false;
            }
        }

        // IDokanOperations implementation
        public NtStatus CreateFile(string fileName, DokanNet.FileAccess access, FileShare share, FileMode mode, FileOptions options, FileAttributes attributes, IDokanFileInfo info)
        {
            try
            {
                if (!IsXPlaneProcess())
                {
                    OnLogMessage(R.GetFormatted("VFSAccessDenied", fileName));
                    return NtStatus.AccessDenied;
                }

                OnLogMessage(R.GetFormatted("VFSFileAccessRequest", fileName));
                OnStatusChanged(VfsStatus.FileAccessed, R.GetFormatted("VFSFileAccessRequest", fileName));

                lock (lockObject)
                {
                    if (files.ContainsKey(fileName))
                    {
                        var fileInfo = files[fileName];
                        info.IsDirectory = fileInfo.Attributes.HasFlag(FileAttributes.Directory);
                        OnLogMessage(R.GetFormatted("VFSFileAccessSuccess", fileName));
                        return NtStatus.Success;
                    }
                }

                OnLogMessage(R.GetFormatted("VFSFileNotExists", fileName));
                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                OnLogMessage(R.GetFormatted("VFSCreateFileError", ex.Message));
                return NtStatus.InternalError;
            }
        }

        public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
        {
            bytesRead = 0;

            try
            {
                OnLogMessage(R.GetFormatted("VFSReadFileRequest", fileName, offset, buffer.Length));

                if (fileName == @"\Fuse 1.obj" && fuseObjData != null)
                {
                    int startIndex = (int)Math.Min(offset, fuseObjData.Length);
                    int lengthToRead = Math.Min(buffer.Length, fuseObjData.Length - startIndex);

                    if (lengthToRead > 0)
                    {
                        Array.Copy(fuseObjData, startIndex, buffer, 0, lengthToRead);
                        bytesRead = lengthToRead;
                        OnLogMessage(R.GetFormatted("VFSReadSuccess", bytesRead, fileName));
                        OnStatusChanged(VfsStatus.FileAccessed, R.GetFormatted("VFSReadBytesInfo", bytesRead));
                        return NtStatus.Success;
                    }
                }

                OnLogMessage(R.GetFormatted("VFSCannotReadFile", fileName));
                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                OnLogMessage(R.GetFormatted("VFSReadFileError", ex.Message));
                return NtStatus.InternalError;
            }
        }

        public NtStatus GetFileInformation(string fileName, out FileInformation fileInfo, IDokanFileInfo info)
        {
            fileInfo = default(FileInformation);

            try
            {
                lock (lockObject)
                {
                    if (files.ContainsKey(fileName))
                    {
                        fileInfo = files[fileName];
                        OnLogMessage(R.GetFormatted("VFSGetFileInfo", fileName));
                        return NtStatus.Success;
                    }
                }

                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                OnLogMessage(R.GetFormatted("VFSGetFileInfoError", ex.Message));
                return NtStatus.InternalError;
            }
        }

        public NtStatus FindFiles(string fileName, out IList<FileInformation> files, IDokanFileInfo info)
        {
            files = new List<FileInformation>();

            try
            {
                OnLogMessage(R.GetFormatted("VFSFindFilesRequest", fileName));

                lock (lockObject)
                {
                    if (fileName == @"\")
                    {
                        foreach (var file in this.files.Values)
                        {
                            if (file.FileName != @"\" && !file.FileName.Contains(@"\", StringComparison.Ordinal))
                            {
                                files.Add(file);
                            }
                        }
                        OnLogMessage(R.GetFormatted("VFSFoundFiles", files.Count));
                        return NtStatus.Success;
                    }
                }

                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                OnLogMessage(R.GetFormatted("VFSFindFilesError", ex.Message));
                return NtStatus.InternalError;
            }
        }

        public NtStatus FindFilesWithPattern(string fileName, string searchPattern, out IList<FileInformation> files, IDokanFileInfo info)
        {
            files = new List<FileInformation>();

            try
            {
                OnLogMessage(R.GetFormatted("VFSFindFilesWithPattern", fileName, searchPattern));

                lock (lockObject)
                {
                    if (fileName == @"\")
                    {
                        foreach (var file in this.files.Values)
                        {
                            if (file.FileName != @"\" && !file.FileName.Contains(@"\", StringComparison.Ordinal))
                            {
                                // Simple pattern matching
                                if (searchPattern == "*" ||
                                    searchPattern == "*.*" ||
                                    file.FileName.Contains(searchPattern.Replace("*", ""), StringComparison.OrdinalIgnoreCase))
                                {
                                    files.Add(file);
                                }
                            }
                        }
                        OnLogMessage(R.GetFormatted("VFSFoundMatchingFiles", files.Count));
                        return NtStatus.Success;
                    }
                }

                return NtStatus.ObjectNameNotFound;
            }
            catch (Exception ex)
            {
                OnLogMessage(R.GetFormatted("VFSFindFilesWithPatternError", ex.Message));
                return NtStatus.InternalError;
            }
        }

        // Key: Dokan mount completion callback
        public NtStatus Mounted(string mountPoint, IDokanFileInfo info)
        {
            OnLogMessage(R.GetFormatted("VFSMountedToPoint", mountPoint));
            OnStatusChanged(VfsStatus.Mounted, R.Get("VFSMounted"));

            // Set mount success flag and release waiting threads
            isMountedSuccessfully = true;
            mountedEvent.Set();

            return NtStatus.Success;
        }

        public NtStatus Unmounted(IDokanFileInfo info)
        {
            OnLogMessage(R.Get("VFSUnmountedFromPoint"));
            OnStatusChanged(VfsStatus.Unmounted, R.Get("VFSUnmounted"));

            // Reset mount status
            isMountedSuccessfully = false;

            return NtStatus.Success;
        }

        // Other IDokanOperations method implementations
        public void Cleanup(string fileName, IDokanFileInfo info) { }
        public void CloseFile(string fileName, IDokanFileInfo info) { }

        public NtStatus WriteFile(string fileName, byte[] buffer, out int bytesWritten, long offset, IDokanFileInfo info)
        {
            bytesWritten = 0;
            return NtStatus.AccessDenied; // Read-only file system
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

        private void OnStatusChanged(VfsStatus status, string message)
        {
            StatusChanged?.Invoke(this, new VfsStatusEventArgs { Status = status, Message = message });
        }

        private void OnLogMessage(string message)
        {
            LogMessage?.Invoke(this, message);
        }

        public void Dispose()
        {
            if (!disposed)
            {
                // Force unmount, don't wait
                ForceUnmount();

                // Release other resources
                try
                {
                    mountedEvent?.Dispose();
                    disposalCancellationTokenSource?.Dispose();
                }
                catch
                {
                    // Ignore release exceptions
                }

                disposed = true;
            }
        }
    }

    /// <summary>
    /// Simple Dokan logger implementation
    /// </summary>
    internal class SimpleDokanLogger : ILogger
    {
        public bool DebugEnabled => true;

        public void Debug(string format, params object[] args)
        {
            System.Diagnostics.Debug.WriteLine($"[Dokan Debug] {string.Format(format, args)}");
        }

        public void Info(string format, params object[] args)
        {
            System.Diagnostics.Debug.WriteLine($"[Dokan Info] {string.Format(format, args)}");
        }

        public void Warn(string format, params object[] args)
        {
            System.Diagnostics.Debug.WriteLine($"[Dokan Warn] {string.Format(format, args)}");
        }

        public void Error(string format, params object[] args)
        {
            System.Diagnostics.Debug.WriteLine($"[Dokan Error] {string.Format(format, args)}");
        }

        public void Fatal(string format, params object[] args)
        {
            System.Diagnostics.Debug.WriteLine($"[Dokan Fatal] {string.Format(format, args)}");
        }
    }
}