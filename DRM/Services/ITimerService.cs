using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace DRM.Services
{
    /// <summary>
    /// Timer service interface for managing application timers
    /// </summary>
    public interface ITimerService : IDisposable
    {
        /// <summary>
        /// Start a named timer with specified interval and callback
        /// </summary>
        /// <param name="name">Timer name</param>
        /// <param name="interval">Timer interval</param>
        /// <param name="callback">Callback action</param>
        /// <returns>True if timer started successfully</returns>
        bool StartTimer(string name, TimeSpan interval, Action callback);

        /// <summary>
        /// Start a named timer with async callback
        /// </summary>
        /// <param name="name">Timer name</param>
        /// <param name="interval">Timer interval</param>
        /// <param name="asyncCallback">Async callback function</param>
        /// <returns>True if timer started successfully</returns>
        bool StartAsyncTimer(string name, TimeSpan interval, Func<Task> asyncCallback);

        /// <summary>
        /// Stop a specific timer
        /// </summary>
        /// <param name="name">Timer name</param>
        /// <returns>True if timer stopped successfully</returns>
        bool StopTimer(string name);

        /// <summary>
        /// Stop all running timers
        /// </summary>
        void StopAllTimers();

        /// <summary>
        /// Check if a timer is running
        /// </summary>
        /// <param name="name">Timer name</param>
        /// <returns>True if timer is running</returns>
        bool IsTimerRunning(string name);

        /// <summary>
        /// Get the interval of a running timer
        /// </summary>
        /// <param name="name">Timer name</param>
        /// <returns>Timer interval, null if timer not found</returns>
        TimeSpan? GetTimerInterval(string name);

        /// <summary>
        /// Get count of active timers
        /// </summary>
        int ActiveTimerCount { get; }
    }

    /// <summary>
    /// Timer service implementation
    /// </summary>
    public class TimerService : ITimerService
    {
        private readonly ConcurrentDictionary<string, TimerInfo> _timers;
        private readonly object _lock = new object();
        private bool _disposed = false;

        public TimerService()
        {
            _timers = new ConcurrentDictionary<string, TimerInfo>();
        }

        public int ActiveTimerCount => _timers.Count;

        public bool StartTimer(string name, TimeSpan interval, Action callback)
        {
            if (string.IsNullOrEmpty(name) || callback == null || interval <= TimeSpan.Zero)
                return false;

            if (_disposed)
                return false;

            lock (_lock)
            {
                // Stop existing timer with same name
                if (_timers.ContainsKey(name))
                {
                    StopTimer(name);
                }

                try
                {
                    var timer = new Timer(state =>
                    {
                        try
                        {
                            callback();
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"[TimerService] Timer '{name}' callback exception: {ex.Message}");
                        }
                    }, null, TimeSpan.Zero, interval);

                    var timerInfo = new TimerInfo
                    {
                        Name = name,
                        Timer = timer,
                        Interval = interval,
                        Callback = callback,
                        IsAsync = false,
                        StartTime = DateTime.Now
                    };

                    _timers.TryAdd(name, timerInfo);
                    System.Diagnostics.Debug.WriteLine($"[TimerService] Started timer '{name}' with interval {interval.TotalSeconds}s");
                    return true;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[TimerService] Failed to start timer '{name}': {ex.Message}");
                    return false;
                }
            }
        }

        public bool StartAsyncTimer(string name, TimeSpan interval, Func<Task> asyncCallback)
        {
            if (string.IsNullOrEmpty(name) || asyncCallback == null || interval <= TimeSpan.Zero)
                return false;

            if (_disposed)
                return false;

            lock (_lock)
            {
                // Stop existing timer with same name
                if (_timers.ContainsKey(name))
                {
                    StopTimer(name);
                }

                try
                {
                    var timer = new Timer(async state =>
                    {
                        try
                        {
                            await asyncCallback();
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"[TimerService] Async timer '{name}' callback exception: {ex.Message}");
                        }
                    }, null, TimeSpan.Zero, interval);

                    var timerInfo = new TimerInfo
                    {
                        Name = name,
                        Timer = timer,
                        Interval = interval,
                        AsyncCallback = asyncCallback,
                        IsAsync = true,
                        StartTime = DateTime.Now
                    };

                    _timers.TryAdd(name, timerInfo);
                    System.Diagnostics.Debug.WriteLine($"[TimerService] Started async timer '{name}' with interval {interval.TotalSeconds}s");
                    return true;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[TimerService] Failed to start async timer '{name}': {ex.Message}");
                    return false;
                }
            }
        }

        public bool StopTimer(string name)
        {
            if (string.IsNullOrEmpty(name))
                return false;

            if (_timers.TryRemove(name, out TimerInfo? timerInfo))
            {
                try
                {
                    timerInfo.Timer?.Dispose();
                    System.Diagnostics.Debug.WriteLine($"[TimerService] Stopped timer '{name}'");
                    return true;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[TimerService] Error stopping timer '{name}': {ex.Message}");
                    return false;
                }
            }

            return false;
        }

        public void StopAllTimers()
        {
            lock (_lock)
            {
                var timerNames = new string[_timers.Keys.Count];
                _timers.Keys.CopyTo(timerNames, 0);

                foreach (string name in timerNames)
                {
                    StopTimer(name);
                }

                System.Diagnostics.Debug.WriteLine("[TimerService] All timers stopped");
            }
        }

        public bool IsTimerRunning(string name)
        {
            if (string.IsNullOrEmpty(name))
                return false;

            return _timers.ContainsKey(name);
        }

        public TimeSpan? GetTimerInterval(string name)
        {
            if (string.IsNullOrEmpty(name))
                return null;

            return _timers.TryGetValue(name, out TimerInfo? timerInfo) ? timerInfo.Interval : null;
        }

        /// <summary>
        /// Get timer information (for debugging)
        /// </summary>
        /// <param name="name">Timer name</param>
        /// <returns>Timer information or null if not found</returns>
        public TimerInfo? GetTimerInfo(string name)
        {
            if (string.IsNullOrEmpty(name))
                return null;

            return _timers.TryGetValue(name, out TimerInfo? timerInfo) ? timerInfo : null;
        }

        /// <summary>
        /// Get all timer names
        /// </summary>
        /// <returns>Array of timer names</returns>
        public string[] GetAllTimerNames()
        {
            var names = new string[_timers.Keys.Count];
            _timers.Keys.CopyTo(names, 0);
            return names;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                StopAllTimers();
                _disposed = true;
                System.Diagnostics.Debug.WriteLine("[TimerService] Disposed");
            }
        }

        /// <summary>
        /// Timer information class
        /// </summary>
        public class TimerInfo
        {
            public string Name { get; set; } = string.Empty;
            public Timer? Timer { get; set; }
            public TimeSpan Interval { get; set; }
            public Action? Callback { get; set; }
            public Func<Task>? AsyncCallback { get; set; }
            public bool IsAsync { get; set; }
            public DateTime StartTime { get; set; }

            public TimeSpan RunningTime => DateTime.Now - StartTime;
        }
    }

    /// <summary>
    /// Timer service factory
    /// </summary>
    public static class TimerServiceFactory
    {
        /// <summary>
        /// Create a new timer service instance
        /// </summary>
        /// <returns>New timer service</returns>
        public static ITimerService Create()
        {
            return new TimerService();
        }

        /// <summary>
        /// Create a timer service with predefined common timers for X-Plane Activator
        /// </summary>
        /// <returns>Timer service with common timers setup</returns>
        public static ITimerService CreateForXPlaneActivator()
        {
            var timerService = new TimerService();

            // Note: Actual timer callbacks would be set up by the calling code
            // This is just the service ready for use

            System.Diagnostics.Debug.WriteLine("[TimerServiceFactory] Created X-Plane Activator timer service");
            return timerService;
        }
    }
}