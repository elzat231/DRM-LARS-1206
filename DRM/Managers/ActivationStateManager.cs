using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace XPlaneActivator
{
    /// <summary>
    /// Activation State Manager - Responsible for persisting and managing activation state
    /// </summary>
    public class ActivationStateManager
    {
        private readonly string stateFilePath;
        private ActivationState? currentState;

        public ActivationStateManager()
        {
            string appDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "XPlaneActivator");
            Directory.CreateDirectory(appDataDir);
            stateFilePath = Path.Combine(appDataDir, "activation_state.json");
        }

        /// <summary>
        /// Get current activation state
        /// </summary>
        /// <returns>Activation state, returns null if not activated</returns>
        public ActivationState? GetCurrentState()
        {
            if (currentState != null)
                return currentState;

            try
            {
                if (File.Exists(stateFilePath))
                {
                    string json = File.ReadAllText(stateFilePath);
                    var state = JsonSerializer.Deserialize<ActivationState>(json);

                    // Verify state is still valid
                    if (state != null && IsStateValid(state))
                    {
                        currentState = state;
                        return state;
                    }
                    else
                    {
                        // State invalid, delete file
                        ClearActivationState();
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ActivationStateManager] {R.GetFormatted("ReadingStateFailed", ex.Message)}");
                // If reading fails, delete potentially corrupted file
                ClearActivationState();
            }

            return null;
        }

        /// <summary>
        /// Save activation state
        /// </summary>
        /// <param name="activationCode">Activation code</param>
        /// <param name="serverToken">Server token (if any)</param>
        /// <param name="mountPoint">Mount point</param>
        /// <returns>Whether save was successful</returns>
        public bool SaveActivationState(string activationCode, string? serverToken = null, string? mountPoint = null)
        {
            try
            {
                var state = new ActivationState
                {
                    ActivationCode = activationCode,
                    ServerToken = serverToken,
                    MountPoint = mountPoint,
                    ActivationTime = DateTime.Now,
                    MachineFingerprint = HardwareIdHelper.GetMachineFingerprint(),
                    IsActivated = true,
                    LastHeartbeat = DateTime.Now
                };

                string json = JsonSerializer.Serialize(state, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                File.WriteAllText(stateFilePath, json);
                currentState = state;

                System.Diagnostics.Debug.WriteLine($"[ActivationStateManager] {R.Get("ActivationStateSaved")}");
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ActivationStateManager] {R.GetFormatted("SavingStateFailed", ex.Message)}");
                return false;
            }
        }

        /// <summary>
        /// Update heartbeat time
        /// </summary>
        public void UpdateHeartbeat()
        {
            if (currentState != null)
            {
                currentState.LastHeartbeat = DateTime.Now;
                try
                {
                    string json = JsonSerializer.Serialize(currentState, new JsonSerializerOptions
                    {
                        WriteIndented = true
                    });
                    File.WriteAllText(stateFilePath, json);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[ActivationStateManager] {R.GetFormatted("UpdateHeartbeatFailed", ex.Message)}");
                }
            }
        }

        /// <summary>
        /// Clear activation state
        /// </summary>
        public void ClearActivationState()
        {
            try
            {
                if (File.Exists(stateFilePath))
                {
                    File.Delete(stateFilePath);
                }
                currentState = null;
                System.Diagnostics.Debug.WriteLine($"[ActivationStateManager] {R.Get("ActivationStateCleared")}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ActivationStateManager] {R.GetFormatted("ClearingStateFailed", ex.Message)}");
            }
        }

        /// <summary>
        /// Check if activation state is valid
        /// </summary>
        /// <param name="state">State to check</param>
        /// <returns>Whether it's valid</returns>
        private bool IsStateValid(ActivationState state)
        {
            try
            {
                // Check if activated
                if (!state.IsActivated)
                    return false;

                // Check if machine fingerprint matches
                string currentFingerprint = HardwareIdHelper.GetMachineFingerprint();
                if (state.MachineFingerprint != currentFingerprint)
                {
                    System.Diagnostics.Debug.WriteLine($"[ActivationStateManager] {R.Get("MachineFingerprintMismatch")}");
                    return false;
                }

                // Check if activation time is too old (e.g., 30 days)
                if ((DateTime.Now - state.ActivationTime).TotalDays > 30)
                {
                    System.Diagnostics.Debug.WriteLine($"[ActivationStateManager] {R.Get("ActivationExpiredMessage")}");
                    return false;
                }

                // Check if last heartbeat is too old (e.g., 1 day)
                if ((DateTime.Now - state.LastHeartbeat).TotalDays > 1)
                {
                    System.Diagnostics.Debug.WriteLine($"[ActivationStateManager] {R.Get("HeartbeatTimeout")}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ActivationStateManager] {R.GetFormatted("StateValidationException", ex.Message)}");
                return false;
            }
        }

        /// <summary>
        /// Check if revalidation is needed
        /// </summary>
        /// <returns>Whether revalidation is needed</returns>
        public bool ShouldRevalidate()
        {
            var state = GetCurrentState();
            if (state == null)
                return true;

            // If last heartbeat is over 1 day, need revalidation
            return (DateTime.Now - state.LastHeartbeat).TotalDays > 1;
        }

        /// <summary>
        /// Get remaining activation days
        /// </summary>
        /// <returns>Remaining days, returns 0 if not activated</returns>
        public int GetRemainingDays()
        {
            var state = GetCurrentState();
            if (state == null)
                return 0;

            int totalDays = 30; // Assume activation valid for 30 days
            int usedDays = (int)(DateTime.Now - state.ActivationTime).TotalDays;
            return Math.Max(0, totalDays - usedDays);
        }
    }

    /// <summary>
    /// Activation state data structure
    /// </summary>
    public class ActivationState
    {
        public string ActivationCode { get; set; } = string.Empty;
        public string? ServerToken { get; set; }
        public string? MountPoint { get; set; }
        public DateTime ActivationTime { get; set; }
        public DateTime LastHeartbeat { get; set; }
        public string MachineFingerprint { get; set; } = string.Empty;
        public bool IsActivated { get; set; }
    }
}