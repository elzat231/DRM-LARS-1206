// =====================================================
// Fixed UIController.cs with English UI and null-safety
// =====================================================
using System;
using System.Windows;
using System.Windows.Media;

namespace XPlaneActivator.Services
{
    public interface IUIController
    {
        void UpdateActivationUI(bool isActivated, ActivationState? state);
        void UpdateStatus(string status);
        void AddLog(string message);
        void ShowMessage(string message, string title, bool isError = false);
        bool ConfirmAction(string message, string title);
    }

    public class UIController : IUIController
    {
        private readonly MainWindow mainWindow;

        public UIController(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
        }

        public void UpdateActivationUI(bool isActivated, ActivationState? state)
        {
            mainWindow.Dispatcher.Invoke(() =>
            {
                if (isActivated && state != null)
                {
                    // Activated state
                    mainWindow.btnActivate.Content = "Activated";
                    mainWindow.btnActivate.IsEnabled = false;

                    // Show activation information
                    int remainingDays = 30 - (int)(DateTime.Now - state.ActivationTime).TotalDays;
                    mainWindow.txtActivationCode.Text = $"Activated - {remainingDays} days remaining";
                    mainWindow.txtActivationCode.IsEnabled = false;

                    // Show deactivate button
                    if (mainWindow.btnDeactivate != null)
                    {
                        mainWindow.btnDeactivate.IsEnabled = true;
                        mainWindow.btnDeactivate.Visibility = Visibility.Visible;
                    }

                    // Show activation info button
                    if (mainWindow.btnActivationInfo != null)
                    {
                        mainWindow.btnActivationInfo.IsEnabled = true;
                        mainWindow.btnActivationInfo.Visibility = Visibility.Visible;
                    }

                    // Update VFS status
                    mainWindow.lblVfsStatus.Text = $"Virtual File System mounted to {state.MountPoint}";
                    mainWindow.lblVfsStatus.Foreground = new SolidColorBrush(Colors.LightGreen);

                    // Show activation status information - Fixed with null checking
                    if (mainWindow.lblActivationStatusTitle != null)
                    {
                        mainWindow.lblActivationStatusTitle.Visibility = Visibility.Visible;
                    }

                    if (mainWindow.spActivationInfo != null)
                    {
                        mainWindow.spActivationInfo.Visibility = Visibility.Visible;

                        // Update activation details with null checking
                        if (mainWindow.lblActivationTime != null)
                        {
                            mainWindow.lblActivationTime.Text = $"Activation Time: {state.ActivationTime:yyyy-MM-dd HH:mm:ss}";
                        }

                        if (mainWindow.lblRemainingDays != null)
                        {
                            mainWindow.lblRemainingDays.Text = $"Remaining Days: {remainingDays} days";
                        }

                        if (mainWindow.lblLastHeartbeat != null)
                        {
                            var timeSinceHeartbeat = DateTime.Now - state.LastHeartbeat;
                            string heartbeatText = timeSinceHeartbeat.TotalMinutes < 1
                                ? "Last Heartbeat: Just now"
                                : $"Last Heartbeat: {(int)timeSinceHeartbeat.TotalMinutes} minutes ago";
                            mainWindow.lblLastHeartbeat.Text = heartbeatText;
                        }
                    }
                }
                else
                {
                    // Not activated state
                    mainWindow.btnActivate.Content = "Online Activation";
                    mainWindow.btnActivate.IsEnabled = true;

                    mainWindow.txtActivationCode.Text = "";
                    mainWindow.txtActivationCode.IsEnabled = true;
                    mainWindow.txtActivationCode.Focus();

                    // Hide deactivate button
                    if (mainWindow.btnDeactivate != null)
                    {
                        mainWindow.btnDeactivate.IsEnabled = false;
                        mainWindow.btnDeactivate.Visibility = Visibility.Collapsed;
                    }

                    // Hide activation info button
                    if (mainWindow.btnActivationInfo != null)
                    {
                        mainWindow.btnActivationInfo.IsEnabled = false;
                        mainWindow.btnActivationInfo.Visibility = Visibility.Collapsed;
                    }

                    // Update VFS status
                    mainWindow.lblVfsStatus.Text = "Virtual File System not mounted";
                    mainWindow.lblVfsStatus.Foreground = new SolidColorBrush(Colors.Gray);

                    // Hide activation status information
                    if (mainWindow.lblActivationStatusTitle != null)
                    {
                        mainWindow.lblActivationStatusTitle.Visibility = Visibility.Collapsed;
                    }

                    if (mainWindow.spActivationInfo != null)
                    {
                        mainWindow.spActivationInfo.Visibility = Visibility.Collapsed;
                    }
                }
            });
        }

        public void UpdateStatus(string status)
        {
            mainWindow.Dispatcher.Invoke(() =>
            {
                mainWindow.lblStatus.Text = status;
            });
        }

        public void AddLog(string message)
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            string logEntry = $"[{timestamp}] {message}\r\n";

            mainWindow.Dispatcher.Invoke(() =>
            {
                mainWindow.txtActivationLog.AppendText(logEntry);
                mainWindow.txtActivationLog.ScrollToEnd();
            });
        }

        public void ShowMessage(string message, string title, bool isError = false)
        {
            var icon = isError ? MessageBoxImage.Error : MessageBoxImage.Information;
            MessageBox.Show(message, title, MessageBoxButton.OK, icon);
        }

        public bool ConfirmAction(string message, string title)
        {
            var result = MessageBox.Show(message, title,
                MessageBoxButton.YesNo, MessageBoxImage.Question);
            return result == MessageBoxResult.Yes;
        }
    }
}