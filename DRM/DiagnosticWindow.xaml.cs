using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Microsoft.Win32;

namespace XPlaneActivator
{
    public partial class DiagnosticWindow : Window
    {
        private readonly DiagnosticReport report;

        public DiagnosticWindow(DiagnosticReport report)
        {
            InitializeComponent();
            this.report = report;
            LoadDiagnosticData();
        }

        private void LoadDiagnosticData()
        {
            try
            {
                // Update summary information
                lblTotalTests.Text = report.TotalTests.ToString();
                lblPassedTests.Text = report.PassedTests.ToString();
                lblWarningTests.Text = report.WarningTests.ToString();
                lblFailedTests.Text = report.FailedTests.ToString();

                // Set overall status and color
                lblOverallStatus.Text = report.OverallStatus;
                UpdateOverallStatusColor(report.OverallStatus);

                // Display results grouped by category
                var categorizedResults = report.Results.GroupBy(r => r.Category).OrderBy(g => g.Key);

                foreach (var categoryGroup in categorizedResults)
                {
                    AddCategorySection(categoryGroup.Key, categoryGroup.ToList());
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading diagnostic data: {ex.Message}", "Error",
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateOverallStatusColor(string status)
        {
            var parent = lblOverallStatus.Parent as Border;
            if (parent != null)
            {
                switch (status.ToLower())
                {
                    case "excellent":
                    case "优秀":
                        parent.Background = new SolidColorBrush(Color.FromRgb(27, 77, 27));
                        parent.BorderBrush = new SolidColorBrush(Color.FromRgb(76, 175, 80));
                        lblOverallStatus.Foreground = new SolidColorBrush(Color.FromRgb(76, 175, 80));
                        break;
                    case "good":
                    case "良好":
                        parent.Background = new SolidColorBrush(Color.FromRgb(77, 61, 27));
                        parent.BorderBrush = new SolidColorBrush(Color.FromRgb(255, 152, 0));
                        lblOverallStatus.Foreground = new SolidColorBrush(Color.FromRgb(255, 152, 0));
                        break;
                    case "needs attention":
                    case "needs improvement":
                    case "需要注意":
                    case "存在问题":
                        parent.Background = new SolidColorBrush(Color.FromRgb(77, 27, 27));
                        parent.BorderBrush = new SolidColorBrush(Color.FromRgb(244, 67, 54));
                        lblOverallStatus.Foreground = new SolidColorBrush(Color.FromRgb(244, 67, 54));
                        break;
                }
            }
        }

        private void AddCategorySection(string categoryName, System.Collections.Generic.List<DiagnosticResult> results)
        {
            // Add category title
            var categoryHeader = new TextBlock
            {
                Text = $"📋 {categoryName}",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0, 122, 204)),
                Margin = new Thickness(0, 10, 0, 5)
            };
            spDiagnosticResults.Children.Add(categoryHeader);

            // Add category statistics
            int categoryPassed = results.Count(r => r.Status == TestStatus.Passed);
            int categoryWarning = results.Count(r => r.Status == TestStatus.Warning);
            int categoryFailed = results.Count(r => r.Status == TestStatus.Failed);

            var statisticsPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(20, 0, 0, 10)
            };

            statisticsPanel.Children.Add(new TextBlock
            {
                Text = $"Passed: {categoryPassed}",
                Foreground = new SolidColorBrush(Color.FromRgb(76, 175, 80)),
                Margin = new Thickness(0, 0, 15, 0),
                FontSize = 12
            });

            if (categoryWarning > 0)
            {
                statisticsPanel.Children.Add(new TextBlock
                {
                    Text = $"Warning: {categoryWarning}",
                    Foreground = new SolidColorBrush(Color.FromRgb(255, 152, 0)),
                    Margin = new Thickness(0, 0, 15, 0),
                    FontSize = 12
                });
            }

            if (categoryFailed > 0)
            {
                statisticsPanel.Children.Add(new TextBlock
                {
                    Text = $"Failed: {categoryFailed}",
                    Foreground = new SolidColorBrush(Color.FromRgb(244, 67, 54)),
                    Margin = new Thickness(0, 0, 15, 0),
                    FontSize = 12
                });
            }

            spDiagnosticResults.Children.Add(statisticsPanel);

            // Add test results
            foreach (var result in results.OrderBy(r => r.Test))
            {
                var resultBorder = CreateResultElement(result);
                spDiagnosticResults.Children.Add(resultBorder);
            }

            // Add separator
            var separator = new Border
            {
                Height = 1,
                Background = new SolidColorBrush(Color.FromRgb(68, 68, 68)),
                Margin = new Thickness(0, 15, 0, 0)
            };
            spDiagnosticResults.Children.Add(separator);
        }

        private Border CreateResultElement(DiagnosticResult result)
        {
            var border = new Border
            {
                Margin = new Thickness(20, 2, 20, 2),
                Padding = new Thickness(10, 5, 10, 5),
                CornerRadius = new CornerRadius(3),
                BorderThickness = new Thickness(1)
            };

            // Set colors
            switch (result.Status)
            {
                case TestStatus.Passed:
                    border.Background = new SolidColorBrush(Color.FromRgb(27, 77, 27));
                    border.BorderBrush = new SolidColorBrush(Color.FromRgb(76, 175, 80));
                    break;
                case TestStatus.Warning:
                    border.Background = new SolidColorBrush(Color.FromRgb(77, 61, 27));
                    border.BorderBrush = new SolidColorBrush(Color.FromRgb(255, 152, 0));
                    break;
                case TestStatus.Failed:
                    border.Background = new SolidColorBrush(Color.FromRgb(77, 27, 27));
                    border.BorderBrush = new SolidColorBrush(Color.FromRgb(244, 67, 54));
                    break;
            }

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Auto) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Auto) });

            // Status icon
            var statusIcon = new TextBlock
            {
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 10, 0),
                VerticalAlignment = VerticalAlignment.Top
            };

            switch (result.Status)
            {
                case TestStatus.Passed:
                    statusIcon.Text = "✅";
                    statusIcon.Foreground = new SolidColorBrush(Color.FromRgb(76, 175, 80));
                    break;
                case TestStatus.Warning:
                    statusIcon.Text = "⚠️";
                    statusIcon.Foreground = new SolidColorBrush(Color.FromRgb(255, 152, 0));
                    break;
                case TestStatus.Failed:
                    statusIcon.Text = "❌";
                    statusIcon.Foreground = new SolidColorBrush(Color.FromRgb(244, 67, 54));
                    break;
            }

            Grid.SetColumn(statusIcon, 0);
            grid.Children.Add(statusIcon);

            // Content panel
            var contentPanel = new StackPanel();

            var testNameBlock = new TextBlock
            {
                Text = result.Test,
                FontWeight = FontWeights.SemiBold,
                FontSize = 14,
                Foreground = Brushes.White
            };
            contentPanel.Children.Add(testNameBlock);

            var messageBlock = new TextBlock
            {
                Text = result.Message,
                FontSize = 12,
                Opacity = 0.9,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 2, 0, 0),
                Foreground = Brushes.White
            };
            contentPanel.Children.Add(messageBlock);

            if (!string.IsNullOrEmpty(result.Details))
            {
                var detailsBlock = new TextBlock
                {
                    Text = result.Details,
                    FontSize = 11,
                    Opacity = 0.7,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 2, 0, 0),
                    Foreground = Brushes.White
                };
                contentPanel.Children.Add(detailsBlock);
            }

            Grid.SetColumn(contentPanel, 1);
            grid.Children.Add(contentPanel);

            // Status label
            var statusLabel = new TextBlock
            {
                Text = result.Status.ToString(),
                FontSize = 12,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Top
            };

            switch (result.Status)
            {
                case TestStatus.Passed:
                    statusLabel.Foreground = new SolidColorBrush(Color.FromRgb(76, 175, 80));
                    break;
                case TestStatus.Warning:
                    statusLabel.Foreground = new SolidColorBrush(Color.FromRgb(255, 152, 0));
                    break;
                case TestStatus.Failed:
                    statusLabel.Foreground = new SolidColorBrush(Color.FromRgb(244, 67, 54));
                    break;
            }

            Grid.SetColumn(statusLabel, 2);
            grid.Children.Add(statusLabel);

            border.Child = grid;
            return border;
        }

        private void BtnSaveReport_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var saveDialog = new SaveFileDialog
                {
                    Title = "Save Diagnostic Report",
                    Filter = "Text files (*.txt)|*.txt|HTML files (*.html)|*.html|All files (*.*)|*.*",
                    FileName = $"XPlane_Diagnostic_Report_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
                };

                if (saveDialog.ShowDialog() == true)
                {
                    string reportContent;

                    if (Path.GetExtension(saveDialog.FileName).ToLower() == ".html")
                    {
                        reportContent = GenerateHtmlReport();
                    }
                    else
                    {
                        reportContent = GenerateTextReport();
                    }

                    File.WriteAllText(saveDialog.FileName, reportContent, Encoding.UTF8);
                    MessageBox.Show($"Diagnostic report saved to: {saveDialog.FileName}", "Save Successful",
                                   MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to save report: {ex.Message}", "Error",
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GenerateTextReport()
        {
            var sb = new StringBuilder();

            sb.AppendLine("X-Plane DRM System Diagnostic Report");
            sb.AppendLine("=".PadRight(50, '='));
            sb.AppendLine($"Generated: {report.Timestamp:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();

            sb.AppendLine("Summary:");
            sb.AppendLine($"  Total Tests: {report.TotalTests}");
            sb.AppendLine($"  Passed: {report.PassedTests}");
            sb.AppendLine($"  Warning: {report.WarningTests}");
            sb.AppendLine($"  Failed: {report.FailedTests}");
            sb.AppendLine($"  Overall Status: {report.OverallStatus}");
            sb.AppendLine();

            var categorizedResults = report.Results.GroupBy(r => r.Category).OrderBy(g => g.Key);

            foreach (var categoryGroup in categorizedResults)
            {
                sb.AppendLine($"[{categoryGroup.Key}]");
                sb.AppendLine("-".PadRight(30, '-'));

                foreach (var result in categoryGroup.OrderBy(r => r.Test))
                {
                    string statusIcon = result.Status switch
                    {
                        TestStatus.Passed => "[√]",
                        TestStatus.Warning => "[!]",
                        TestStatus.Failed => "[×]",
                        _ => "[?]"
                    };

                    sb.AppendLine($"  {statusIcon} {result.Test}");
                    sb.AppendLine($"      Status: {result.Status}");
                    sb.AppendLine($"      Message: {result.Message}");
                    if (!string.IsNullOrEmpty(result.Details))
                    {
                        sb.AppendLine($"      Details: {result.Details}");
                    }
                    sb.AppendLine();
                }
            }

            return sb.ToString();
        }

        private string GenerateHtmlReport()
        {
            var sb = new StringBuilder();

            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html>");
            sb.AppendLine("<head>");
            sb.AppendLine("<meta charset=\"utf-8\">");
            sb.AppendLine("<title>X-Plane DRM System Diagnostic Report</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: Arial, sans-serif; margin: 20px; background-color: #2d2d30; color: white; }");
            sb.AppendLine(".header { text-align: center; color: #007ACC; }");
            sb.AppendLine(".summary { background-color: #1e1e1e; padding: 15px; border-radius: 5px; margin: 20px 0; }");
            sb.AppendLine(".category { margin: 20px 0; }");
            sb.AppendLine(".category-title { font-size: 18px; font-weight: bold; color: #007ACC; border-bottom: 1px solid #007ACC; padding-bottom: 5px; }");
            sb.AppendLine(".test-result { margin: 10px 0; padding: 10px; border-radius: 3px; border-left: 4px solid; }");
            sb.AppendLine(".passed { background-color: #1B4D1B; border-left-color: #4CAF50; }");
            sb.AppendLine(".warning { background-color: #4D3D1B; border-left-color: #FF9800; }");
            sb.AppendLine(".failed { background-color: #4D1B1B; border-left-color: #F44336; }");
            sb.AppendLine(".test-name { font-weight: bold; font-size: 14px; }");
            sb.AppendLine(".test-message { font-size: 12px; opacity: 0.9; margin-top: 5px; }");
            sb.AppendLine(".test-details { font-size: 11px; opacity: 0.7; margin-top: 5px; }");
            sb.AppendLine("</style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");

            sb.AppendLine("<h1 class=\"header\">X-Plane DRM System Diagnostic Report</h1>");

            sb.AppendLine("<div class=\"summary\">");
            sb.AppendLine($"<p><strong>Generated:</strong> {report.Timestamp:yyyy-MM-dd HH:mm:ss}</p>");
            sb.AppendLine($"<p><strong>Total Tests:</strong> {report.TotalTests} | ");
            sb.AppendLine($"<span style=\"color: #4CAF50;\">Passed: {report.PassedTests}</span> | ");
            sb.AppendLine($"<span style=\"color: #FF9800;\">Warning: {report.WarningTests}</span> | ");
            sb.AppendLine($"<span style=\"color: #F44336;\">Failed: {report.FailedTests}</span></p>");
            sb.AppendLine($"<p><strong>Overall Status:</strong> {report.OverallStatus}</p>");
            sb.AppendLine("</div>");

            var categorizedResults = report.Results.GroupBy(r => r.Category).OrderBy(g => g.Key);

            foreach (var categoryGroup in categorizedResults)
            {
                sb.AppendLine("<div class=\"category\">");
                sb.AppendLine($"<div class=\"category-title\">{categoryGroup.Key}</div>");

                foreach (var result in categoryGroup.OrderBy(r => r.Test))
                {
                    string cssClass = result.Status.ToString().ToLower();
                    string statusIcon = result.Status switch
                    {
                        TestStatus.Passed => "✅",
                        TestStatus.Warning => "⚠️",
                        TestStatus.Failed => "❌",
                        _ => "❓"
                    };

                    sb.AppendLine($"<div class=\"test-result {cssClass}\">");
                    sb.AppendLine($"<div class=\"test-name\">{statusIcon} {result.Test}</div>");
                    sb.AppendLine($"<div class=\"test-message\">{result.Message}</div>");
                    if (!string.IsNullOrEmpty(result.Details))
                    {
                        sb.AppendLine($"<div class=\"test-details\">{result.Details}</div>");
                    }
                    sb.AppendLine("</div>");
                }

                sb.AppendLine("</div>");
            }

            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            return sb.ToString();
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}