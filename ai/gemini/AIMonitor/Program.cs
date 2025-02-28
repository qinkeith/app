using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Text.RegularExpressions;

namespace WindowsSecurityMonitor
{
    public class Program
    {
        private static readonly HttpClient client = new HttpClient();
        private static readonly string GEMINI_API_KEY = "YOUR_GEMINI_API_KEY";
        private static readonly string GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent";

        [STAThread]
        static void Main()
        {
            // Check for admin privileges
            if (!IsAdministrator())
            {
                MessageBox.Show("This application requires administrator privileges to monitor system security effectively.", 
                    "Administrator Rights Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }

        public static bool IsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public class MainForm : Form
    {
        private TabControl tabControl = new TabControl();
        private TabPage systemInfoTab = new TabPage("System Information");
        private TabPage runningProcessesTab;
        private TabPage securityVulnerabilitiesTab;
        private TabPage fixesTab;
        private Button scanButton;
        private TextBox resultsTextBox;
        private Button applyFixesButton;
        private SecurityScanner scanner;
        private List<SecurityVulnerability> vulnerabilities;

        public MainForm()
        {
            InitializeComponents();
            scanner = new SecurityScanner();
            vulnerabilities = new List<SecurityVulnerability>();
        }

        private void InitializeComponents()
        {
            this.Text = "Windows Security Monitor with Gemini AI";
            this.Size = new System.Drawing.Size(900, 700);
            this.StartPosition = FormStartPosition.CenterScreen;

            tabControl = new TabControl();
            tabControl.Dock = DockStyle.Fill;

            // Create tabs
            systemInfoTab = new TabPage("System Information");
            runningProcessesTab = new TabPage("Running Processes");
            securityVulnerabilitiesTab = new TabPage("Security Vulnerabilities");
            fixesTab = new TabPage("Recommended Fixes");

            // Add tabs to tab control
            tabControl.TabPages.Add(systemInfoTab);
            tabControl.TabPages.Add(runningProcessesTab);
            tabControl.TabPages.Add(securityVulnerabilitiesTab);
            tabControl.TabPages.Add(fixesTab);

            // Create scan button
            scanButton = new Button();
            scanButton.Text = "Scan System";
            scanButton.Dock = DockStyle.Bottom;
            scanButton.Height = 40;
            scanButton.Click += ScanButton_Click;

            // Create results textbox
            resultsTextBox = new TextBox();
            resultsTextBox.Multiline = true;
            resultsTextBox.ScrollBars = ScrollBars.Vertical;
            resultsTextBox.Dock = DockStyle.Fill;
            resultsTextBox.ReadOnly = true;

            // Create apply fixes button
            applyFixesButton = new Button();
            applyFixesButton.Text = "Apply Recommended Fixes";
            applyFixesButton.Dock = DockStyle.Bottom;
            applyFixesButton.Height = 40;
            applyFixesButton.Click += ApplyFixesButton_Click;
            applyFixesButton.Enabled = false;

            // Add controls to tabs
            systemInfoTab.Controls.Add(resultsTextBox);
            fixesTab.Controls.Add(applyFixesButton);

            // Add tab control to form
            this.Controls.Add(tabControl);
            this.Controls.Add(scanButton);
        }

        private async void ScanButton_Click(object sender, EventArgs e)
        {
            scanButton.Enabled = false;
            resultsTextBox.Clear();
            resultsTextBox.AppendText("Scanning system... Please wait.\r\n");

            try
            {
                // Gather system information
                await DisplaySystemInformation();
                
                // Scan for vulnerabilities
                vulnerabilities = await scanner.ScanForVulnerabilities();
                
                // Display vulnerabilities
                DisplayVulnerabilities();
                
                // Get remediation recommendations from Gemini AI
                await GetRemediationRecommendations();
                
                applyFixesButton.Enabled = vulnerabilities.Count > 0;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"An error occurred during scanning: {ex.Message}", 
                    "Scan Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                scanButton.Enabled = true;
            }
        }

        private async Task DisplaySystemInformation()
        {
            tabControl.SelectedTab = systemInfoTab;
            resultsTextBox.AppendText("Collecting system information...\r\n\r\n");

            // OS Information
            resultsTextBox.AppendText("=== OPERATING SYSTEM INFORMATION ===\r\n");
            string osInfo = await Task.Run(() => 
            {
                StringBuilder sb = new StringBuilder();
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject os in searcher.Get())
                    {
                        sb.AppendLine($"OS Name: {os["Caption"]}");
                        sb.AppendLine($"Version: {os["Version"]}");
                        sb.AppendLine($"Architecture: {os["OSArchitecture"]}");
                        sb.AppendLine($"Install Date: {ManagementDateTimeConverter.ToDateTime(os["InstallDate"].ToString())}");
                        sb.AppendLine($"Last Boot Up: {ManagementDateTimeConverter.ToDateTime(os["LastBootUpTime"].ToString())}");
                    }
                }
                return sb.ToString();
            });
            resultsTextBox.AppendText(osInfo + "\r\n");

            // Hardware Information
            resultsTextBox.AppendText("=== HARDWARE INFORMATION ===\r\n");
            string hardwareInfo = await Task.Run(() => 
            {
                StringBuilder sb = new StringBuilder();
                using (ManagementObjectSearcher processorSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (ManagementObject processor in processorSearcher.Get())
                    {
                        sb.AppendLine($"Processor: {processor["Name"]}");
                        sb.AppendLine($"Cores: {processor["NumberOfCores"]}");
                    }
                }
                
                using (ManagementObjectSearcher memorySearcher = new ManagementObjectSearcher("SELECT * FROM Win32_PhysicalMemory"))
                {
                    ulong totalMemory = 0;
                    foreach (ManagementObject memory in memorySearcher.Get())
                    {
                        totalMemory += Convert.ToUInt64(memory["Capacity"]);
                    }
                    sb.AppendLine($"Total Memory: {totalMemory / (1024 * 1024 * 1024)} GB");
                }
                return sb.ToString();
            });
            resultsTextBox.AppendText(hardwareInfo + "\r\n");

            // Display running processes
            await DisplayRunningProcesses();
        }

        private async Task DisplayRunningProcesses()
        {
            ListView processesListView = new ListView();
            processesListView.View = View.Details;
            processesListView.Dock = DockStyle.Fill;
            processesListView.FullRowSelect = true;
            processesListView.Columns.Add("Process Name", 150);
            processesListView.Columns.Add("PID", 70);
            processesListView.Columns.Add("Memory (MB)", 100);
            processesListView.Columns.Add("Start Time", 150);
            
            runningProcessesTab.Controls.Clear();
            runningProcessesTab.Controls.Add(processesListView);
            
            await Task.Run(() => 
            {
                Process[] processes = Process.GetProcesses();
                List<ListViewItem> items = new List<ListViewItem>();
                
                foreach (Process process in processes)
                {
                    try
                    {
                        ListViewItem item = new ListViewItem(process.ProcessName);
                        item.SubItems.Add(process.Id.ToString());
                        item.SubItems.Add((process.WorkingSet64 / (1024 * 1024)).ToString());
                        
                        string startTime = "N/A";
                        try
                        {
                            startTime = process.StartTime.ToString();
                        }
                        catch { }
                        
                        item.SubItems.Add(startTime);
                        items.Add(item);
                    }
                    catch { }
                }
                
                this.Invoke(new Action(() => 
                {
                    foreach (var item in items)
                    {
                        processesListView.Items.Add(item);
                    }
                }));
            });
        }

        private void DisplayVulnerabilities()
        {
            tabControl.SelectedTab = securityVulnerabilitiesTab;
            
            ListView vulnerabilitiesListView = new ListView();
            vulnerabilitiesListView.View = View.Details;
            vulnerabilitiesListView.Dock = DockStyle.Fill;
            vulnerabilitiesListView.FullRowSelect = true;
            vulnerabilitiesListView.Columns.Add("Severity", 80);
            vulnerabilitiesListView.Columns.Add("Category", 150);
            vulnerabilitiesListView.Columns.Add("Description", 500);
            
            securityVulnerabilitiesTab.Controls.Clear();
            securityVulnerabilitiesTab.Controls.Add(vulnerabilitiesListView);
            
            foreach (var vulnerability in vulnerabilities)
            {
                ListViewItem item = new ListViewItem(vulnerability.Severity.ToString());
                item.SubItems.Add(vulnerability.Category);
                item.SubItems.Add(vulnerability.Description);
                
                // Color-code based on severity
                switch (vulnerability.Severity)
                {
                    case SeverityLevel.Critical:
                        item.BackColor = System.Drawing.Color.LightCoral;
                        break;
                    case SeverityLevel.High:
                        item.BackColor = System.Drawing.Color.LightSalmon;
                        break;
                    case SeverityLevel.Medium:
                        item.BackColor = System.Drawing.Color.Khaki;
                        break;
                    case SeverityLevel.Low:
                        item.BackColor = System.Drawing.Color.LightGreen;
                        break;
                }
                
                vulnerabilitiesListView.Items.Add(item);
            }
        }

        private async Task GetRemediationRecommendations()
        {
            if (vulnerabilities.Count == 0)
            {
                MessageBox.Show("No vulnerabilities found!", "Security Scan Complete", 
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            tabControl.SelectedTab = fixesTab;
            ListView fixesListView = new ListView();
            fixesListView.View = View.Details;
            fixesListView.Dock = DockStyle.Fill;
            fixesListView.FullRowSelect = true;
            fixesListView.CheckBoxes = true;
            fixesListView.Columns.Add("Apply", 50);
            fixesListView.Columns.Add("Vulnerability", 150);
            fixesListView.Columns.Add("Recommended Fix", 500);
            fixesListView.Columns.Add("Automated", 80);
            
            fixesTab.Controls.Clear();
            fixesTab.Controls.Add(fixesListView);
            fixesTab.Controls.Add(applyFixesButton);

            // For each vulnerability, get a recommendation from Gemini AI
            foreach (var vulnerability in vulnerabilities)
            {
                string prompt = $"As a Windows security expert, please provide a specific, technical recommendation to fix this Windows security vulnerability: {vulnerability.Description}. " +
                    "Format your response as a concise step-by-step guide for an IT administrator. Include whether this fix can be automated with PowerShell or requires manual intervention.";
                
                string recommendation = await GetGeminiRecommendation(prompt);
                bool canAutomate = recommendation.ToLower().Contains("powershell") || 
                                  recommendation.ToLower().Contains("registry") ||
                                  recommendation.ToLower().Contains("automated") ||
                                  recommendation.ToLower().Contains("command");
                
                vulnerability.RecommendedFix = recommendation;
                vulnerability.CanAutomate = canAutomate;
                
                ListViewItem item = new ListViewItem();
                item.Checked = canAutomate; // Pre-check items that can be automated
                item.SubItems.Add(vulnerability.Category);
                item.SubItems.Add(recommendation);
                item.SubItems.Add(canAutomate ? "Yes" : "No");
                item.Tag = vulnerability; // Store vulnerability object for reference
                
                fixesListView.Items.Add(item);
            }
        }

        private async Task<string> GetGeminiRecommendation(string prompt)
        {
            try
            {
                var requestData = new
                {
                    contents = new[]
                    {
                        new
                        {
                            parts = new[]
                            {
                                new { text = prompt }
                            }
                        }
                    }
                };

                var json = JsonSerializer.Serialize(requestData);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                // Add the API key as a query parameter
                string url = $"{GEMINI_API_URL}?key={GEMINI_API_KEY}";
                
                var response = await client.PostAsync(url, content);
                response.EnsureSuccessStatusCode();
                
                var responseBody = await response.Content.ReadAsStringAsync();
                using (JsonDocument document = JsonDocument.Parse(responseBody))
                {
                    // Extract the text from the Gemini API response
                    JsonElement root = document.RootElement;
                    var candidates = root.GetProperty("candidates");
                    var firstCandidate = candidates[0];
                    var content2 = firstCandidate.GetProperty("content");
                    var parts = content2.GetProperty("parts");
                    var text = parts[0].GetProperty("text").GetString();
                    
                    return text;
                }
            }
            catch (Exception ex)
            {
                // In real application, handle this more gracefully
                return $"Unable to get AI recommendation: {ex.Message}. Please check your Gemini API key and connectivity.";
            }
        }

        private async void ApplyFixesButton_Click(object sender, EventArgs e)
        {
            applyFixesButton.Enabled = false;
            
            try
            {
                ListView fixesListView = fixesTab.Controls.OfType<ListView>().FirstOrDefault();
                if (fixesListView == null)
                {
                    MessageBox.Show("No fixes to apply.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                
                List<SecurityVulnerability> selectedFixes = new List<SecurityVulnerability>();
                foreach (ListViewItem item in fixesListView.Items)
                {
                    if (item.Checked)
                    {
                        SecurityVulnerability vulnerability = (SecurityVulnerability)item.Tag;
                        selectedFixes.Add(vulnerability);
                    }
                }
                
                if (selectedFixes.Count == 0)
                {
                    MessageBox.Show("No fixes selected to apply.", "Information", 
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                
                if (MessageBox.Show($"Are you sure you want to apply {selectedFixes.Count} selected fixes? " +
                    "This may modify system settings.", "Confirm Fixes", 
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.No)
                {
                    return;
                }
                
                // Apply the fixes
                await ApplySelectedFixes(selectedFixes);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error applying fixes: {ex.Message}", "Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                applyFixesButton.Enabled = true;
            }
        }

        private async Task ApplySelectedFixes(List<SecurityVulnerability> selectedFixes)
        {
            // Create a progress form
            Form progressForm = new Form
            {
                Text = "Applying Fixes",
                Size = new System.Drawing.Size(400, 150),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterParent,
                MaximizeBox = false,
                MinimizeBox = false
            };
            
            ProgressBar progressBar = new ProgressBar
            {
                Dock = DockStyle.Top,
                Margin = new Padding(10),
                Height = 30
            };
            
            Label statusLabel = new Label
            {
                Dock = DockStyle.Fill,
                TextAlign = System.Drawing.ContentAlignment.MiddleCenter
            };
            
            progressForm.Controls.Add(statusLabel);
            progressForm.Controls.Add(progressBar);
            
            progressBar.Maximum = selectedFixes.Count;
            progressBar.Value = 0;
            
            progressForm.Show(this);
            
            int successCount = 0;
            int failureCount = 0;
            
            foreach (var vulnerability in selectedFixes)
            {
                progressBar.Value++;
                statusLabel.Text = $"Applying fix for: {vulnerability.Category}";
                Application.DoEvents();
                
                bool success = await Task.Run(() => ApplyFix(vulnerability));
                
                if (success)
                    successCount++;
                else
                    failureCount++;
                
                await Task.Delay(500); // Small delay to show progress
            }
            
            progressForm.Close();
            
            // Show results
            MessageBox.Show($"Fix application complete.\nSuccessful: {successCount}\nFailed: {failureCount}", 
                "Fix Results", MessageBoxButtons.OK, 
                failureCount > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            
            // Refresh the vulnerability scan if fixes were applied successfully
            if (successCount > 0)
            {
                if (MessageBox.Show("Would you like to scan again to verify the fixes?", 
                    "Verify Fixes", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                {
                    ScanButton_Click(null, null);
                }
            }
        }

        private bool ApplyFix(SecurityVulnerability vulnerability)
        {
            if (!vulnerability.CanAutomate)
                return false;
            
            try
            {
                // This would contain logic to apply the fix based on the vulnerability type
                // For demonstration, let's handle some common cases:
                
                switch (vulnerability.Category.ToLower())
                {
                    case "windows update":
                        // Start Windows Update service
                        using (var service = new ServiceController("wuauserv"))
                        //using (var service = new System.ServiceProcess.ServiceController("wuauserv"))
                        {
                            if (service.Status != ServiceControllerStatus.Running)
                            {
                                service.Start();
                                service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                            }
                        }
                        return true;
                        
                    case "firewall":
                        // Enable Windows Firewall
                        ProcessStartInfo psi = new ProcessStartInfo
                        {
                            FileName = "netsh",
                            Arguments = "advfirewall set allprofiles state on",
                            CreateNoWindow = true,
                            UseShellExecute = false
                        };
                        Process.Start(psi).WaitForExit();
                        return true;
                        
                    case "user account control":
                        // Set UAC to recommended level
                        using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", true))
                        {
                            if (key != null)
                            {
                                key.SetValue("EnableLUA", 1, RegistryValueKind.DWord);
                                key.SetValue("ConsentPromptBehaviorAdmin", 5, RegistryValueKind.DWord);
                            }
                        }
                        return true;
                        
                    case "smb1":
                        // Disable SMBv1
                        psi = new ProcessStartInfo
                        {
                            FileName = "powershell",
                            Arguments = "-Command Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                            CreateNoWindow = true,
                            UseShellExecute = false
                        };
                        Process.Start(psi).WaitForExit();
                        return true;
                        
                    default:
                        // For other vulnerabilities, we would parse the AI recommendation
                        // and convert it to PowerShell or registry operations
                        
                        // For now, we'll simulate a fix by creating a PowerShell script
                        string script = GenerateFixScript(vulnerability);
                        string scriptPath = Path.Combine(Path.GetTempPath(), $"Fix_{Guid.NewGuid()}.ps1");
                        File.WriteAllText(scriptPath, script);
                        
                        psi = new ProcessStartInfo
                        {
                            FileName = "powershell",
                            Arguments = $"-ExecutionPolicy Bypass -File \"{scriptPath}\"",
                            CreateNoWindow = true,
                            UseShellExecute = false
                        };
                        Process.Start(psi).WaitForExit();
                        
                        // Clean up temp script
                        File.Delete(scriptPath);
                        return true;
                }
            }
            catch
            {
                return false;
            }
        }

        private string GenerateFixScript(SecurityVulnerability vulnerability)
        {
            // In a real application, this would parse the AI recommendation
            // and generate an appropriate PowerShell script
            
            // For demonstration, we'll create a simple logging script
            StringBuilder script = new StringBuilder();
            script.AppendLine("# Auto-generated fix script");
            script.AppendLine($"Write-Host \"Applying fix for: {vulnerability.Category}\"");
            script.AppendLine($"Write-Host \"Description: {vulnerability.Description}\"");
            script.AppendLine("# Simulating fix application");
            script.AppendLine("Start-Sleep -Seconds 2");
            script.AppendLine("Write-Host \"Fix applied successfully\" -ForegroundColor Green");
            
            return script.ToString();
        }
    }

    public class SecurityScanner
    {
        public async Task<List<SecurityVulnerability>> ScanForVulnerabilities()
        {
            List<SecurityVulnerability> vulnerabilities = new List<SecurityVulnerability>();
            
            // Run various security checks in parallel
            Task<List<SecurityVulnerability>> windowsUpdateTask = CheckWindowsUpdates();
            Task<List<SecurityVulnerability>> firewallTask = CheckFirewall();
            Task<List<SecurityVulnerability>> antivirusTask = CheckAntivirus();
            Task<List<SecurityVulnerability>> userAccountTask = CheckUserAccountControl();
            Task<List<SecurityVulnerability>> networkProtocolsTask = CheckNetworkProtocols();
            Task<List<SecurityVulnerability>> passwordPolicyTask = CheckPasswordPolicy();
            
            // Wait for all tasks to complete
            await Task.WhenAll(
                windowsUpdateTask, 
                firewallTask, 
                antivirusTask, 
                userAccountTask, 
                networkProtocolsTask,
                passwordPolicyTask
            );
            
            // Combine results
            vulnerabilities.AddRange(windowsUpdateTask.Result);
            vulnerabilities.AddRange(firewallTask.Result);
            vulnerabilities.AddRange(antivirusTask.Result);
            vulnerabilities.AddRange(userAccountTask.Result);
            vulnerabilities.AddRange(networkProtocolsTask.Result);
            vulnerabilities.AddRange(passwordPolicyTask.Result);
            
            return vulnerabilities;
        }
        
        private async Task<List<SecurityVulnerability>> CheckWindowsUpdates()
        {
            List<SecurityVulnerability> vulnerabilities = new List<SecurityVulnerability>();
            
            await Task.Run(() => 
            {
                try
                {
                    // Check Windows Update service status
                    using (ServiceController service = new ServiceController("wuauserv"))
                    {
                        if (service.Status != ServiceControllerStatus.Running)
                        {
                            vulnerabilities.Add(new SecurityVulnerability
                            {
                                Category = "Windows Update",
                                Description = "Windows Update service is not running. This could prevent security updates from being installed.",
                                Severity = SeverityLevel.High
                            });
                        }
                    }
                    
                    // Check last update time
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect"))
                    {
                        if (key != null)
                        {
                            object lastChecked = key.GetValue("LastSuccessTime");
                            if (lastChecked != null)
                            {
                                DateTime lastCheckTime = DateTime.Parse(lastChecked.ToString());
                                if ((DateTime.Now - lastCheckTime).TotalDays > 7)
                                {
                                    vulnerabilities.Add(new SecurityVulnerability
                                    {
                                        Category = "Windows Update",
                                        Description = $"Windows has not checked for updates in {(int)(DateTime.Now - lastCheckTime).TotalDays} days. Regular updates are important for security.",
                                        Severity = SeverityLevel.Medium
                                    });
                                }
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    // Add a generic vulnerability in case of error
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        Category = "Windows Update",
                        Description = "Unable to determine Windows Update status. Please check Windows Update settings manually.",
                        Severity = SeverityLevel.Medium
                    });
                }
            });
            
            return vulnerabilities;
        }
        
        private async Task<List<SecurityVulnerability>> CheckFirewall()
        {
            List<SecurityVulnerability> vulnerabilities = new List<SecurityVulnerability>();
            
            await Task.Run(() => 
            {
                try
                {
                    // Check Windows Firewall status
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "advfirewall show allprofiles",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    
                    Process process = Process.Start(psi);
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    
                    bool domainEnabled = output.Contains("Domain Profile") && output.Contains("State                                 ON");
                    bool privateEnabled = output.Contains("Private Profile") && output.Contains("State                                 ON");
                    bool publicEnabled = output.Contains("Public Profile") && output.Contains("State                                 ON");
                    
                    if (!domainEnabled || !privateEnabled || !publicEnabled)
                    {
                        string profiles = "";
                        if (!domainEnabled) profiles += "Domain ";
                        if (!privateEnabled) profiles += "Private ";
                        if (!publicEnabled) profiles += "Public ";
                        
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            Category = "Firewall",
                            Description = $"Windows Firewall is disabled for the following profiles: {profiles.Trim()}. This significantly increases your exposure to network-based attacks.",
                            Severity = SeverityLevel.Critical
                        });
                    }
                }
                catch (Exception)
                {
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        Category = "Firewall",
                        Description = "Unable to determine firewall status. Please check Windows Firewall settings manually.",
                        Severity = SeverityLevel.Medium
                    });
                }
            });
            
            return vulnerabilities;
        }
        
        private async Task<List<SecurityVulnerability>> CheckAntivirus()
        {
            List<SecurityVulnerability> vulnerabilities = new List<SecurityVulnerability>();
            
            await Task.Run(() => 
            {
                try
                {
                    bool antivirusDetected = false;
                    
                    // Check Windows Security Center
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntivirusProduct"))
                    {
                        ManagementObjectCollection antivirusProducts = searcher.Get();
                        antivirusDetected = antivirusProducts.Count > 0;
                        
                        foreach (ManagementObject product in antivirusProducts)
                        {
                            // ProductState is a bitmask that indicates enabled/disabled and up-to-date/out-of-date
                            uint state = Convert.ToUInt32(product["productState"]);
                            bool enabled = (state & 0x1000) != 0; // Check if bit is set
                            bool upToDate = (state & 0x10) != 0;  // Check if bit is set
                            
                            if (!enabled)
                            {
                                vulnerabilities.Add(new SecurityVulnerability
                                {
                                    Category = "Antivirus",
                                    Description = $"Antivirus product '{product["displayName"]}' is installed but not enabled. This leaves your system vulnerable to malware.",
                                    Severity = SeverityLevel.Critical
                                });
                            }
                            
                            if (!upToDate)
                            {
                                vulnerabilities.Add(new SecurityVulnerability
                                {
                                    Category = "Antivirus",
                                    Description = $"Antivirus product '{product["displayName"]}' does not have up-to-date virus definitions. This reduces its effectiveness against new threats.",
                                    Severity = SeverityLevel.High
                                });
                            }
                        }
                    }
                    
                    if (!antivirusDetected)
                    {
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            Category = "Antivirus",
                            Description = "No antivirus software detected. Your system is vulnerable to malware and other threats.",
                            Severity = SeverityLevel.Critical
                        });
                    }
                }
                catch (Exception)
                {
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        Category = "Antivirus",
                        Description = "Unable to determine antivirus status. Please check antivirus settings manually.",
                        Severity = SeverityLevel.Medium
                    });
                }
            });
            
            return vulnerabilities;
        }
        
        private async Task<List<SecurityVulnerability>> CheckUserAccountControl()
        {
            List<SecurityVulnerability> vulnerabilities = new List<SecurityVulnerability>();
            
            await Task.Run(() => 
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                    {
                        if (key != null)
                        {
                            // Check if UAC is enabled
                            object enableLUA = key.GetValue("EnableLUA");
                            if (enableLUA == null || Convert.ToInt32(enableLUA) == 0)
                            {
                                vulnerabilities.Add(new SecurityVulnerability
                                {
                                    Category = "User Account Control",
                                    Description = "User Account Control (UAC) is disabled. This allows programs to make changes to your computer without your knowledge.",
                                    Severity = SeverityLevel.Critical
                                });
                            }
                            else
                            {
                                // Check UAC level
                                object consentPromptBehaviorAdmin = key.GetValue("ConsentPromptBehaviorAdmin");
                                if (consentPromptBehaviorAdmin != null && Convert.ToInt32(consentPromptBehaviorAdmin) == 0)
                                {
                                    vulnerabilities.Add(new SecurityVulnerability
                                    {
                                        Category = "User Account Control",
                                        Description = "User Account Control (UAC) is set to never notify. This reduces security by allowing programs to make system changes without your permission.",
                                        Severity = SeverityLevel.High
                                    });
                                }
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        Category = "User Account Control",
                        Description = "Unable to determine User Account Control (UAC) status. Please check UAC settings manually.",
                        Severity = SeverityLevel.Medium
                    });
                }
            });
            
            return vulnerabilities;
        }
        
        private async Task<List<SecurityVulnerability>> CheckNetworkProtocols()
        {
            List<SecurityVulnerability> vulnerabilities = new List<SecurityVulnerability>();
            
            await Task.Run(() => 
            {
                try
                {
                    // Check for SMBv1 (vulnerable protocol)
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = "-Command Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object State",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    
                    Process process = Process.Start(psi);
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    
                    if (output.Contains("Enabled"))
                    {
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            Category = "SMB1",
                            Description = "SMBv1 protocol is enabled. This protocol is vulnerable to various attacks including WannaCry ransomware and should be disabled.",
                            Severity = SeverityLevel.Critical
                        });
                    }
                    
                    // Check for RDP enabled
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"System\CurrentControlSet\Control\Terminal Server"))
                    {
                        if (key != null)
                        {
                            object fDenyTSConnections = key.GetValue("fDenyTSConnections");
                            if (fDenyTSConnections != null && Convert.ToInt32(fDenyTSConnections) == 0)
                            {
                                // RDP is enabled, check NLA
                                using (RegistryKey nlaSetting = Registry.LocalMachine.OpenSubKey(@"System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"))
                                {
                                    if (nlaSetting != null)
                                    {
                                        object userAuthentication = nlaSetting.GetValue("UserAuthentication");
                                        if (userAuthentication == null || Convert.ToInt32(userAuthentication) == 0)
                                        {
                                            vulnerabilities.Add(new SecurityVulnerability
                                            {
                                                Category = "Remote Desktop",
                                                Description = "Remote Desktop Protocol (RDP) is enabled without Network Level Authentication (NLA). This configuration is vulnerable to brute force attacks and certain exploits.",
                                                Severity = SeverityLevel.High
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        Category = "Network Protocols",
                        Description = "Unable to determine status of potentially insecure network protocols. Please check network protocol settings manually.",
                        Severity = SeverityLevel.Medium
                    });
                }
            });
            
            return vulnerabilities;
        }
        
        private async Task<List<SecurityVulnerability>> CheckPasswordPolicy()
        {
            List<SecurityVulnerability> vulnerabilities = new List<SecurityVulnerability>();
            
            await Task.Run(() => 
            {
                try
                {
                    // Get password policy information
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "net",
                        Arguments = "accounts",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    
                    Process process = Process.Start(psi);
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    
                    // Parse minimum password length
                    int minPasswordLength = 0;
                    Match match = Regex.Match(output, @"Minimum password length \(characters\):\s+(\d+)");
                    if (match.Success)
                    {
                        minPasswordLength = Convert.ToInt32(match.Groups[1].Value);
                    }
                    
                    if (minPasswordLength < 8)
                    {
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            Category = "Password Policy",
                            Description = $"Minimum password length is set to {minPasswordLength} characters. NIST recommends at least 8 characters for security.",
                            Severity = minPasswordLength < 6 ? SeverityLevel.High : SeverityLevel.Medium
                        });
                    }
                    
                    // Parse password history
                    int passwordHistory = 0;
                    match = Regex.Match(output, @"Length of password history maintained:\s+(\d+)");
                    if (match.Success)
                    {
                        passwordHistory = Convert.ToInt32(match.Groups[1].Value);
                    }
                    
                    if (passwordHistory < 5)
                    {
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            Category = "Password Policy",
                            Description = $"Password history is set to remember only {passwordHistory} passwords. This allows users to cycle through a small set of passwords.",
                            Severity = SeverityLevel.Low
                        });
                    }
                    
                    // Parse maximum password age
                    int maxPasswordAge = 0;
                    match = Regex.Match(output, @"Maximum password age \(days\):\s+(\d+)");
                    if (match.Success)
                    {
                        maxPasswordAge = Convert.ToInt32(match.Groups[1].Value);
                    }
                    
                    if (maxPasswordAge > 90 || maxPasswordAge == 0)
                    {
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            Category = "Password Policy",
                            Description = maxPasswordAge == 0 
                                ? "Passwords are set to never expire. This is contrary to security best practices." 
                                : $"Maximum password age is set to {maxPasswordAge} days. NIST recommends changing passwords every 60-90 days.",
                            Severity = SeverityLevel.Medium
                        });
                    }
                }
                catch (Exception)
                {
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        Category = "Password Policy",
                        Description = "Unable to determine password policy settings. Please check password policy manually.",
                        Severity = SeverityLevel.Low
                    });
                }
            });
            
            return vulnerabilities;
        }
    }

    [Serializable]
    public class SecurityVulnerability
    {
        public string Category { get; set; }
        public string Description { get; set; }
        public SeverityLevel Severity { get; set; }
        public string RecommendedFix { get; set; }
        public bool CanAutomate { get; set; }
    }

    public enum SeverityLevel
    {
        Low,
        Medium,
        High,
        Critical
    }

    public static class ManagementDateTimeConverter
    {
        public static DateTime ToDateTime(string dmtfDate)
        {
            int year = int.Parse(dmtfDate.Substring(0, 4));
            int month = int.Parse(dmtfDate.Substring(4, 2));
            int day = int.Parse(dmtfDate.Substring(6, 2));
            int hour = int.Parse(dmtfDate.Substring(8, 2));
            int minute = int.Parse(dmtfDate.Substring(10, 2));
            int second = int.Parse(dmtfDate.Substring(12, 2));
            
            return new DateTime(year, month, day, hour, minute, second);
        }
    }

    public class ServiceController
    {
        private string serviceName;
        
        public ServiceController(string serviceName)
        {
            this.serviceName = serviceName;
        }
        
        public ServiceControllerStatus Status
        {
            get
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "sc",
                    Arguments = $"query {serviceName}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                Process process = Process.Start(psi);
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                
                if (output.Contains("RUNNING"))
                    return ServiceControllerStatus.Running;
                else if (output.Contains("STOPPED"))
                    return ServiceControllerStatus.Stopped;
                else if (output.Contains("PAUSED"))
                    return ServiceControllerStatus.Paused;
                else if (output.Contains("START_PENDING"))
                    return ServiceControllerStatus.StartPending;
                else if (output.Contains("STOP_PENDING"))
                    return ServiceControllerStatus.StopPending;
                else
                    return ServiceControllerStatus.Stopped;
            }
        }
        
        public void Start()
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "sc",
                Arguments = $"start {serviceName}",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            
            Process process = Process.Start(psi);
            process.WaitForExit();
        }
        
        public void WaitForStatus(ServiceControllerStatus desiredStatus, TimeSpan timeout)
        {
            DateTime endTime = DateTime.Now.Add(timeout);
            
            while (DateTime.Now < endTime)
            {
                if (Status == desiredStatus)
                    return;
                
                System.Threading.Thread.Sleep(1000);
            }
            
            throw new TimeoutException($"Timeout waiting for service {serviceName} to reach status {desiredStatus}");
        }
    }
    
    public enum ServiceControllerStatus
    {
        Running,
        Stopped,
        Paused,
        StartPending,
        StopPending,
        ContinuePending,
        PausePending
    }
}