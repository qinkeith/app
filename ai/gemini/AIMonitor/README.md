# AI Monitor with Gemini

The C# project AIMonitor is a Windows desktop application that scans a system for security vulnerabilities and provides remediation recommendations using Google Gemini's large language model.

The application performs the following actions:

1. System Information Gathering: Collects and displays basic system information, including operating system details, hardware specifications, and a list of running processes. This information is displayed in a tabbed interface.

2. Security Vulnerability Scanning: Performs several security checks:

    - Checks the status and last update time of the Windows Update service.
    - Checks the status of the Windows Firewall for all profiles (Domain, Private, Public).
    - Checks for the presence and status of installed antivirus software.
    - Checks the status of User Account Control (UAC).
    - Checks for the presence of potentially insecure network protocols like SMBv1 and RDP configurations.
    - Checks password policy settings like minimum length, history, and maximum age.

3. Gemini AI Integration: For each identified vulnerability, it sends a description to the Google Gemini API (using the gemini-pro model) to obtain a recommended fix. The prompt specifically requests a step-by-step guide for an IT administrator, formatted clearly and indicating whether automation with PowerShell is possible.

4. Remediation Recommendation Display: Presents the detected vulnerabilities and their corresponding Gemini-generated remediation recommendations in a user-friendly tabbed interface, color-coded by severity. Fixes that can be automated are pre-selected.

5. Automated Fix Application: Allows the user to select recommended fixes and apply them. The application includes basic automated fix implementation for some common vulnerabilities (e.g., starting the Windows Update service, enabling the firewall, setting UAC to a recommended level, and disabling SMBv1) using `sc` and `netsh` commands and PowerShell. For other vulnerabilities, it generates a placeholder PowerShell script that simulates the fix application. A progress bar and a dedicated status display are included.

## Build the program

- Go to AIMonitor's root folder
- Run `dotnet build` 
- Run `dotnet publish -c Release -r win-x64 --self-contained true`

## Limitations

- Partial Automation: Currently, automation is limited; many fixes would require more sophisticated code to handle diverse vulnerability types and scenarios. The code simulates applying fixes for many cases.
- Error Handling: While some error handling is currently present, it could be improved for robustness.
- Security Implications: Directly executing user-generated or AI-generated scripts poses security risks. Robust input validation and sanitization are crucial but not fully implemented in this project yet.
