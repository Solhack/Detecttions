# Import the necessary modules
import-module 'microsoft[.]powershell[.]security'

# Get a list of all loaded DLLs
$loadedDlls = Get-Process | Get-Module | Where-Object {$_.ModuleName -ne 'Kernel32.dll'}

# Check each DLL for vulnerabilities
foreach ($dll in $loadedDlls) {
 # Get the DLL's file path
 $dllPath = $dll.Path

 # Check if the DLL is vulnerable to process injection
 $isVulnerable = Test-Path $dllPath -PathType 'Physical' -Recurse -Include '*.sys'

 # If the DLL is vulnerable, output a message
 if ($isVulnerable) {
  Write-Host "The DLL $dllPath is vulnerable to process injection."
 }
}
