# Detections


Use the KQL query DeviceProcessEvents | where ProcessName == "ssh.exe" and FileName == "msys-2.0.dll" to identify instances of the ssh.exe process launching the msys-2.0.dll library.
Use the PowerShell script Get-Process | where {$_.ProcessName -eq "ssh.exe" -and $_.Modules.ModuleName -eq "msys-2.0.dll"} to identify any instances of the ssh.exe process that have the msys-2.0.dll library loaded.
Monitor for unusual process creation events.
Monitor for changes to legitimate DLLs.
Use a security information and event management (SIEM) tool to correlate events across your network.
Keep your security software up to date.
By following these steps, you can help protect your systems from the Mockingjay process injection technique.
