#ACRT Detection Script
#Checks system against compliance benchmarks
#Exit 1 = remediation needed
#Exit 0 = compliant
#Auth. Maxwell Howard


#Report Location
$ReportFolder = "C:\ProgramData\ACRT\Reports"
$ReportFile   = Join-Path $ReportFolder "ACRT_DetectionReport.txt"

#Creates file at path if the file is not found
if (!(Test-Path $ReportFolder)) 
{ 
	New-Item -Path $ReportFolder -ItemType Directory -Force | Out-Null 
}

#Logging function - Gets time format and adds the time and message params
function Log 
{
	param([string]$Message)
	$time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	Add-Content -Path $ReportFile -Value "$time  $Message"
}


Log "ACRT DETECTION"
Log "Computer: $env:COMPUTERNAME | UserContext: $env:USERNAME"

$NonCompliant = $false


#Firewall Check
try
{
    $firewall = Get-NetFirewallProfile

    if ($firewall.Enabled -contains $false)
    {
        Write-Output "Firewall is NOT."
        $NonCompliant = $true
    }
    else
    {
        Write-Output "Firewall is enabled."
    }
}
catch
{
    Write-Output "Error checking firewall: $($_.Exception.Message)"
}


#Windows Defender Service
try
{
    $defenderService = Get-Service WinDefend

    if ($defenderService.Status -ne "Running")
    {
        Write-Output "Windows Defender service is NOT running."
        $NonCompliant = $true
    }
    else
    {
        Write-Output "Windows Defender service is running."
    }
}
catch
{
    Write-Output "Error checking Defender: $($_.Exception.Message)"
}


#RTP
try
{
    $check = Get-MpComputerStatus

    if ($check.RealTimeProtectionEnabled -eq $true)
    {
        Write-Output "Real Time Protection is ON."
    }
    else
    {
        Write-Output "Real Time Protection is OFF."
        $NonCompliant = $true
    }
}
catch
{
    Write-Output "Error checking real time protection: $($_.Exception.Message)"
}


#BitLocker Check
try
{
    $bitlocker = Get-BitLockerVolume -MountPoint "C:"

    if ($bitlocker.ProtectionStatus -eq "On")
    {
    	Write-Output "BitLocker is enabled."
    } 
    else 
    {
    	Write-Output "BitLocker is NOT enabled."
    }
}
catch
{
    Write-Output "Error checking BitLocker: $($_.Exception.Message)"
}


#Secure Boot Check
try
{
    $secureBoot = Confirm-SecureBootUEFI

    if ($secureBoot -eq $true)
    {
        Write-Output "Secure Boot is enabled."
    }
    else
    {
        Write-Output "Secure Boot is NOT enabled."
        $NonCompliant = $true
    }
}
catch
{
    Write-Output "Secure Boot cannot be checked."
}



#If any noncompliants exist in benchmarks above
if ($NonCompliant -eq $true)
{
    Write-Output "System is NONCOMPLIANT."
    exit 1
}
else
{
    Write-Output "System is COMPLIANT."
    exit 0
}