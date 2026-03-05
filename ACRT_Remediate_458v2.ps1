#ACRT Remediation Script
#Attempts to remediate compliance benchmarks for the ACRT test policy in MS Intune 
#(Firewall, Defender service, Real-time protection, BitLocker)
#Auth. Maxwell Howard

#Report Location
$ReportFolder = "C:\ProgramData\ACRT\Reports"
$ReportFile = Join-Path $ReportFolder "ACRT_RemediationReport.txt"

if (!(Test-Path $ReportFolder))
{ 
	New-Item -Path $ReportFolder -ItemType Directory -Force | Out-Null 
}

function Log 
{
    	param([string]$Message)
    	$time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    	Add-Content -Path $ReportFile -Value "$time  $Message"
}

Log "ACRT Remediate Start"
Log "Computer: $env:COMPUTERNAME  |  UserContext: $env:USERNAME"

#Firewall Remediation
try
{
    Log "Checking Firewall..."
    $firewall = Get-NetFirewallProfile

    if ($firewall.Enabled -contains $false)
    {
        Log "Firewall is NOT enabled on all profiles. Enabling now..."
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Log "Firewall enabled on Domain/Public/Private."
    }
    else
    {
        Log "Firewall already enabled on all profiles."
    }
}
catch
{
    Log "Error remediating Firewall: $($_.Exception.Message)"
}

#Windows Defender Remediation
try
{
    Log "Checking WinDefend Service..."
    $defenderService = Get-Service WinDefend

    if ($defenderService.Status -ne "Running")
    {
        Log "Windows Defender service is NOT running. Starting service..."
        Start-Service WinDefend
        Set-Service WinDefend -StartupType Automatic
        Log "Windows Defender service started and set to Automatic."
    }
    else
    {
        Log "Windows Defender service is already running."
    }
}
catch
{
    Log "Error remediating Defender service: $($_.Exception.Message)"
}


# RTP Remediation
try
{
    Log "Checking Real Time Protection..."
    $check = Get-MpComputerStatus

    if ($check.RealTimeProtectionEnabled -eq $true)
    {
        Log "Real Time Protection already ON."
    }
    else
    {
        Log "Real Time Protection is OFF. Enabling now..."
        Set-MpPreference -DisableRealtimeMonitoring $false
        Log "Real Time Protection enable command applied."
    }
}
catch
{
    Log "Error remediating Real Time Protection: $($_.Exception.Message)"
}


#BitLocker Remediation
try
{
    Log "Checking BitLocker status on C: ..."
    $bitlocker = Get-BitLockerVolume -MountPoint "C:"

    if ($bitlocker.ProtectionStatus -eq "On")
    {
        Log "BitLocker is already enabled."
    }
    else
    {
        Log "BitLocker protection is OFF. Attempting to enable..."

        #Checks TPM Status
        $tpmOk = $false
        try 
	{
            $tpm = Get-Tpm
            if ($tpm.TpmPresent -and $tpm.TpmReady) 
	    { 
		$tpmOk = $true 
	    }
        } 
	catch 
	{
            $tpmOk = $false
        }

        if ($tpmOk -eq $false)
        {
            Log "TPM not present/ready. Cannot enable BitLocker with TPM protector."
        }
        else
        {
            Log "TPM OK. Enabling BitLocker with TPM protector..."

            Enable-BitLocker `
                -MountPoint "C:" `
                -EncryptionMethod XtsAes128 `
                -UsedSpaceOnly `
                -TpmProtector `
                -SkipHardwareTest

            Log "Enable-BitLocker command sent. Encryption/Protection may take a moment."
        }
    }
}
catch
{
    Log "Error remediating BitLocker: $($_.Exception.Message)"
}

#Secure Boot (Marks in Logs -> Cannot remediate through PS)
try
{
    Log "Checking Secure Boot..."
    $secureBoot = Confirm-SecureBootUEFI

    if ($secureBoot -eq $true)
    {
        Log "Secure Boot already enabled."
    }
    else
    {
        Log "Secure Boot is NOT enabled."
        Log "MANUAL ACTION REQUIRED: Enable UEFI + Secure Boot in BIOS/VM firmware settings."
    }
}
catch
{
    Log "Secure Boot cannot be checked."
    Log "MANUAL ACTION REQUIRED."
}

Log "==================== ACRT REMEDIATION END ===================="
Write-Output "Remediation complete. See report: $ReportFile"
exit 0