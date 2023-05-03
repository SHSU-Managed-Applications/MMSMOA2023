### EXAMPLE SCRIPT. NOT FOR PRODUCTION USE. ###

Start-Transcript -Path "$env:windir\Logs\Software\MEM_EndpointSecurity_Compliance.log"
#==============================
# MPCOMPUTERSTATUS
#==============================
Write-Output "### ENDPOINT PROTECTION COMPUTER STATUS EVALUATION ###"
$MPComputerStatus = Get-MpComputerStatus
$MPComputerNOTCompliantCount = 0
$MPComputerStatusArray = @(                 
    "AMRunningMode,Normal",
    "AMServiceEnabled,True",
    "AntispywareEnabled,True",
    "AntivirusEnabled,True",
    "BehaviorMonitorEnabled,True",
    "ComputerState,0",
    "IoavProtectionEnabled,True",
    "IsTamperProtected,False",
    "NISEnabled,True",
    "OnAccessProtectionEnabled,True",
    "RealTimeProtectionEnabled,True",
    "RealTimeScanDirection,0"
)
# Evaluate each Setting in the array for compliance with the desired value
Foreach ($setting in $MPComputerStatusArray) {
    # Seperate out each item from the Array
    $configuration = ($setting.Split(","))[0]
    $value = ($setting.Split(","))[1]
    # Save the current value of the setting
    $currentValue = $MPComputerStatus.$configuration
    # Check current value against the desired value that was specified in the array
    if ("$currentValue" -eq "$value") {
        Write-Output "$configuration is COMPLIANT with value $value"
    } else {
        Write-Output "$configuration is NOT COMPLIANT with value $value"
        $MPComputerNOTCompliantCount += 1
    }
    # Validated the compliance count for MPPreference settings. If the number of compliant devices is NOT 0, we set compliance to False
    if ($MPComputerNOTCompliantCount -eq 0){
        $MPComputerComp=$true
    } else {
        $MPComputerComp=$false
    }
}
#==============================
# MPPREFERENCE
#==============================
Write-Output "### ENDPOINT PROTECTION PREFERENCE EVALUATION ###"
$MPPreference = Get-MpPreference
$MPPreferenceNOTCompliantCount = 0
# ASRArray values can be aligned with the AttackSurfaceReductionRuleIDs if specific settings need to be in separate modes.
$ASRArray = @("1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1") # 0 = Off ; 1 = Block ; 2 = Audit ; 6 = Warn
$MPPreferenceArray = @(
    "AttackSurfaceReductionRules_Actions,$ASRArray",
    "CheckForSignaturesBeforeRunningScan,True",
    "CloudBlockLevel,2",
    "CloudExtendedTimeout,45",
    "DefinitionUpdatesChannel,0",
    "DisableArchiveScanning,False",
    "DisableAutoExclusions,False",
    "DisableBehaviorMonitoring,False",
    "DisableBlockAtFirstSeen,False",
    "DisableCatchupFullScan,False",
    "DisableCatchupQuickScan,False",
    "DisableCpuThrottleOnIdleScans,True",
    "DisableDatagramProcessing,False",
    "DisableDnsOverTcpParsing,False",
    "DisableDnsParsing,False",
    "DisableEmailScanning,False",
    "DisableFtpParsing,False",
    "DisableGradualRelease,False",
    "DisableHttpParsing,False",
    "DisableInboundConnectionFiltering,False",
    "DisableIOAVProtection,False",
    "DisableNetworkProtectionPerfTelemetry,False",
    "DisablePrivacyMode,False",
    "DisableRdpParsing,False",
    "DisableRealtimeMonitoring,False",
    "DisableRemovableDriveScanning,True",
    "DisableRestorePoint,True",
    "DisableScanningMappedNetworkDrivesForFullScan,True",
    "DisableScanningNetworkFiles,False",
    "DisableScriptScanning,False",
    "DisableSmtpParsing,False",
    "DisableSshParsing,False",
    "DisableTlsParsing,False",
    "EnableControlledFolderAccess,2",
    "EnableLowCpuPriority,False",
    "EnableNetworkProtection,1",
    "EngineUpdatesChannel,0",
    "ForceUseProxyOnly,False",
    "HighThreatDefaultAction,2",
    "LowThreatDefaultAction,2",
    "MAPSReporting,2",
    "ModerateThreatDefaultAction,2",
    "PlatformUpdatesChannel,0",
    "PUAProtection,1",
    "QuarantinePurgeItemsAfterDelay,30",
    "RandomizeScheduleTaskTimes,True",
    "RealTimeScanDirection,0",
    "RemediationScheduleDay,0",
    "RemediationScheduleTime,02:00:00",
    "ScanAvgCPULoadFactor,30",
    "ScanOnlyIfIdleEnabled,True",
    "ScanParameters,2",
    "ScanPurgeItemsAfterDelay,30",
    "ScanScheduleDay,3",
    "ScanScheduleQuickScanTime,10:00:00",
    "ScanScheduleTime,02:00:00",
    "SevereThreatDefaultAction,2",
    "SignatureDisableUpdateOnStartupWithoutEngine,False",
    "SignatureFallbackOrder,MMPC|MicrosoftUpdateServer",
    "SignatureScheduleDay,0",
    "SignatureScheduleTime,02:00:00",
    "SignatureUpdateCatchupInterval,1",
    "SignatureUpdateInterval,1",
    "SubmitSamplesConsent,3",
    "ThrottleForScheduledScanOnly,True",
    "UILockdown,False",
    "UnknownThreatDefaultAction,0"
)
# Evaluate each Setting in the array for compliance with the desired value
Foreach ($setting in $MPPreferenceArray) {
    # Seperate out each item from the Array
    $configuration = ($setting.Split(","))[0]
    $value = ($setting.Split(","))[1]
    # Save the current value of the setting
    $currentValue = $MPPreference.$configuration
    # Check current value against the desired value that was specified in the array
    if ("$currentValue" -eq "$value") {
        Write-Output "$configuration is COMPLIANT with value $value"
    } else {
        Write-Output "$configuration is NOT COMPLIANT with value $value"
        $MPPreferenceNOTCompliantCount += 1
    }
    # Validated the compliance count for MPPreference settings. If the number of compliant devices is NOT 0, we set compliance to False
    if ($MPPreferenceNOTCompliantCount -eq 0){
        $MPPreferenceComp=$true
    } else {
        $MPPreferenceComp=$false
    }
}
#==============================
# COMPLIANCE CHECK
#==============================
# Valdate both MPComputerStatusComp and MPPreferenceComp are both equal to True
if ($MPComputerComp -and $MPPreferenceComp) {
    Write-Host "COMPLIANT" -ForegroundColor Green
    Stop-Transcript
    [System.Environment]::Exit(0)
} else {
    Write-Host "NOT COMPLIANT" -ForegroundColor Red
    Stop-Transcript
    [System.Environment]::Exit(1)
}
