##############################################################################################################
########                                    IBM HTTP Server CmdLets                                  #########
##############################################################################################################

enum StartupType {
    Automatic
    Manual
    Disabled
}

# Global Variables / Resource Configuration
$IHS_SVC_PREFIX = "IBMHTTPServerV"
$IHS_ADM_SVC_PREFIX = "IBMHTTPAdmin"


##############################################################################################################
# Get-IBMHTTPServerInstallLocation
#   Returns the location where IBM HTTP Server is installed
##############################################################################################################
Function Get-IBMHTTPServerInstallLocation() {
    [CmdletBinding(SupportsShouldProcess=$False)]
    param (
        [parameter(Mandatory=$false,position=1)]
        [System.Version] $Version = "8.5.0.0"
    )

    Write-Verbose "Get-IBMHTTPServerInstallLocation::ENTRY(Version=$Version)"
    
    $ihsPath = Get-IBMWebSphereProductRegistryPath "HTTP Server" $Version
    if ($ihsPath -and $ihsPath.StartsWith("HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
    }
    
    if (($ihsPath) -and (Test-Path($ihsPath))) {
        $ihsHome = (Get-ItemProperty($ihsPath)).installPath
        if ($ihsHome -and (Test-Path $ihsHome)) {
            Write-Verbose "Get-IBMHTTPServerInstallLocation returning $ihsHome"
            Return $ihsHome
        }
    }
    Return $null
}

##############################################################################################################
# Install-IBMHTTPServer
#   Installs IBM HTTP Server
##############################################################################################################
Function Install-IBMHTTPServer() {
    [CmdletBinding(SupportsShouldProcess=$False)]
    param (
        [parameter(Mandatory = $true)]
		[String] $InstallMediaConfig,
        
        [parameter(Mandatory = $true)]
		[String] $ResponseFileTemplate,
        
    	[parameter(Mandatory = $true)]
		[String] $InstallationDirectory,
        
        [parameter()]
		[String] $IHSPluginInstallLocation,
        
        [parameter()]
		[String] $ToolBoxInstallLocation,
        
        [Int] $HTTPPort = 80,
        
        [StartupType] $StartupType = [StartupType]::Automatic,
        
        [PSCredential] $WindowsServiceAccount,
        
        [parameter(Mandatory = $true)]
		[String] $IMSharedLocation,

    	[parameter(Mandatory = $true)]
		[String] $SourcePath,

        [PSCredential] $SourcePathCredential
	)
    
    $installed = $false
    [Hashtable] $Variables = @{}
    $Variables.Add("sharedLocation", $IMSharedLocation)
    $Variables.Add("ihsInstallLocation", $InstallationDirectory)
    $Variables.Add("ihsPluginInstallLocation", $IHSPluginInstallLocation)
    $Variables.Add("toolBoxInstallLocation", $ToolBoxInstallLocation)
    $Variables.Add("httpPort", $HTTPPort)
    if ($StartupType -eq [StartupType]::Automatic) {
        $Variables.Add("serviceStartType", "auto")
    } elseif ($StartupType -eq [StartupType]::Manual) {
        $Variables.Add("serviceStartType", "demand")
    }
    if ($WindowsServiceAccount) {
        $Variables.Add("serviceAccUsername", $WindowsServiceAccount.UserName)
        $Variables.Add("serviceAccPassword", $WindowsServiceAccount)
    } else {
        $Variables.Add("useServiceAcc", "true")
    }
    
    $portOpen = Test-NetConnection -ComputerName localhost -Port $HTTPPort -InformationLevel Quiet
    if (!$portOpen) {
        $installed = Install-IBMProduct -InstallMediaConfig $InstallMediaConfig `
                        -ResponseFileTemplate $ResponseFileTemplate -Variables $Variables `
                        -SourcePath $SourcePath -SourcePathCredential $SourcePathCredential -ErrorAction Stop
    } else {
        Write-Error "The port $HTTPPort is already in used, please use a different port"
    }
    
    if ($installed) {
        Start-IBMHTTPServer
    }

    Return $installed
}

##############################################################################################################
# Install-IBMHTTPServerFixpack
#   Installs IBM HTTP Server Fixpack
##############################################################################################################
Function Install-IBMHTTPServerFixpack() {
    [CmdletBinding(SupportsShouldProcess=$False)]
    param (
        [parameter(Mandatory=$false)]
        [Version] $Version = "8.5.0.0",
        
        [parameter(Mandatory = $true)]
		[String] $InstallationDirectory,
        
        [parameter(Mandatory = $true)]
        [PSCredential] $WebSphereAdministratorCredential,

    	[parameter(Mandatory = $true)]
		[String[]] $SourcePath,

        [PSCredential] $SourcePathCredential
	)
    
    [string] $productId = $null
    if ($Version.ToString(2) -eq "8.5") {
        $productId = "com.ibm.websphere.IHS.v85"
    } else {
        Write-Error "Fixpack version not supported at this time"
    }

    [bool] $updated = $false
    [string] $httpServerDir = $InstallationDirectory
    
    # Disable the WAS services
    Get-Service -Name "IBMHTTPServerV8.5" | Stop-Service -PassThru | Set-Service -StartupType disabled
    
    # Stop all servers
    $fileLocked = Wait-AllFileReleased (Join-Path $httpServerDir "bin")
    
    if($fileLocked){
        Write-Error "File Locked IBMHTTPServerFixpack installation Aborted"
    }
    $updated = Install-IBMProductViaCmdLine -ProductId $productId -InstallationDirectory $httpServerDir `
        -SourcePath $SourcePath -SourcePathCredential $SourcePathCredential -ErrorAction Stop
    
    if ($updated) {        
        # Enable the IHS service and Start Server
        Get-Service -Name "IBMHTTPServerV8.5" | Start-Service -PassThru | Set-Service -StartupType Manual
    }
    
    Return $updated
}

##############################################################################################################
# Start-IBMHTTPServer
#   Starts the IBM HTTP Server
##############################################################################################################
Function Start-IBMHTTPServer {
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param ()

    $ihsSvcName = $IHS_SVC_PREFIX + "*"
    $ihsSvc = Get-Service -Name $ihsSvcName
    
    if ($ihsSvc) {
        if ($ihsSvc.Status -ne "Running") {
            Write-Verbose "Starting IBM HTTP Server via Windows Service"
            Start-Service $ihsSvc
        } else {
            Write-Verbose "IBM HTTP Server already started"
        }
    }
}

##############################################################################################################
# Stop-IBMHTTPServer
#   Stops the IBM HTTP Server
##############################################################################################################
Function Stop-IBMHTTPServer {
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param ()

    $ihsSvcName = $IHS_SVC_PREFIX + "*"
    $ihsSvc = Get-Service -Name $ihsSvcName
    
    if ($ihsSvc) {
        if ($ihsSvc.Status -ne "Stopped") {
            Write-Verbose "Stopping IBM HTTP Server via Windows Service"
            Stop-Service $ihsSvc
        } else {
            Write-Verbose "IBM HTTP Server already stopped"
        }
    }
}


##############################################################################################################
# Start-IBMHTTPAdminService
#   Starts the IBM HTTP Admin Service 
##############################################################################################################
Function Start-IBMHTTPAdminService {
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param ()

    $ihsSvcName = $IHS_ADM_SVC_PREFIX + "*"
    $ihsSvc = Get-Service -Name $ihsSvcName
    
    if ($ihsSvc) {
        if ($ihsSvc.Status -ne "Running") {
            Write-Verbose "Starting IBM HTTP Admin Service via Windows Service"
            Start-Service $ihsSvc
        } else {
            Write-Verbose "IBM HTTP Admin Service already started"
        }
    }
}

##############################################################################################################
# Stop-IBMHTTPAdminService
#   Stops the IBM HTTP Admin Service
##############################################################################################################
Function Stop-IBMHTTPAdminService {
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param ()

    $ihsSvcName = $IHS_ADM_SVC_PREFIX + "*"
    $ihsSvc = Get-Service -Name $ihsSvcName
    
    if ($ihsSvc) {
        if ($ihsSvc.Status -ne "Stopped") {
            Write-Verbose "Stopping IBM HTTP Admin Service via Windows Service"
            Stop-Service $ihsSvc
        } else {
            Write-Verbose "IBM HTTP Admin Service already stopped"
        }
    }
}



##############################################################################################################
# Invoke-GskCmd
#   Wrapper function for gskcmd.bat
##############################################################################################################
Function Invoke-GskCmd() {
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param (
        [Parameter(Mandatory=$true,position=0)]
        [String[]] $Commands,
        
        [Parameter(Mandatory=$false,position=1)]
        [PSCredential] $KeyDBPassword,
        
        [switch] $Target
    )

    $ihsInstallDir = Get-IBMHTTPServerInstallLocation
    [string] $gskcmdBat = Join-Path -Path $ihsInstallDir -ChildPath "bin\gskcmd.bat"
    [PSCustomObject] $gskCmdProcess = @{
        StdOut = $null
        StdErr = $null
        ExitCode = $null
    }
    if (Test-Path($gskcmdBat)) {
        [string[]] $gskArgs = $Commands
        # Add credentials
        if ($KeyDBPassword) {
            $keyPwd = $KeyDBPassword.GetNetworkCredential().Password
            if ($Target) {
                $gskArgs += @("-target_pw", $keyPwd)
            } else {
                $gskArgs += @("-pw", $keyPwd)
            }
        }
        $gskCmdProcess = Invoke-ProcessHelper -ProcessFileName $gskcmdBat -ProcessArguments $gskArgs `
                            -WorkingDirectory (Split-Path($gskcmdBat))
        if (!$gskCmdProcess -or (($gskCmdProcess.StdErr)) -and ($gskCmdProcess.ExitCode -ne 0)) {
            $errorMsg = $null
            if ($gskCmdProcess -and $gskCmdProcess.StdErr) {
                $errorMsg = $gskCmdProcess.StdErr
            } else {
                $errorMsg = $gskCmdProcess.StdOut
            }
            $exitCode = (&{if($gskCmdProcess) {$gskCmdProcess.ExitCode} else {$null}})
            Write-Error "An error occurred while executing the gskcmd.bat process. ExitCode: $exitCode Mesage: $errorMsg"
        }
    } else {
        Write-Error "Unable to locate gskcmd.bat using: $gskcmdBat"
    }
    Return $gskCmdProcess
}

##############################################################################################################
# New-IBMSSLKeyDatabase
#   Creates a new key database
##############################################################################################################
Function New-IBMSSLKeyDatabase() {
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param (
        [Parameter(Mandatory=$true,position=0)]
        [String] $KeyDBPath,
        
        [Parameter(Mandatory=$true,position=1)]
        [PSCredential] $KeyDBPassword,

        [Parameter(Mandatory=$false,position=2)]
        [String] $DBType = 'cms',

        [switch] $Stash
    )

    $keydbCreated = $false

    if (!(Test-Path $KeyDBPath -PathType Leaf)) {
        if (!(Test-Path (Split-Path $KeyDBPath))) {
            # Parent folder does not exist, create it
            New-Item -Path (Split-Path $KeyDBPath) -Type Directory -Force | Out-Null
            if (!(Test-Path (Split-Path $KeyDBPath))) {
                Write-Error "Unable to create parent folder for key database"
            }
        }
        [string[]] $gskArgs = @("-keydb","-create","-db",$KeyDBPath,"-type",$DBType)

        if ($Stash) {
            $gskArgs += "-stash"
        }
        
        $gskCmdProcess = Invoke-GskCmd -Commands $gskArgs -KeyDBPassword $KeyDBPassword
        if ($gskCmdProcess) {
            if (([string]$gskCmdProcess.StdOut).Trim().Length -eq 0) {
                $keydbCreated = $true
            } else {
                $errorMsg = $gskCmdProcess.StdOut
                Write-Error "An error ocurred while creating the Key Database: $errorMsg"
            }
        }
    } else {
        Write-Error "Key Database already exits or path is invalid: $KeyDBPath"
    }
    Return $keydbCreated
}

##############################################################################################################
# Get-IBMKeyDBCertificates
#   Returns a list of SSL certificate labels stored in a Key Database
##############################################################################################################
Function Get-IBMKeyDBCertificates() {
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param (
        [Parameter(Mandatory=$true,position=0)]
        [String] $KeyDBPath,
        
        [Parameter(Mandatory=$true,position=1)]
        [PSCredential] $KeyDBPassword
    )
    [string[]] $certificateLabels = $null

    if (Test-Path $KeyDBPath -PathType Leaf) {
        [string[]] $gskArgs = @("-cert","-list","-db",$KeyDBPath)
        $gskCmdProcess = Invoke-GskCmd -Commands $gskArgs -KeyDBPassword $KeyDBPassword
        if ($gskCmdProcess -and $gskCmdProcess.StdOut) {
            if ($gskCmdProcess.StdOut.Contains("Certificates in database")) {
                $certificateLabels = @()
                ($gskCmdProcess.StdOut -split [environment]::NewLine) | ? {
                    if (!([string]$_).Contains("Certificates in database")) {
                        $certificateLabels += ([string]$_).Trim()
                    }
                }
            } else {
                $errorMsg = $gskCmdProcess.StdOut
                Write-Error "An error ocurred while listing the certificates: $errorMsg"
            }
        }
    } else {
        Write-Error "Invalid Key Database"
    }
    Return $certificateLabels
}

##############################################################################################################
# Get-IBMKeyDBDefaultCertificate
#   Returns the default SSL certificate label for the specified Key Database
##############################################################################################################
Function Get-IBMKeyDBDefaultCertificate() {
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param (
        [Parameter(Mandatory=$true,position=0)]
        [String] $KeyDBPath,
        
        [Parameter(Mandatory=$true,position=1)]
        [PSCredential] $KeyDBPassword
    )
    [string] $certificateLabel = $null

    if (Test-Path $KeyDBPath -PathType Leaf) {
        [string[]] $gskArgs = @("-cert","-getdefault","-db",$KeyDBPath)
        $gskCmdProcess = Invoke-GskCmd -Commands $gskArgs -KeyDBPassword $KeyDBPassword
        if ($gskCmdProcess -and $gskCmdProcess.StdOut) {
            [string] $labelStr = "Label: "
            if ($gskCmdProcess.StdOut.Contains($labelStr)) {
                ($gskCmdProcess.StdOut -split [environment]::NewLine) | ? {
                    if (([string]$_).Contains($labelStr)) {
                        $certificateLabel = ([string]$_).Trim().Substring($labelStr.Length)
                    }
                }
            } else {
                $errorMsg = $gskCmdProcess.StdOut
                Write-Error "An error ocurred while listing the certificates: $errorMsg"
            }
        }
    } else {
        Write-Error "Invalid Key Database"
    }
    Return $certificateLabel
}

##############################################################################################################
# Add-SSLCertificateToIBMKeyDB
#   Adds an SSL Certificate to the IBM Key Database specified
##############################################################################################################
Function Add-SSLCertificateToIBMKeyDB() {
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param (
        [Parameter(Mandatory=$true)]
        [String] $KeyDBPath,
        
        [Parameter(Mandatory=$true)]
        [PSCredential] $KeyDBPassword,

        [Parameter(Mandatory=$false)]
        [String] $CertificateType = "pfx",

        [Parameter(Mandatory=$true)]
        [String] $CertificatePath,

        [Parameter(Mandatory=$true)]
        [PSCredential] $CertificatePassword,

        [PSCredential] $CertificatePathCredential,

        [String] $DefaultCertificateLabel
    )

    $certAdded = $false

    if (Test-Path $KeyDBPath -PathType Leaf) {
        $certTempPath = Copy-RemoteItemLocal -Source $CertificatePath -SourceCredential $CertificatePathCredential -Verbose 
        Try {
	        [string[]] $gskArgs = @("-cert","-import","-file",$certTempPath)
	        $certPwd = $CertificatePassword.GetNetworkCredential().Password
	        $gskArgs += @("-pw", $certPwd)
	        $gskArgs += @("-target", $KeyDBPath, "-$CertificateType")
	        
	        $gskCmdProcess = Invoke-GskCmd -Commands $gskArgs -KeyDBPassword $KeyDBPassword -Target
	        if ($gskCmdProcess) {
	            if (([string]$gskCmdProcess.StdOut).Trim().Length -eq 0) {
	                $certAdded = $true
	            } else {
	                $errorMsg = $gskCmdProcess.StdOut
	                Write-Error "An error ocurred while adding the certificate to the Key Database: $errorMsg"
	            }
	        }
	
	        if ($certAdded -and (!([string]::IsNullOrEmpty($DefaultCertificateLabel)))) {
	            $gskSetDefaultArgs = @("-cert", "-setdefault", "-db", $KeyDBPath, "-label",('"' + $DefaultCertificateLabel + '"'))
	            $gskCmdProcess = Invoke-GskCmd -Commands $gskSetDefaultArgs -KeyDBPassword $KeyDBPassword
	            $certAdded = $false
	            if ($gskCmdProcess) {
	                if (([string]$gskCmdProcess.StdOut).Trim().Length -eq 0) {
	                    $certAdded = $true
	                } else {
	                    $errorMsg = $gskCmdProcess.StdOut
	                    Write-Error "An error ocurred setting the certificate label $DefaultCertificateLabel as default: $errorMsg"
	                }
	            }
	        }
        } Finally {
        	#Delete wildcase certificate
			if(Test-Path($certTempPath)){
	            Remove-Item $certTempPath -Force
	        }
        }
    } else {
        Write-Error "Invalid Key Database: $KeyDBPath"
    }
    Return $certAdded
}


##############################################################################################################
# Invoke-CommandHelper
#   Wrapper of Invoke-ProcessHelper for Remote Process Execution
##############################################################################################################
Function Invoke-CommandHelper(){
	[CmdletBinding(SupportsShouldProcess=$False)]
    Param (
        [String] $ComputerName,
        
        [PSCredential] $RunAsCredential,
        
        [Parameter(Mandatory)]
        [String] $ProcessFileName,

        [String[]] $ProcessArguments,

        [String] $WorkingDirectory,
		
        [switch] $DiscardStandardOut,

        [switch] $DiscardStandardErr,
        
        [switch] $LogToFile,
        
        [switch] $RunasAdmin
    )
    if(!$ComputerName){
    	$ComputerName = $env:COMPUTERNAME
    }

    [Hashtable] $arguments = @{
		'processFileName' = $ProcessFileName
		'processArguments' = $ProcessArguments
		'workingDirectory' = $WorkingDirectory
		'discardStandardOut' = $DiscardStandardOut.isPresent
		'discardStandardErr' = $DiscardStandardErr.isPresent
		'logToFile' = $LogToFile.isPresent
		'runasAdmin' = $RunasAdmin.isPresent
	}

	[PSCustomObject] $cmdResult = $null
	Try{
		
		
		$scriptBlock = {
	    	param($arguments)
	    	
	    	$procResult = Invoke-ProcessHelper `
	    						-ProcessFileName $arguments.processFileName `
	    						-ProcessArguments $arguments.processArguments `
	    						-WorkingDirectory $arguments.workingDirectory `
	    						-DiscardStandardOut:$arguments.discardStandardOut `
	    						-DiscardStandardErr:$arguments.discardStandardErr `
	    						-LogToFile:$arguments.logToFile `
	    						-RunasAdmin:$arguments.runasAdmin
	    	
	    	return $procResult
	    }
	    
	    $session = New-PSSession -ComputerName $ComputerName -Credential $RunAsCredential
	    $cmdResult = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $arguments
	    
	} finally {
        if ($session){
        	Remove-PSSession $session
        }
    }
    
	return $cmdResult
}


##############################################################################################################
# Invoke-CommandHelper
#   Wrapper of Any CmdLet for Remote Process Execution
##############################################################################################################
Function Invoke-CommandHelper(){
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param (
		[Parameter(Mandatory=$true,position=0)]
        [ScriptBlock] $ScriptBlock,

        [Parameter(Mandatory=$false,position=1)]
        [Hashtable] $Arguments = $null,
        
        [Parameter(Mandatory=$false,position=2)]
		[String] $ComputerName,
        
        [Parameter(Mandatory=$false,position=3)]
        [PSCredential] $RunAsCredential
    )
    if(!$ComputerName){
    	$ComputerName = $env:COMPUTERNAME
    }
	[PSCustomObject] $cmdResult = $null
	Try{
	    $session = New-PSSession -ComputerName $ComputerName -Credential $RunAsCredential
	    $cmdResult = Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $arguments
	} finally {
        if ($session){
        	Remove-PSSession $session
        }
    }
	return $cmdResult

}

##############################################################################################################
# Invoke-WsAdminRemote
#   Wrapper of Invoke-WsAdmin for Remote Process Execution
##############################################################################################################
Function Invoke-WsAdminRemote(){
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param (
        [Parameter(Mandatory=$true,position=0)]
        [String]
        $ProfilePath,

        [Parameter(Mandatory=$false,position=1)]
        [String]
        $ScriptPath = $null,

        [Parameter(Mandatory=$false,position=2)]
        [String[]]
        $Commands = $null,
        
        [Parameter(Mandatory=$false,position=3)]
        [String[]]
        $Arguments = @(),
        
        [Parameter(Mandatory=$false,position=4)]
        [String[]]
        $ModulesPaths = @(),

        [Parameter(Mandatory=$false,position=5)]
        [System.Management.Automation.PSCredential]
        $WebSphereAdministratorCredential,
        
        [Parameter(Mandatory=$false,position=6)]
        [ValidateSet('jython', 'jacl')]
        [String]
        $Lang = 'jython',
        
        [parameter(Mandatory=$false,position=7)]
        [String]
        $OutputFilter = 'WASX', 
        
        [switch] $LogToFile,
        
		[String] $ComputerName,
        
        [PSCredential] $RunAsCredential
    )
    
    [Hashtable] $arguments = @{
		'ProfilePath' = $ProfilePath
		'ScriptPath' = $ScriptPath
		'Commands' = $Commands
		'Arguments' = $Arguments
		'ModulesPaths' = $ModulesPaths
		'WebSphereAdministratorCredential' = $WebSphereAdministratorCredential
		'Lang' = $Lang
		'OutputFilter' = $OutputFilter
		'logToFile' = $LogToFile.isPresent
	}
	
	[ScriptBlock] $scriptBlock = {
		param($arguments)
	    	
    	$procResult = Invoke-WsAdmin `
    						-ProfilePath $arguments.ProfilePath `
    						-ScriptPath $arguments.ScriptPath `
    						-Commands $arguments.Commands `
    						-Arguments $arguments.Arguments `
    						-ModulesPaths $arguments.ModulesPaths `
    						-WebSphereAdministratorCredential $arguments.WebSphereAdministratorCredential `
    						-Lang $arguments.Lang `
    						-OutputFilter $arguments.OutputFilter `
    						-LogToFile:$arguments.logToFile
    	
    	return $procResult
    }
    
	return Invoke-CommandHelper $scriptBlock $arguments $ComputerName $RunAsCredential
}


##############################################################################################################
# Invoke-ProcessHelperRemote
#   Wrapper of Invoke-ProcessHelper for Remote Process Execution
##############################################################################################################
Function Invoke-ProcessHelperRemote(){
	[CmdletBinding(SupportsShouldProcess=$False)]
    Param (
        [Parameter(Mandatory=$True, Position=0)]
        [String]
        [ValidateNotNullOrEmpty()]
        $ProcessFileName,

        [Parameter(Mandatory=$False, Position=1)]
        [String[]]
        $ProcessArguments,

        [Parameter(Mandatory=$False, Position=2)]
        [String]
        $WorkingDirectory,
		
        [switch]
        $DiscardStandardOut,

        [switch]
        $DiscardStandardErr,
        
        [switch]
        $LogToFile,
        
        [switch]
        $RunasAdmin,
        
		[String] $ComputerName,
        
        [PSCredential] $RunAsCredential
    )
    [Hashtable] $arguments = @{
		'processFileName' = $ProcessFileName
		'processArguments' = $ProcessArguments
		'workingDirectory' = $WorkingDirectory
		'discardStandardOut' = $DiscardStandardOut.isPresent
		'discardStandardErr' = $DiscardStandardErr.isPresent
		'logToFile' = $LogToFile.isPresent
		'runasAdmin' = $RunasAdmin.isPresent
	}
	
	[ScriptBlock] $scriptBlock = {
	    	param($arguments)
	    	$procResult = Invoke-ProcessHelper `
	    						-ProcessFileName $arguments.processFileName `
	    						-ProcessArguments $arguments.processArguments `
	    						-WorkingDirectory $arguments.workingDirectory `
	    						-DiscardStandardOut:$arguments.discardStandardOut `
	    						-DiscardStandardErr:$arguments.discardStandardErr `
	    						-LogToFile:$arguments.logToFile `
	    						-RunasAdmin:$arguments.runasAdmin
	    	
	    	return $procResult
	    }
	return Invoke-CommandHelper $scriptBlock $arguments $ComputerName $RunAsCredential
}


##############################################################################################################
# Invoke-GenPluginCfg
#   Wrapper cmdlet for running GenPluginCfg. Returns the location of the plugin-cfg.xml generated
##############################################################################################################
Function Invoke-GenPluginCfg()
{
    [CmdletBinding(SupportsShouldProcess=$False)]
	Param
    (
        [parameter(Mandatory=$true,position=0)]
        [string]
        $ProfileDir,
        
        [parameter(Mandatory=$false,position=1)]
        [string]
        $ClusterName,
        
        [parameter(Mandatory=$false,position=2)]
        [string]
        $CellName,
        
        [parameter(Mandatory=$false,position=3)]
        [string]
        $NodeName,

        [parameter(Mandatory=$false,position=4)]
        [string]
        $ServerName,

        [parameter(Mandatory=$false,position=5)]
        [string]
        $WebServerName = $null,
        
        [switch] $Propagate
    )

    $pluginFileGenerated = $null

    $profileBinPath = Join-Path -Path $ProfileDir -ChildPath "bin"
    $genPluginCfgBatch = Join-Path -Path $profileBinPath -ChildPath "GenPluginCfg.bat"

    if (Test-Path($genPluginCfgBatch))
    {
        $genPluginCfgArgs = @('-destination.operating.system', 'windows')
        if ($CellName) {
            $genPluginCfgArgs += @('-cell.name', $CellName)
        }
        if ($ClusterName) {
            $genPluginCfgArgs += @('-cluster.name', $ClusterName)
        }
        if ($NodeName) {
            $genPluginCfgArgs += @('-node.name', $NodeName)
        }
        if ($WebServerName) {
            $genPluginCfgArgs += @('-webserver.name', $WebServerName)
        }
        if ($ServerName) {
            $genPluginCfgArgs += @('-server.name', $ServerName)
        }
        if ($Propagate) {
            $genPluginCfgArgs += @('-propagate', 'yes')
        }
        $pluginCfgProc = Invoke-ProcessHelper $genPluginCfgBatch $genPluginCfgArgs (Split-Path($genPluginCfgBatch))
            
		if ($pluginCfgProc -and ($pluginCfgProc.exitCode -eq 0)){
			Write-Verbose "Processed $genPluginCfgBatch successfully!"      
        	Write-Verbose $pluginCfgProc.StdOut
        	$pluginFileGenerated = $True
        }else{
			Write-Error "An error occurred while executing the wctcmd.bat process. ExitCode: $pluginCfgProc.exitCode Mesage: $pluginCfgProc.errorMsg"
        }
    }
    else
    {
        Write-Error "GenPluginCfg Batch not found: $genPluginCfgBatch"
    }

    Return $pluginFileGenerated
}

##############################################################################################################
# Test-WebServerExists
##############################################################################################################
Function Test-WebServerExists{
	[CmdletBinding(SupportsShouldProcess=$False)]
    Param (
    	[parameter(Mandatory=$True, Position=0)]
    	[String] $ServerType,
    	
    	[parameter(Mandatory=$True, Position=1)]
    	[String] $CellName,
    	
    	[parameter(Mandatory=$True, Position=2)]
    	[String] $ServerName,
    	
		[parameter(Mandatory=$True, Position=3)]
        [String] $ProfilePath,
        
        [Parameter(Mandatory = $True, position=4)]
        [PSCredential] $AdminCredential
    )
    $serverLstString = Get-ServerList $ServerType $ProfilePath $AdminCredential
	return $serverLstString -like "*$ServerName(cells/$CellName/*/servers/$ServerName|server.xml*"
}

##############################################################################################################
# List-WebServer
##############################################################################################################
Function Get-ServerList{
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param (
    	[parameter(Mandatory=$True, Position=0)]
    	[String] $ServerType,
    
		[parameter(Mandatory=$True, Position=1)]
        [String] $ProfilePath,
        
        [Parameter(Mandatory = $True, position=2)]
        [PSCredential] $AdminCredential
    )
    $wasCmd = "AdminTask.listServers('[-serverType $ServerType]')"
	$wasProc = Invoke-WsAdmin `
							-ProfilePath $ProfilePath `
							-Commands @($wasCmd) `
							-WebSphereAdministratorCredential $AdminCredential
    
    if($wasProc -and ($wasProc.ExitCode -eq 0)){
        Write-Verbose $wasProc.StdOut
        return $wasProc.StdOut
#        if($wasProc.StdOut -like "*$ClusterName(cells/*/clusters/$ClusterName|cluster.xml*"){
#            $result = $True
#        }
    }else{
        Write-Error "Invoke WsAdmin $wasCmd failed"
    }
}