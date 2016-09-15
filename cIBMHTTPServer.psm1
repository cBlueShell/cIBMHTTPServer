# Import IBM HTTP Server Utils Module
Import-Module $PSScriptRoot\cIBMHTTPServerUtils.psm1 -ErrorAction Stop

enum Ensure {
    Absent
    Present
}

enum StartupType {
    Automatic
    Manual
    Disabled
}

<#
   DSC resource to manage the installation of IBM HTTP Server.
   Key features: 
    - Install IBM HTTP Server for the first time
    - Can use media on the local drive as well as from a network share which may require specifying credentials
#>

[DscResource()]
class cIBMHTTPServer {
    
    [DscProperty(Mandatory)]
    [Ensure] $Ensure
    
    [DscProperty(Key)]
    [String] $Version
    
    [DscProperty()]
    [Int] $HTTPPort = 80
    
    [DscProperty()]
    [String] $InstallationDirectory = "C:\IBM\HTTPServer"
    
    [DscProperty()]
    [String] $IHSPluginInstallLocation = "C:\IBM\WebSphere\Plugins"
    
    [DscProperty()]
    [String] $ToolBoxInstallLocation = "C:\IBM\WebSphere\Toolbox"
    
    [DscProperty()]
    [String] $IMSharedLocation = "C:\IBM\IMShared"
    
    [DscProperty()]
    [StartupType] $StartupType = [StartupType]::Automatic
    
    [DscProperty()]
    [PSCredential] $WindowsServiceAccount
    
    [DscProperty()]
    [String] $InstallMediaConfig
    
    [DscProperty()]
    [String] $ResponseFileTemplate

    [DscProperty()]
    [String] $SourcePath
    
    [DscProperty()]
    [bool] $PlusPluginAndToolBox = $true
    
    
    [DscProperty()]
    [System.Management.Automation.PSCredential] $SourcePathCredential
    
    

    <#
        Installs IBM HTTP Server
    #>
    [void] Set () {
        try {
            if ($this.Ensure -eq [Ensure]::Present) {
                Write-Verbose -Message "Starting installation of IBM HTTP Server"
                $ihsVersion = $this.Version
                if (!($this.InstallMediaConfig)) {
                    $this.InstallMediaConfig = Join-Path -Path $PSScriptRoot -ChildPath "InstallMediaConfig\IHS-$ihsVersion.xml"
                }
                if (!($this.ResponseFileTemplate)) {
                	if($this.PlusPluginAndToolBox){
	                    $this.ResponseFileTemplate = Join-Path -Path $PSScriptRoot -ChildPath "ResponseFileTemplates\IHS-Plus-Plugin-$ihsVersion-template.xml"
                	}else{
	                    $this.ResponseFileTemplate = Join-Path -Path $PSScriptRoot -ChildPath "ResponseFileTemplates\IHS-$ihsVersion-template.xml"
                	}
                }
                $installed = Install-IBMHTTPServer `
			                	-InstallMediaConfig $this.InstallMediaConfig `
			                    -ResponseFileTemplate $this.ResponseFileTemplate `
			                    -InstallationDirectory $this.InstallationDirectory `
			                    -IHSPluginInstallLocation $this.IHSPluginInstallLocation `
			                    -ToolBoxInstallLocation $this.ToolBoxInstallLocation `
			                    -HTTPPort $this.HTTPPort `
			                    -StartupType $this.StartupType `
			                    -WindowsServiceAccount $this.WindowsServiceAccount `
			                    -IMSharedLocation $this.IMSharedLocation `
			                    -SourcePath $this.SourcePath `
			                    -SourcePathCredential $this.SourcePathCredential
                if ($installed) {
                    Write-Verbose "IBM HTTP Server Installed Successfully"
                } else {
                    Write-Error "Unable to install IBM HTTP Server, please check installation logs for more information"
                }
            } else {
                Write-Verbose "Uninstalling IBM HTTP Server (Not Yet Implemented)"
            }
        } catch {
            Write-Error -ErrorRecord $_ -ErrorAction Stop
        }
    }

    <#
        Performs test to check if IHS is in the desired state, includes 
        validation of installation directory and version
    #>
    [bool] Test () {
        Write-Verbose "Checking for IBM HTTP Server installation"
        if(Test-IBMPSDscSequenceDebug){return $True}
        $ihsConfiguredCorrectly = $false
        $ihsRsrc = $this.Get()
        
        if (($ihsRsrc.Ensure -eq $this.Ensure) -and ($ihsRsrc.Ensure -eq [Ensure]::Present)) {
            $sameVersion = ($ihsRsrc.Version -eq $this.Version)
            if (!($sameVersion)) {
                $currVersionObj = (New-Object -TypeName System.Version -ArgumentList $ihsRsrc.Version)
                $newVersionObj = (New-Object -TypeName System.Version -ArgumentList $this.Version)
                $sameVersion = (($currVersionObj.ToString(3)) -eq ($newVersionObj.ToString(3)))
            }
            if ($sameVersion) {
                if (((Get-Item($ihsRsrc.InstallationDirectory)).Name -eq 
                    (Get-Item($this.InstallationDirectory)).Name) -and (
                    (Get-Item($ihsRsrc.InstallationDirectory)).Parent.FullName -eq 
                    (Get-Item($this.InstallationDirectory)).Parent.FullName)) {
                    Write-Verbose "IBM HTTP Server is installed and configured correctly"
                    $ihsConfiguredCorrectly = $true
                }
            }
        } elseif (($ihsRsrc.Ensure -eq $this.Ensure) -and ($ihsRsrc.Ensure -eq [Ensure]::Absent)) {
            $ihsConfiguredCorrectly = $true
        }

        if (!($ihsConfiguredCorrectly)) {
            Write-Verbose "IBM HTTP Server not configured correctly"
        }
        
        return $ihsConfiguredCorrectly
    }

    <#
        Leverages the information stored in the registry to populate the properties of an existing
        installation of IHS
    #>
    [cIBMHTTPServer] Get () {
        $RetEnsure = [Ensure]::Absent
        $RetVersion = $null
        
        $versionObj = (New-Object -TypeName System.Version -ArgumentList $this.Version)
        $RetInsDir = Get-IBMHTTPServerInstallLocation $versionObj
        
        if($RetInsDir -and (Test-Path($RetInsDir))) {
            $VersionInfo = Get-IBMWebSphereProductVersionInfo $RetInsDir
            if($VersionInfo -and ($VersionInfo.Products) -and ($VersionInfo.Products["IHS"])) {
                Write-Verbose "IBM HTTP Server is Present"
                $RetEnsure = [Ensure]::Present
                $RetVersion = $VersionInfo.Products["IHS"].Version
            } else {
                Write-Warning "Unable to retrieve version information from the IBM HTTP Server installed"
            }
        } else {
            Write-Verbose "IBM HTTP Server is NOT Present"
        }

        $returnValue = @{
            InstallationDirectory = $RetInsDir
            Version = $RetVersion
            Ensure = $RetEnsure
        }

        return $returnValue
    }
}

[DscResource()]
class cIBMHTTPServerSSLCertificate {
    
    [DscProperty(Mandatory)]
    [Ensure] $Ensure
    
    [DscProperty(Key)]
    [String] $KeyDBPath

    [DscProperty(Mandatory)]
    [PSCredential] $KeyDBPassword
    
    [DscProperty(Key)]
    [String] $CertificateLabel
    
    [DscProperty()]
    [Boolean] $Default
    
    [DscProperty()]
    [String] $CertificatePath
    
    [DscProperty()]
    [PSCredential] $CertificatePassword
    
    [DscProperty()]
    [PSCredential] $CertificatePathCredential

    <#
        Adds SSL certificates to key database
    #>
    [void] Set () {
        try {
            if ($this.Ensure -eq [Ensure]::Present) {
                Write-Verbose -Message "Adding SSL certificate / key database"
                $addCert = $false
                if (!(Test-Path $this.KeyDBPath -PathType Leaf)) {
                    # Create new Key DB
                    $addCert = New-IBMSSLKeyDatabase -KeyDBPath $this.KeyDBPath -KeyDBPassword $this.KeyDBPassword -Stash
                    if (!$addCert) {
                        Write-Error "An issue occurred while creating the key database"
                    }
                } else {
                    $addCert = $true
                }
                
                if ($addCert) {
                    $sslCertAdded = $false
                    if ($this.Default) {
                        $sslCertAdded = Add-SSLCertificateToIBMKeyDB $this.KeyDBPath -KeyDBPassword $this.KeyDBPassword `
                             -CertificatePath $this.CertificatePath -CertificatePathCredential $this.CertificatePathCredential `
                             -CertificatePassword $this.CertificatePassword -DefaultCertificateLabel $this.CertificateLabel
                    } else {
                        $sslCertAdded = Add-SSLCertificateToIBMKeyDB $this.KeyDBPath -KeyDBPassword $this.KeyDBPassword `
                             -CertificatePath $this.CertificatePath -CertificatePathCredential $this.CertificatePathCredential `
                             -CertificatePassword $this.CertificatePassword
                    }
                }
            } else {
                Write-Verbose "Removing SSL certificate (Not Yet Implemented)"
            }
        } catch {
            Write-Error -ErrorRecord $_ -ErrorAction Stop
        }
    }

    <#
        Performs test to check if SSL certificates has been added to key database
    #>
    [bool] Test () {
        Write-Verbose "Checking if SSL Certificate has been installed"
        if(Test-IBMPSDscSequenceDebug){return $True}
        $certIsOK = $false
        $certRsrc = $this.Get()
        
        if (($certRsrc.Ensure -eq $this.Ensure) -and ($certRsrc.Ensure -eq [Ensure]::Present)) {
            if ($certRsrc.RetKeyDBPath -eq $this.RetKeyDBPath) {
                if ($certRsrc.RetCertLabel -eq $this.RetCertLabel) {
                    if ($certRsrc.Default -eq $this.Default) {
                        Write-Verbose "IBM SSL Certificate configured correctly"
                        $certIsOK = $true
                    }
                }
            }
        } elseif (($certRsrc.Ensure -eq $this.Ensure) -and ($certRsrc.Ensure -eq [Ensure]::Absent)) {
            $certIsOK = $true
        }

        if (!($certIsOK)) {
            Write-Verbose "IBM SSL Certificate not configured correctly"
        }
        
        return $certIsOK
    }

    <#
        Retreives current SSL config
    #>
    [cIBMHTTPServerSSLCertificate] Get () {
        $RetEnsure = [Ensure]::Absent
        $RetKeyDBPath = $null
        $RetCertLabel = $null
        $RetDefault = $false
        
        if (Test-Path $this.KeyDBPath -PathType Leaf) {
            $certs = Get-IBMKeyDBCertificates -KeyDBPath $this.KeyDBPath -KeyDBPassword $this.KeyDBPassword
            if ($certs) {
                $RetKeyDBPath = $this.KeyDBPath
                if ($certs.Contains($this.CertificateLabel)) {
                    $RetCertLabel = $this.CertificateLabel
                    $defaultCert = Get-IBMKeyDBDefaultCertificate -KeyDBPath $this.KeyDBPath -KeyDBPassword $this.KeyDBPassword
                    if ($RetCertLabel -eq $defaultCert) {
                        $RetEnsure = [Ensure]::Present
                        $RetDefault = $true
                    }
                }
            }
        }
        
        $returnValue = @{
            Ensure = $RetEnsure
            KeyDBPath = $RetKeyDBPath
            CertificateLabel = $RetCertLabel
            Default = $RetDefault
        }

        return $returnValue
    }
}

<#
   DSC resource to config WebSphere IHS plugin.
#>
[DscResource()]
class cIBMHTTPServerPluginConfig {
    [DscProperty(Mandatory)]
    [Ensure] $Ensure = [Ensure]::Present

	[DscProperty()]
    [String] $ConfigType = "remote"
	
	[DscProperty()]
    [Bool] $EnableAdminServerSupport = $true
	
	[DscProperty()]
    [Bool] $EnableUserAndPass = $true
	
	[DscProperty()]
    [Bool] $EnableWinService = $true
	
	[DscProperty()]
    [Int] $IhsAdminPort = 8008
	
	[DscProperty(Mandatory)]
    [PSCredential] $IhsAdminCredential

	[DscProperty()]
    [PSCredential] $IhsWindowsCredential
	
	[DscProperty()]
    [String] $IhsWindowsStartupType = "auto"
	
	[DscProperty()]
    [Bool] $MapWebServerToApplications = $true
	
	[DscProperty(Mandatory)]
    [String] $WasMachineHostname
    
	[DscProperty(key)]
    [String] $WebServerDefinition = "webserver1"
	
	[DscProperty(Mandatory)]
    [String] $WebServerHostName
	
	[DscProperty()]
    [String] $WebServerInstallArch = "32"
	
	[DscProperty()]
    [String] $WebServerOS = "windows"
	
	[DscProperty()]
    [Int] $WebServerPortNumber = 80
	
	[DscProperty()]
    [String] $WebServerSelected = "ihs"

    [DscProperty()]
    [String] $WebServerType = "IHS"

    [DscProperty()]
    [String] $DefinitionLocationName = "defaultWebServerLocation"
    
    [DscProperty()]
    [String] $IHSInstallLocation = "D:\IBM\HTTPServer"
    
	[DscProperty()]
    [String] $IHSPluginInstallLocation = "D:\IBM\WebSphere\Plugins"
    
    [DscProperty()]
    [String] $ToolBoxInstallLocation = "D:\IBM\WebSphere\Toolbox"
    
    [DscProperty()]
    [String] $WebServerConfigFile1
	
    [String] $wctRspFile
    
    [String] GenerateWCTResponseFile(){
    	$this.wctRspFile = Join-Path (Get-IBMTempDir) "wctRspFile-$(get-date -f yyyyMMddHHmmss)-$(Get-Random).tmp"
    	if(!$this.WebServerConfigFile1){
    		$this.WebServerConfigFile1 = Join-Path $this.IHSInstallLocation "conf\httpd.conf"
    	}
    	[System.Collections.Specialized.OrderedDictionary] $variables = @{}
    	if($this.ConfigType){$variables.Add("configType", $this.ConfigType)}
    	$variables.Add("enableAdminServerSupport", $this.EnableAdminServerSupport)
    	$variables.Add("enableUserAndPass", $this.EnableUserAndPass)
    	$variables.Add("enableWinService", $this.EnableWinService)
    	if($this.IhsAdminPort){$variables.Add("ihsAdminPort", $this.IhsAdminPort)}
    	if($this.IhsAdminCredential){
    		$variables.Add("ihsAdminUserID", $this.IhsAdminCredential.UserName)
    		$variables.Add("ihsAdminPassword", $this.IhsAdminCredential.GetNetworkCredential().Password)
    	}
    	if($this.IhsWindowsStartupType){$variables.Add("ihsWindowsStartupType", $this.IhsWindowsStartupType)}
    	if($this.IhsWindowsCredential){
    		$variables.Add("ihsWindowsUserID", $this.IhsWindowsCredential.UserName)
    		$variables.Add("ihsWindowsPassword", $this.IhsWindowsCredential.GetNetworkCredential().Password)
    	}
    	$variables.Add("mapWebServerToApplications", $this.mapWebServerToApplications)
    	if($this.WasMachineHostname){$variables.Add("wasMachineHostname", $this.WasMachineHostname)}
    	if($this.WebServerConfigFile1){$variables.Add("webServerConfigFile1", ($this.WebServerConfigFile1 -replace "\\","/"))}
    	if($this.WebServerDefinition){$variables.Add("webServerDefinition", $this.WebServerDefinition)}
    	if($this.WebServerHostName){$variables.Add("webServerHostName", $this.WebServerHostName)}
    	if($this.WebServerInstallArch){$variables.Add("webServerInstallArch", $this.WebServerInstallArch)}
    	if($this.WebServerPortNumber){$variables.Add("webServerPortNumber", $this.WebServerPortNumber)}
    	if($this.WebServerOS){$variables.Add("webServerOS", $this.WebServerOS)}
    	if($this.WebServerSelected){$variables.Add("webServerSelected", $this.WebServerSelected)}
    	if($this.WebServerType){$variables.Add("webServerType", $this.WebServerType)}
    	
    	[String] $wctRspStr = ($variables.Keys | foreach { $key = $_;"$key=$($variables.$key)" }) -join [environment]::newline
    	$wctRspStr | Out-File $this.wctRspFile -encoding "ASCII"
    	Write-Verbose "Generated WCT Response File : $($this.wctRspFile)"
    	return $this.wctRspFile
    }
    
    [String[]] PopulateWctArgs(){
    	#wctcmd.bat  -tool pct -defLocPathname D:\data\IBM\WebSphere\Plugins 
    	#-defLocName someDefinitionLocationName -createDefinition 
    	#-response D:\IBM\WebSphere\tools\WCT\responsefile.txt
    	[String[]] $wctArgs = @();
    	$wctArgs += @("-tool", "pct")
    	$wctArgs += @("-defLocPathname", $this.IHSPluginInstallLocation)
    	$wctArgs += @("-defLocName", $this.DefinitionLocationName)
    	$wctArgs += "-createDefinition" 
    	$wctArgs += @("-response", $this.wctRspFile)
    	return $wctArgs
    }
    
    <#
        Config IBM IHS PLUGIN
    #>
    [void] Set () {
        try {
        	# Generate WCT Rsp file
        	$this.wctRspFile = $this.GenerateWCTResponseFile()	
        	# Get wctcmd.bat path
        	[String] $wctBat = Join-Path $this.ToolBoxInstallLocation "WCT\wctcmd.bat"
        	# Populate wctcmd.bat args
        	[String[]] $wctArgs = $this.PopulateWctArgs()
        	# Invoke-ProcessHelper Excute wctcmd.bat -tool pct -defLocPathname D:\data\IBM\WebSphere\Plugins -defLocName someDefinitionLocationName -createDefinition -response D:\IBM\WebSphere\tools\WCT\responsefile.txt
        	$wctProc = Invoke-ProcessHelper $wctBat $wctArgs (Split-Path($wctBat))
        	# Handle Process Results
            if ($wctProc -and ($wctProc.exitCode -eq 0)){
				Write-Verbose "Processed wctcmd.bat successfully!"
            	Write-Debug $wctProc.StdOut
            	Stop-IBMHTTPAdminService
            	Start-IBMHTTPAdminService
            }else{
				Write-Error "An error occurred while executing the wctcmd.bat process. ExitCode: $wctProc.exitCode Mesage: $wctProc.errorMsg"
            }
        } catch {
            Write-Error -ErrorRecord $_ -ErrorAction Stop
        }
    }

    <#
        Performs test to check if IHS is configured properly
    #>
    [bool] Test () {
        Write-Verbose "Checking for IBM HTTP Server Configuration"
#        if(Test-IBMPSDscSequenceDebug){return $True}
        $ihsConfiguredCorrectly = Test-Path (Join-Path $this.IHSPluginInstallLocation "config/$($this.WebServerDefinition)")
        return $ihsConfiguredCorrectly
    }

    <#
        Leverages the information stored in the registry to populate the properties of an existing
        installation of IHS
    #>
    [cIBMHTTPServerPluginConfig] Get () {
        [String] $pluginResponseFile = Join-Path $this.IHSPluginInstallLocation "config/$($this.WebServerDefinition)/$($this.WebServerDefinition).responseFile"
        if(Test-Path $pluginResponseFile){
            $pluginCfg = Get-Content $pluginResponseFile -encoding "ASCII"| % {if ($_ -match "[A-Z]:\\"){$_ -replace '\\','/'}else {$_}} | ConvertFrom-StringData
            $returnValue = @{
            	ConfigType = $pluginCfg.configType
            	EnableAdminServerSupport = $pluginCfg.enableAdminServerSupport
            	EnableUserAndPass = $pluginCfg.enableUserAndPass
            	EnableWinService = $pluginCfg.enableWinService
            	IhsAdminPort = $pluginCfg.ihsAdminPort
            	IhsWindowsStartupType = $pluginCfg.ihsWindowsStartupType
            	MapWebServerToApplications = $pluginCfg.mapWebServerToApplications
            	WasMachineHostname = $pluginCfg.wasMachineHostname
            	WebServerConfigFile1 = $pluginCfg.webServerConfigFile1
            	WebServerDefinition = $pluginCfg.webServerDefinition
            	WebServerHostName = $pluginCfg.webServerHostName
            	WebServerInstallArch = $pluginCfg.webServerInstallArch
            	WebServerOS = $pluginCfg.webServerOS
            	WebServerPortNumber = $pluginCfg.webServerPortNumber
            	WebServerSelected = $pluginCfg.webServerSelected
            	WebServerType = $pluginCfg.webServerType
                DefinitionLocationName = $pluginCfg.defLocPathname
            }
            
            return $returnValue
        }else{
            return $this;
        }
    }
}


<#
   DSC resource to manage IBM WebServer within WebSphere Application Server.
#>
[DscResource()]
class cIBMWASManagedWebServer {
    [DscProperty(Mandatory)]
    [Ensure] $Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [String] $DmgrHost

    [DscProperty(Mandatory)]
    [String] $DmgrProfile
    
    [DscProperty(Mandatory)]
    [String] $DmgrCell
    
    [DscProperty(Mandatory)]
    [PSCredential] $WasAdminCredential
    
    [DscProperty()]
    [PSCredential] $IhsAdminCredential
    
    [DscProperty(key)]
    [String] $WebServerName = "WebServer01"
    
    [DscProperty()]
    [String] $WebServerConfigFile
    
    [DscProperty()]
    [String] $WebServerType = "IHS"
    
    [DscProperty(Mandatory)]
    [String] $WebNodeName = "webNode01"
    
    [DscProperty(Mandatory)]
	[String] $IHSInstallLocation = "D:\IBM\HTTPServer"
	
	[DscProperty()]
    [String] $IHSPluginInstallLocation = "D:\IBM\WebSphere\Plugins"
    
	[DscProperty(Mandatory)]
    [String] $WebServerHostName
    
    [DscProperty()]
    [Int] $WebServerPortNumber = 80
    
	[DscProperty()]
    [Int] $IhsAdminPort = 8008
    
    
    [String[]] PopulatePluginConfigArgs(){
    	#Example:  configurepredevWebServer1.bat -profileName AppSrv01 -user admin -password admin1 -ihsAdminPassword ihsPWD
    	$pluginConfigArgs = @("-profileName", $this.DmgrProfile)
    	$pluginConfigArgs += @("-user", $this.WasAdminCredential.UserName)
    	$pluginConfigArgs += @("-password", $this.WasAdminCredential.GetNetworkCredential().Password)
    	if($this.IhsAdminCredential){
    		$pluginConfigArgs += @("-ihsAdminPassword", $this.IhsAdminCredential.GetNetworkCredential().Password)
    	}
    	return $pluginConfigArgs
    }
    
    [String] GetWebServerConfigBatFile(){
    	$pluginConfigBatPath = Join-Path (Get-IBMWebSphereAppServerInstallLocation ND) "bin\configure$($this.WebServerName).bat"
		$ihsAdmin = $this.IhsAdminCredential.UserName
		$ihsAdminPassword = $this.IhsAdminCredential.GetNetworkCredential().Password
		if(!$this.WebServerConfigFile){
			$this.WebServerConfigFile = (Join-Path $this.IHSInstallLocation "conf\httpd.conf").Replace('\','\\')
		}
    	$tokens = @{
        	WebServerName = $this.WebServerName
        	WebServerType = $this.WebServerType
        	WebNodeName = $this.WebNodeName
        	IHSInstallLocation = [regex]::Escape($this.IHSInstallLocation)
            WebServerConfigFile= $this.WebServerConfigFile
        	IHSPluginInstallLocation = [regex]::Escape($this.IHSPluginInstallLocation)
        	WebServerHostName = $this.WebServerHostName
        	WebServerPortNumber = $this.WebServerPortNumber
        	IhsAdminPort = $this.IhsAdminPort
        	IHSAdmin = $ihsAdmin
        	IHSAdminPassword = $ihsAdminPassword
        }
    	Get-Content (Join-Path ($PSScriptRoot) "WebServerConfigTemplate\configureWebServerTemplate.bat") | Merge-Tokens -tokens $tokens -Verbose:$false | Set-Content $pluginConfigBatPath
        return $pluginConfigBatPath
    }
    
	[void] Set () {
        # Invoke Command on WAS target Server refer Invoke-Batch
        $pluginConfigBatPath = $this.GetWebServerConfigBatFile()
        if(!(Test-Path $pluginConfigBatPath)){
        	Write-Error "pluginConfigBatPath is not found! : $pluginConfigBatPath"
        }
        $pluginConfigArgs = $this.PopulatePluginConfigArgs()
        $pluginConfigProc = Invoke-ProcessHelper `
        						-ProcessFileName $pluginConfigBatPath `
        						-ProcessArguments $pluginConfigArgs `
        						-WorkingDirectory (Split-Path($pluginConfigBatPath))
		if ($pluginConfigProc -and ($pluginConfigProc.exitCode -eq 0)){
			Write-Verbose "Processed wctcmd.bat successfully!"      
        	Write-Debug $pluginConfigProc.StdOut
        }else{
			Write-Error "An error occurred while executing the wctcmd.bat process. ExitCode: $pluginConfigProc.exitCode Mesage: $pluginConfigProc.errorMsg"
        }
        # Generates and propogates the webserver plugin for the specified webserver
        $dmgrProfileDir = Get-IBMWASProfilePath $this.DmgrProfile ND
        $pluginFileGenerated = Invoke-GenPluginCfg -ProfileDir $dmgrProfileDir `
        					-CellName $this.DmgrCell `
        					-Propagate -Verbose
        					
		if($pluginFileGenerated){
			Write-Verbose "WebServer Plugin generated successfully, restarting all WebSphere Application Servers now..."
			Stop-ManagedWebServer $this.WebNodeName $this.WebServerName $dmgrProfileDir $this.WasAdminCredential
			Start-ManagedWebServer $this.WebNodeName $this.WebServerName $dmgrProfileDir $this.WasAdminCredential
		}else{
			Write-Error "Error Occurred when generating the WebSphere Plugin, please find log for more detail."
		}
	}
	<#
    #>
    [bool] Test () {
    	$dmgrProfileDir = Get-IBMWASProfilePath $this.DmgrProfile ND
    	$skip = Test-WebServerExists "WEB_SERVER" $this.DmgrCell $this.WebServerName `
    									$dmgrProfileDir $this.WasAdminCredential
        return $skip
    }
    <#
    #>
    [cIBMWASManagedWebServer] Get () {
        return $this;
    }
}