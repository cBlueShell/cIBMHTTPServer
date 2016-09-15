#requires -Version 5

Configuration IHS
{   
    param (
        [Parameter(Mandatory)]
        [PSCredential] $KeyDBPassword,
        
        [Parameter(Mandatory)]
        [PSCredential] $CertPassword
    )
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'cIBMInstallationManager' -ModuleVersion '1.0.5'
    Import-DSCResource -ModuleName 'cIBMHTTPServer' -ModuleVersion '1.0.0'
    
    node localhost {
        Package SevenZip {
            Ensure = 'Present'
            Name = '7-Zip 9.20 (x64 edition)'
            ProductId = '23170F69-40C1-2702-0920-000001000000'
            Path = 'C:\Media\7z920-x64.msi'
        }
        cIBMInstallationManager IIMInstall
        {
            Ensure = 'Present'
            InstallationDirectory = 'C:\IBM\IIM'
            TempDir = 'C:\IBM\Temp'
            Version = '1.8.3'
            SourcePath = 'C:\Media\agent.installer.win32.win32.x86_1.8.3000.20150606_0047.zip'
            DependsOn= '[Package]SevenZip'
        }
        cIBMHTTPServer IHSInstall
        {
            Ensure = 'Present'
            InstallationDirectory = 'C:\IBM\HTTPServer'
            Version = '8.5.5'
            SourcePath = 'C:\Media\IHS855\'
            DependsOn= '[cIBMInstallationManager]IIMInstall'
        }
    
        cIBMHTTPServerSSLCertificate MySSLCert
        {
            Ensure = 'Present'
            KeyDBPath = 'C:\IBM\HTTPServer\SSL\mysslcerts.kdb'
            KeyDBPassword = $KeyDBPassword
            CertificateLabel = '*.mywebsite.com'
            Default = $true
            CertificatePath = 'C:\SSLFiles\devcert.pfx'
            CertificatePassword = $CertPassword
            DependsOn= '[cIBMHTTPServer]IHSInstall'
        }
    }
}

$configData = @{
    AllNodes = @(
        @{
            NodeName = "localhost"
            PSDscAllowPlainTextPassword = $true
         }
    )
}

IHS -ConfigurationData $configData -KeyDBPassword (Get-Credential) -CertPassword (Get-Credential)
Start-DscConfiguration -Wait -Force -Verbose IHS