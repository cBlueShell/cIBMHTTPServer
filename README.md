#cIBMHTTPServer

PowerShell CmdLets and Class-Based DSC resources to manage IBM HTTP Server (IHS) on Windows Environments.

To get started using this module just type the command below and the module will be downloaded from [PowerShell Gallery](https://www.powershellgallery.com/packages/cIBMHTTPServer/)
```shell
PS> Install-Module -Name cIBMHTTPServer
```

## Resources

* **cIBMHTTPServer** installs IBM HTTP Server on target machine.

### cIBMHTTPServer

* **Ensure**: (Required) Ensures that IHS is Present or Absent on the machine
* **Version**: (Key) The version of IHS to install
* **InstallationDirectory**: (Optional) Installation path.  Default: C:\IBM\HTTPServer
* **HTTPPort**: (Optional) HTTP port. Default 80
* **StartupType**: (Optional) Startup Type for the IHS Windows Service.  Default Automatic
* **WindowsServiceAccount**: (Optional) Service Account use to run the IHS Windows Service
* **IMSharedLocation**: (Optional) Location of the IBM Installation Manager cache.  Default: C:\IBM\IMShared
* **InstallMediaConfig**: (Optional) Path to the clixml export of the IBMProductMedia object that contains media configuration.
* **ResponseFileTemplate**: (Optional) Path to the response file template to use for the installation.
* **SourcePath**: UNC or local file path to the directory where the IHS installation media resides.
* **SourcePathCredential**: (Optional) Credential to be used to map sourcepath if a remote share is being specified.

_Note_ InstallMediaConfig and ResponseFileTemplate are useful parameters when there's no built-in support for the WAS edition you need to install or when you have special requirements based on how your media is setup or maybe you have unique response file template needs.
If you create your own Response File template it is expected that the template has the variables: **sharedLocation** and **ihsInstallLocation**.  See sample response file template before when planning to roll out your own.

### cIBMHTTPServerSSLCertificate
* **Ensure**: (Required) Ensures that the SSL Certificate is Present or Absent on the machine
* **KeyDBPath**:: (Key) Path to the Key Database file
* **KeyDBPassword**: (Required) Credential needed to create or open Key Database
* **CertificateLabel**: (Key) The label of the primary certificate
* **Default**: (Optional) Sets the cetificate matching the label to the default certificate of the Key Databaes
* **CertificatePath**: UNC or local file path to the SSL certificate file
* **CertificatePassword**: Credential to be used to access the certificate while being imported to the Key Database
* **CertificatePathCredential**: (Optional) Credential to be used to map credentialpath if a remote share is being specified.

## Depedencies
* [cIBMWebSphereAppServer](http://github.com/cBlueShell/cIBMWebSphereAppServer) DSC Resource/CmdLets for IBM WebSphere Products
* [cIBMInstallationManager](http://github.com/cBlueShell/cIBMInstallationManager) DSC Resource/CmdLets for IBM Installation Manager
* [7-Zip](http://www.7-zip.org/ "7-Zip") needs to be installed on the target machine.  You can add 7-Zip to your DSC configuration by using the Package
DSC Resource or by leveraging the [x7Zip DSC Module](https://www.powershellgallery.com/packages/x7Zip/ "x7Zip at PowerShell Gallery")

## Versions

### 1.1.0
* New DSC resources
    - cIBMHTTPServerPluginConfig
    - cIBMWASManagedWebServer

### 1.0.0
* Initial release with the following resources 
    - cIBMHTTPServer
    - cIBMHTTPServerSSLCertificate

## Testing

The table below outlines the tests that various IHS versions have been verify to date.  As more configurations are tested there should be a corresponding entry for Media Configs and Response File Templates.  Could use help on this, pull requests welcome :-)

| IHS Version | Operating System               | IHS |
|-------------|--------------------------------|-----|
| v8.5.5      |                                |     |
|             | Windows 2012 R2 (64bit)        |  x  |
|             | Windows 10 (64bit)             |  x  |
|             | Windows 2008 R2 Server (64bit) |     |


## Media Files

The installation depents on media files that have already been downloaded.  In order to get the media files please check your IBM Passport Advantage site.

The table below shows the currently supported (i.e. tested) media files.

| IHS Version | Media Files                 |
|-------------|-----------------------------|
| v8.5.5      |                             |
|             | WAS_V8.5.5_SUPPL_1_OF_3.zip |
|             | WAS_V8.5.5_SUPPL_2_OF_3.zip |
|             | WAS_V8.5.5_SUPPL_3_OF_3.zip |

## Examples

### Install IBM HTTP Server

This configuration will install [7-Zip](http://www.7-zip.org/ "7-Zip") using the DSC Package Resource, install/update IBM Installation Manager
and finally install IBM HTTP Server and started on port 80

Note: This requires the following DSC modules:
* xPsDesiredStateConfiguration
* cIBMInstallationManager

```powershell
Configuration IHS
{   
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'cIBMInstallationManager' -ModuleVersion '1.0.5'
    Import-DSCResource -ModuleName 'cIBMHTTPServer' -ModuleVersion '1.0.0'
    
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
}
IHS
Start-DscConfiguration -Wait -Force -Verbose IHS
```