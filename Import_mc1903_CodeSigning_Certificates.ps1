<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Script: Import_mc1903_CodeSigning_Certificates.ps1
Author:	Martin Cooper (@mc1903)
Date: 26-07-2022
GitHub Repo: https://github.com/mc1903/MomusCA
Version: 1.0.2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Downloads and installs the 3 certificates required to trust my signed PowerShell scripts/modules.

If the script runs as Administrator (elevated) the certificates will be installed into the LocalMachine for all users

If the script runs as Current User the Root CA certificate import will require user intervention to answer GUI confirmation

#>

Clear-Host

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

[Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent()
$runningAsAdmin = $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

If ($runningAsAdmin -eq 'True') {
    $certStore = "LocalMachine"
}
Else {
    $certStore = "CurrentUser"
}

$certsBaseURL = "https://raw.githubusercontent.com/mc1903/MomusCA/main/certs"
$certsList = @(
        @{
            name = "Momus Root CA Certificate"
            filename = "MomusRootCA.cer"
            storename = "Root"
        },
        @{
            name = "Momus Intermediate CA Certificate"
            filename = "MomusInterCA.cer"
            storename = "CA"
        },
        @{
            name = "mc1903 Code Signing Certificate"
            filename = "mc1903_CodeSigning.cer"
            storename = "TrustedPublisher"
        }
    )

ForEach ($cert in $certsList) {
    Write-Output "Downloading and Installing - $($cert.name)"
    $certURL = $certsBaseURL + $($cert.filename)
    Invoke-WebRequest -Uri $certURL -OutFile $env:temp\$($cert.filename) -ErrorAction Stop
    $certStoreLocation = "Cert:\$certStore\$($cert.storename)"
    Import-Certificate -FilePath $env:temp\$($cert.filename) -CertStoreLocation $certStoreLocation | Format-List Subject,Issuer,Thumbprint,NotBefore,NotAfter
    Remove-Item –Path $env:temp\$($cert.filename) -Force -Confirm:$false -ErrorAction SilentlyContinue
}

Remove-Variable runningAsAdmin,certStore,certsBaseURL,certsList,certURL,certStoreLocation -ErrorAction SilentlyContinue -Confirm:$false
