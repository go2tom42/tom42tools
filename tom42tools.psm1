function DeployMe() {
    <#
    .SYNOPSIS
    Downloads .ps1 and runs it as admin
    .DESCRIPTION
    Used for system reinstalls, it downloads .ps1 and runs it as admin, it will also record restore folder
    Downloads .ps1 and runs it as admin
    .PARAMETER URL
    URL to a .ps1 files
    .PARAMETER Restorefolder
    Where the old install backup files were movied to
    .EXAMPLE
    PS C:\> DeployMe 'https://www.website.com/file.ps1'
    Downloads .ps1 and runs it as admin
    .EXAMPLE
    PS C:\> DeployMe -URL 'https://www.website.com/file.ps1'
    Downloads .ps1 and runs it as admin
    .EXAMPLE
    PS C:\> DeployMe 'https://www.website.com/file.ps1' 'e:\restore'
    Downloads .ps1 and runs it as admin, saves 'e:\restore' to file named "~\restore.dir"
    .EXAMPLE
    PS C:\> DeployMe -URL 'https://www.website.com/file.ps1' -Restorefolder 'e:\restore'
    Downloads .ps1 and runs it as admin, saves 'e:\restore' to file named "~\restore.dir"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $URL,

        [Parameter()]
        [string]
        $Restorefolder
    )

    Write-Output $restorefolder | out-file -FilePath "~\restore.dir"
    (New-Object System.Net.WebClient).DownloadFile($URL,"$env:TEMP\part1.ps1");Start-Process -FilePath "powershell.exe" -ArgumentList "-executionpolicy bypass -File $env:TEMP\part1.ps1" -Verb RunAs
}

function Set-RunOnce {
    <#
    .SYNOPSIS
    Sets file as a runonce next time the system is rebooted
    .DESCRIPTION
    Sets file as a runonce next time the system is rebooted, this is used to setup next part of reinstall
    .PARAMETER Command
    File to run next boot
    .EXAMPLE
    PS C:\> Set-RunOnce 'https://www.website.com/file.ps1'
    Downloads .ps1 and runs it as admin
    #>
    [cmdletbinding()]
    param
    (
    [string]$Command = '%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -executionpolicy bypass -file c:\WORK\part3.ps1'
    )

    if (-not ((Get-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce).'Run' ))
    {
        New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'Run' -Value $Command -PropertyType ExpandString
    }
    else
    {
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'Run' -Value $Command -PropertyType ExpandString
    }
}


function isURIWeb($address) {
	$uri = $address -as [System.URI]
	$uri.AbsoluteURI -ne $null -and $uri.Scheme -match '[http|https]'
}