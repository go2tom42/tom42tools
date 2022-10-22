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
        $Restorefolder = 'NA'
    )
    if (isURIWeb $URL) {
        Write-Output $restorefolder | out-file -FilePath "~\restore.dir"
        (New-Object System.Net.WebClient).DownloadFile($URL, "$env:TEMP\part1.ps1"); Start-Process -FilePath "powershell.exe" -ArgumentList "-executionpolicy bypass -File $env:TEMP\part1.ps1" -Verb RunAs    
    }
    else {
        Write-Host 'NOT VALID URL'
        Pause
    }
    
}

function isURIWeb($address) {
    $uri = $address -as [System.URI]
    $null -ne $uri.AbsoluteURI -and $uri.Scheme -match '[http|https]'
}
function isURIFile($address) {
    $uri = $address -as [System.URI]
    $null -ne $uri.AbsoluteURI -and $uri.Scheme -match '[File|file]'
}

function Get-BAFile() {
    <#
    .SYNOPSIS
    Downloads files requiring Basic Authorization
    .DESCRIPTION
    Downloads files requiring Basic Authorization
    .PARAMETER URL
    URL to file
    .PARAMETER Path
    Path to save file
    .PARAMETER User
    Username
    .PARAMETER Pass
    Password
    .EXAMPLE
    PS C:\> Get-BAFile 'https://remotely.tom42.pw/Content/Remotely_Installer.exe' './Remotely_Installer.exe' 'tom42' '1tardis1'
    Downloads .ps1 and runs it as admin
    .EXAMPLE
    PS C:\> Get-BAFile -URL 'https://remotely.tom42.pw/Content/Remotely_Installer.exe' -PATH './Remotely_Installer.exe' -USER 'tom42' -PASS '1tardis1'
    Downloads .ps1 and runs it as admin
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $True)]
        [string]
        $URL = 'NA',

        [parameter(Mandatory = $True)]
        [string]
        $PATH = 'NA',

        [parameter(Mandatory = $True)]
        [string]
        $USER = 'NA',

        [parameter(Mandatory = $True)]
        [string]
        $PASS = 'NA'
    )

    if ($PATH -eq 'NA') { Write-Host 'NOT VALID PATH'; exit }
    if ($PASS -eq 'NA') { Write-Host 'NOT VALID PASS'; exit }
    if ($USER -eq 'NA') { Write-Host 'NOT VALID USER'; exit }

    if (isURIWeb $URL) {
        $WebClient = New-Object System.Net.WebClient;
        $WebClient.Credentials = New-Object System.Net.Networkcredential($user, $pass)
        $WebClient.DownloadFile($url, $path)
    }
    else {
        Write-Host 'NOT VALID URL'
        Pause
    }
}

function Add-RunOnce {
    <#
    .SYNOPSIS
    Sets file as a runonce next time the system is rebooted
    .DESCRIPTION
    Sets file as a runonce next time the system is rebooted, this is used to setup next part of reinstall
    .PARAMETER Command
    File to run next boot
    .EXAMPLE
    PS C:\> Set-RunOnce 'https://www.website.com/file.ps1'
    #>
    [cmdletbinding()]
    param
    (
        [string]$Command = ''
    )
	
    $Command = $base + $Command
	
    $base = '%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -executionpolicy bypass -file '
	
    if (-not ((Get-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce).'Run' )) {
        New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'Run' -Value $Command -PropertyType ExpandString
    }
    else {
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'Run' -Value $Command -PropertyType ExpandString
    }
}

function Set-DefaultSetup {
    #download apps
    Install-Choco
    $dlfile = New-Object net.webclient
    $dlfile.Downloadfile("https://t0m.pw/tcmd", "$env:TEMP\tcmd.exe")
    $dlfile.Downloadfile("https://t0m.pw/wfc", "$env:TEMP\wfc6setup.exe")
    $dlfile.Downloadfile("https://t0m.pw/terminal", "$env:TEMP\Microsoft.WindowsTerminal.zip")
    choco install 7zip.install firefox notepadplusplus.install path-copy-copy winrar setdefaultbrowser
	
    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
    }
    catch {
        #Do Nothing
    }
	
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name BurntToast -Force
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    Install-Module -Name PolicyFileEditor -Force

    #install Total Commander 
    start-process -FilePath "$env:TEMP\tcmd.exe" -ArgumentList "/AHL0GDUKFW0" -Wait
    Set-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Ghisler\Total Commander" -Name "IniFileName" -Value ".\wincmd.ini" -type String -erroraction SilentlyContinue
    Set-ItemProperty "HKLM:\SOFTWARE\Ghisler\Total Commander" -Name "IniFileName" -Value ".\wincmd.ini" -type String -erroraction SilentlyContinue
    Set-ItemProperty "HKCU:\SOFTWARE\Ghisler\Total Commander" -Name "IniFileName" -Value ".\wincmd.ini" -type String -erroraction SilentlyContinue
    New-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Ghisler\Total Commander" -Name "IniFileName" -Value ".\wincmd.ini" -type String -erroraction SilentlyContinue
    New-ItemProperty "HKLM:\SOFTWARE\Ghisler\Total Commander" -Name "IniFileName" -Value ".\wincmd.ini" -type String -erroraction SilentlyContinue
    New-ItemProperty "HKCU:\SOFTWARE\Ghisler\Total Commander" -Name "IniFileName" -Value ".\wincmd.ini" -type String -erroraction SilentlyContinue


    $wincmdini = 'W0NvbmZpZ3VyYXRpb25dDQpJbnN0YWxsRGlyPUM6XFByb2dyYW0gRmlsZXNcdG90YWxjbWQNClVzZU5ld0RlZkZvbnQ9MQ0KU2V0RW5jb2Rpbmc95PYuZG8ubm90LnJlbW92ZQ0KZmlyc3RtbnU9MjY4Mg0KRmlyc3RUaW1lPTANCkZpcnN0VGltZUljb25MaWI9MA0KdGVzdD0xODUNClNob3dIaWRkZW5TeXN0ZW09MQ0KVXNlTG9uZ05hbWVzPTENClNtYWxsODNOYW1lcz0wDQpPbGRTdHlsZVRyZWU9MA0KYXV0b3RyZWVjaGFuZ2U9MA0KRGlyQnJhY2tldHM9MQ0KU2hvd1BhcmVudERpckluUm9vdD0wDQpTb3J0RGlyc0J5TmFtZT0xDQpUaXBzPTMNCkZpbGVUaXBXaW5kb3dzPTANCldpbjMyVGlwV2luZG93cz0wDQpTb3J0VXBwZXI9MA0KU2hvd0NlbnR1cnk9MQ0KQWxpZ25lZCBleHRlbnNpb249MA0KU2l6ZVN0eWxlPTANClNpemVGb290ZXI9MQ0KU2VwYXJhdGVUcmVlPTANClBhbmVsc1ZlcnRpY2FsPTANCltCdXR0b25iYXJDYWNoZV0NCkljb25EbGxfZGVmYXVsdC5iYXI9DQpJY29uRGxsX3ZlcnRpY2FsLmJhcj0NCltGaWxlU3lzdGVtUGx1Z2luczY0XQ0KJGNoZWNrc3VtJD0zMDE0NjcyDQpbTGF5b3V0XQ0KQnV0dG9uQmFyPTENCkJ1dHRvbkJhclZlcnRpY2FsPTENCkRyaXZlQmFyMT0xDQpEcml2ZUJhcjI9MQ0KRHJpdmVCYXJGbGF0PTENCkludGVyZmFjZUZsYXQ9MQ0KRHJpdmVDb21ibz0xDQpEaXJlY3RvcnlUYWJzPTENClhQdGhlbWVCZz0xDQpDdXJEaXI9MQ0KVGFiSGVhZGVyPTENClN0YXR1c0Jhcj0xDQpDbWRMaW5lPTENCktleUJ1dHRvbnM9MQ0KSGlzdG9yeUhvdGxpc3RCdXR0b25zPTENCkJyZWFkQ3J1bWJCYXI9MQ0KW1RhYnN0b3BzXQ0KMD0yMjgNCjE9MjMxDQozPTI4Ng0KND0tMQ0KNj02MjkNCjU9MTAwDQpBZGp1c3RXaWR0aD0xDQpbMTkyMHgxMDgwICg4eDE2KV0NClRhYnN0b3BzPTIyOCwyMzEsMjg2LC0xLDYyOSwxMDAsNTANCltsZWZ0XQ0KcGF0aD1DOlxQcm9ncmFtRGF0YVwNClZpZXdNb2RlPTEwMDAxDQphY3RpdmVwYW5lbGNvbG9yPS0xDQphY3RpdmVwYW5lbGNvbG9yMj0tMQ0KYWN0aXZlcGFuZWxjb2xvcmRhcms9LTENCmFjdGl2ZXBhbmVsY29sb3JkYXJrMj0tMQ0KU2hvd0FsbERldGFpbHM9MQ0KU3BlY2lhbFZpZXc9MA0Kc2hvdz0xDQpzb3J0b3JkZXI9MA0KbmVnYXRpdmUgU29ydG9yZGVyPTANCltyaWdodF0NCnBhdGg9YzpcDQpWaWV3TW9kZT0xMDAwMQ0KYWN0aXZlcGFuZWxjb2xvcj0tMQ0KYWN0aXZlcGFuZWxjb2xvcjI9LTENCmFjdGl2ZXBhbmVsY29sb3JkYXJrPS0xDQphY3RpdmVwYW5lbGNvbG9yZGFyazI9LTENClNob3dBbGxEZXRhaWxzPTENClNwZWNpYWxWaWV3PTANCnNob3c9MQ0Kc29ydG9yZGVyPTANCm5lZ2F0aXZlIFNvcnRvcmRlcj0wDQpbUmlnaHRIaXN0b3J5XQ0KMD1jOlwJIzANCltMZWZ0SGlzdG9yeV0NCjA9QzpcUHJvZ3JhbURhdGFcCSMwDQoxPWM6XAkjNyxQcm9ncmFtRGF0YQ0KW0xpc3RlclBsdWdpbnM2NF0NCiRjaGVja3N1bSQ9MzAxNDY3Mg0K'
    $wincmdini = [System.Convert]::FromBase64String($wincmdini)
    [System.IO.File]::WriteAllBytes("C:\Program Files\totalcmd\wincmd.ini", $wincmdini)

    $wincmdkey = 'R3RD5Q8EQqQLjWRhSA/WQnQkZZIVrsU8PUwHnYHYlSmxPSMLdnYJbs+xBAFSsn06W7S4EnGQpwFBLzdR7WGQaLn9qftFEEoeUgWF+J6amOWaIsadpRie9zbbGx6TLvdnVw9vo7nZ44Gm7ZEjYN130mauIYQGpNvkEQdEyD9YCu/N50BwhO5Nau/+To4PsezkTtsauKt2gzSSFTa57pd6DyWvGbAgGQxYzSWTqgddyrZSJu5b47gcs/qWY2QDosv2SU18eyiEVvyOPQVrBp5MMzHI5V5Pem8KW2tH0091yS6hRcCoyGL/nnOaiLCb9nh8JQEIEUEWzCMRq9zE01758ZfP3Wg9X4G/ysZyP9eP1kZb50cjTIFtxl4GdcNSFkPDOlF5ag2GR37YwFZunFt20lWg8CifbLvGjHhPknWvecGETPDxG1jeE/lDgm1dbBE7UR2rh5nwenEmrVmwua0I4SBlZs+J6g5kUEOEOGZ3pPx5Qs9FLt0IUXCHP22IlOUYr0l0ZjpezYV3tddyl3hTzyQ87myvPFirsnddvWPh7SEOsD36hjun3RMvhLaHDMDDoZapheiwbyrg2Zeei6n0xfXma6+nv2I/rTg37oUoOMm338WVxvUdP2JJu3gV77hLiD0TQY+k7xn1x/BoqKcL0jWPQqxGtqXn8ow1YwyC7Rqbr1OdnQ3niunz6aBnA6VEOEe3IbMpmz7VN2WLLZUq6kOYKLeCZLtIZR6C5+F0f1pbx/JKXshkQDTX1c91LyV+icvQrDVtCDhy1kCedvmv+qpgXb8Vbk4KzGPDHhaab1wHTVGVBxDdNfUD7XhFQ6GrXtD7fQeCSlxtQvjLu7Oq/y9C4lLb2/i6n/MBZs68iCez1R+y5OqkvMHmTx65sa5MU1WNnw8uheRPAYMkeJx1BtbpwNGreFCNSyyck8GArigh2ZHie6O1h7Rv4AT4gThPuHqMxwjFieW6m142vJ3F3+cOkEV0/XQEewr559tltr0zIwFD8zeUBb+F1Igkm8xe4it6m2IRoXln0m1MNbMQm3IdaaTvbv2V4xzj95LaOtuGZswGADD+LyocmWz3VzarxhYOiTs40o4iKmxFZ35sIv/IfwLhvZfuuxdw1dATZUVggSvAsyDUFnA7vOF7B23NKFnXGIETMWGtBRp1KPzh4OGKm55aKsDmoPsfV1uCwphDb3B5cmlnaHQgqSAxOTk5IGJ5IENocmlzdGlhbiBHaGlzbGVyLCBDLiBHaGlzbGVyICYgQ28uLCBhbGwgcmlnaHRzIHJlc2VydmVkLiBVbmF1dGhvcml6ZWQgY29weWluZyBwcm9oaWJpdGVkIQCI/lcvjbllY5//R9qXVB+fLg=='
    $wincmdkey = [System.Convert]::FromBase64String($wincmdkey)
    [System.IO.File]::WriteAllBytes("C:\Program Files\totalcmd\wincmd.key", $wincmdkey)

    #install Windows Firewall Control
    start-process -FilePath "$env:TEMP\wfc6setup.exe" -ArgumentList "-i -c" -Wait

    #install Windows Terminal
    Expand-Archive -LiteralPath "$env:TEMP\Microsoft.WindowsTerminal.zip" -DestinationPath $env:TEMP
    $UWPDesktop = (Get-ChildItem -file -Path "$env:TEMP" -Filter '*.UWPDesktop_14.*x64*').FullName
    Add-AppxPackage $UWPDesktop
    $UWPDesktop = (Get-ChildItem -file -Path "$env:TEMP" -Filter '*.msixbundle').FullName
    Add-AppxPackage $UWPDesktop
  


    #firefox 
    Start-Process -FilePath "C:\Program Files\Mozilla Firefox\firefox.exe"
    Start-Sleep -s 3
    Stop-Process -Name 'firefox' -Force 

    $configjs = 'Ly8gc2tpcCAxc3QgbGluZQpsb2NrUHJlZigneHBpbnN0YWxsLnNpZ25hdHVyZXMucmVxdWlyZWQnLCBmYWxzZSk7CgpPYmplY3QgPSBDdS5nZXRHbG9iYWxGb3JPYmplY3QoQ3UpLk9iamVjdDsKY29uc3QgeyBmcmVlemUgfSA9IE9iamVjdDsKT2JqZWN0LmZyZWV6ZSA9IG9iaiA9PiB7CiAgaWYgKENvbXBvbmVudHMuc3RhY2suY2FsbGVyLmZpbGVuYW1lICE9ICdyZXNvdXJjZTovL2dyZS9tb2R1bGVzL0FwcENvbnN0YW50cy5qc20nKQogICAgcmV0dXJuIGZyZWV6ZShvYmopOwoKICBvYmouTU9aX1JFUVVJUkVfU0lHTklORyA9IGZhbHNlOwogIE9iamVjdC5mcmVlemUgPSBmcmVlemU7CiAgcmV0dXJuIGZyZWV6ZShvYmopOwp9Cgp0cnkgewogIGxldCBjbWFuaWZlc3QgPSBDY1snQG1vemlsbGEub3JnL2ZpbGUvZGlyZWN0b3J5X3NlcnZpY2U7MSddLmdldFNlcnZpY2UoQ2kubnNJUHJvcGVydGllcykuZ2V0KCdVQ2hybScsIENpLm5zSUZpbGUpOwogIGNtYW5pZmVzdC5hcHBlbmQoJ3V0aWxzJyk7CiAgY21hbmlmZXN0LmFwcGVuZCgnY2hyb21lLm1hbmlmZXN0Jyk7CiAgQ29tcG9uZW50cy5tYW5hZ2VyLlF1ZXJ5SW50ZXJmYWNlKENpLm5zSUNvbXBvbmVudFJlZ2lzdHJhcikuYXV0b1JlZ2lzdGVyKGNtYW5pZmVzdCk7CgogIEN1LmltcG9ydCgnY2hyb21lOi8vdXNlcmNocm9tZWpzL2NvbnRlbnQvQm9vdHN0cmFwTG9hZGVyLmpzbScpOwp9IGNhdGNoIChleCkge307Cgp0cnkgewogIEN1LmltcG9ydCgnY2hyb21lOi8vdXNlcmNocm9tZWpzL2NvbnRlbnQvdXNlckNocm9tZS5qc20nKTsKfSBjYXRjaCAoZXgpIHt9Ow=='
    $configprefsjs = 'cHJlZigiZ2VuZXJhbC5jb25maWcub2JzY3VyZV92YWx1ZSIsIDApOwpwcmVmKCJnZW5lcmFsLmNvbmZpZy5maWxlbmFtZSIsICJjb25maWcuanMiKTsKcHJlZigiZ2VuZXJhbC5jb25maWcuc2FuZGJveF9lbmFibGVkIiwgZmFsc2UpOwo='
    $configjs = [System.Convert]::FromBase64String($configjs)
    [System.IO.File]::WriteAllBytes("$Env:Programfiles\Mozilla Firefox\config.js", $configjs)
    $configprefsjs = [System.Convert]::FromBase64String($configprefsjs)
    [System.IO.File]::WriteAllBytes("$Env:Programfiles\Mozilla Firefox\defaults\pref\config-prefs.js", $configprefsjs)
    
    $firefoxcss = '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'

    $FirefoxProfile = (Get-ChildItem -Directory -Path "$Env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles" -Filter '*.default-release').FullName
    $FirefoxProfilecss = $FirefoxProfile + '\chrome.7z'
    $firefoxcss = [System.Convert]::FromBase64String($firefoxcss)
    [System.IO.File]::WriteAllBytes($FirefoxProfilecss, $firefoxcss)

    $FirefoxProfile = $FirefoxProfile + "/chrome"
    mkdir $FirefoxProfile 
    $FirefoxProfile = "-o" + $FirefoxProfile
    7z x $FirefoxProfilecss $FirefoxProfile
    Remove-Item $FirefoxProfilecss
    $FirefoxProfile = (Get-ChildItem -Directory -Path "$Env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles" -Filter '*.default-release').FullName
    $FirefoxProfile = $FirefoxProfile + '\prefs.js'
    $prefsjs = @"
user_pref("browser.compactmode.show", true);
user_pref("browser.uidensity", 1);
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);
"@

    Add-Content -Path $FirefoxProfile -Value $prefsjs
    Start-Process -FilePath "SetDefaultBrowser.exe" -ArgumentList "HKLM Firefox-308046B0AF4A39CB" -Wait -PassThru -NoNewWindow
}

function Install-WinUpdate {
    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
    }
    catch {
        #Do Nothing
    }
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module PSWindowsUpdate -Force
    Import-Module PSWindowsUpdate -Force
    Get-WindowsUpdate 
    Install-WindowsUpdate -AcceptAll -AutoReboot   
}

function Get-IP {
    Set-Clipboard -Value ((Invoke-WebRequest -uri "http://ifconfig.me/ip").Content)
    (Invoke-WebRequest -uri "http://ifconfig.me/ip").Content
}

Function Set-WallPaper {
    <#
 
    .SYNOPSIS
    Applies a specified wallpaper to the current user's desktop
    
    .PARAMETER Image
    Provide the exact path to the image
 
    .PARAMETER Style
    Provide wallpaper style (Example: Fill, Fit, Stretch, Tile, Center, or Span)
  
    .EXAMPLE
    Set-WallPaper -Image "C:\Wallpaper\Default.jpg"
    Set-WallPaper -Image "C:\Wallpaper\Background.jpg" -Style Fit

    
    https://www.joseespitia.com/2017/09/15/set-wallpaper-powershell-function/
#>
 
    param (
        [parameter(Mandatory = $True)]
        # Provide path to image
        [string]$Image,
        # Provide wallpaper style that you would like applied
        [parameter(Mandatory = $False)]
        [ValidateSet('Fill', 'Fit', 'Stretch', 'Tile', 'Center', 'Span')]
        [string]$Style
    )
 
    $WallpaperStyle = Switch ($Style) {
  
        "Fill" { "10" }
        "Fit" { "6" }
        "Stretch" { "2" }
        "Tile" { "0" }
        "Center" { "0" }
        "Span" { "22" }
  
    }
 
    If ($Style -eq "Tile") {
 
        New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
        New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 1 -Force
 
    }
    Else {
 
        New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
        New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 0 -Force
 
    }
 
    Add-Type -TypeDefinition @" 
using System; 
using System.Runtime.InteropServices;
  
public class Params
{ 
    [DllImport("User32.dll",CharSet=CharSet.Unicode)] 
    public static extern int SystemParametersInfo (Int32 uAction, 
                                                   Int32 uParam, 
                                                   String lpvParam, 
                                                   Int32 fuWinIni);
}
"@ 
  
    $SPI_SETDESKWALLPAPER = 0x0014
    $UpdateIniFile = 0x01
    $SendChangeEvent = 0x02
  
    $fWinIni = $UpdateIniFile -bor $SendChangeEvent
  
    $ret = [Params]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $Image, $fWinIni)
}

function Install-Choco {
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    choco feature enable -n allowGlobalConfirmation
}

function Get-TimeBasedOneTimePassword {
    [CmdletBinding()]
    [Alias('Get-TOTP')]
    param
    (
        #example t42_Get-TimeBasedOneTimePassword -SharedSecret 'YOHCC4TKKATXG2F4UJRU2J4AHK7YO2FO'
        # Base 32 formatted shared secret (RFC 4648).
        [Parameter(Mandatory = $true)]
        [System.String]
        $SharedSecret,

        # The date and time for the target calculation, default is now (UTC).
        [Parameter(Mandatory = $false)]
        [System.DateTime]
        $Timestamp = (Get-Date).ToUniversalTime(),

        # Token length of the one-time password, default is 6 characters.
        [Parameter(Mandatory = $false)]
        [System.Int32]
        $Length = 6,

        # The hash method to calculate the TOTP, default is HMAC SHA-1.
        [Parameter(Mandatory = $false)]
        [System.Security.Cryptography.KeyedHashAlgorithm]
        $KeyedHashAlgorithm = (New-Object -TypeName 'System.Security.Cryptography.HMACSHA1'),

        # Baseline time to start counting the steps (T0), default is Unix epoch.
        [Parameter(Mandatory = $false)]
        [System.DateTime]
        $Baseline = '1970-01-01 00:00:00',

        # Interval for the steps in seconds (TI), default is 30 seconds.
        [Parameter(Mandatory = $false)]
        [System.Int32]
        $Interval = 30
    )

    # Generate the number of intervals between T0 and the timestamp (now) and
    # convert it to a byte array with the help of Int64 and the bit converter.
    $numberOfSeconds = ($Timestamp - $Baseline).TotalSeconds
    $numberOfIntervals = [Convert]::ToInt64([Math]::Floor($numberOfSeconds / $Interval))
    $byteArrayInterval = [System.BitConverter]::GetBytes($numberOfIntervals)
    [Array]::Reverse($byteArrayInterval)

    # Use the shared secret as a key to convert the number of intervals to a
    # hash value.
    $KeyedHashAlgorithm.Key = Convert-Base32ToByte -Base32 $SharedSecret
    $hash = $KeyedHashAlgorithm.ComputeHash($byteArrayInterval)

    # Calculate offset, binary and otp according to RFC 6238 page 13.
    $offset = $hash[($hash.Length - 1)] -band 0xf
    $binary = (($hash[$offset + 0] -band '0x7f') -shl 24) -bor
          (($hash[$offset + 1] -band '0xff') -shl 16) -bor
          (($hash[$offset + 2] -band '0xff') -shl 8) -bor
          (($hash[$offset + 3] -band '0xff'))
    $otpInt = $binary % ([Math]::Pow(10, $Length))
    $otpStr = $otpInt.ToString().PadLeft($Length, '0')

    Write-Output $otpStr
}

function Convert-Base32ToByte {
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Base32
    )

    # RFC 4648 Base32 alphabet
    $rfc4648 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

    $bits = ''

    # Convert each Base32 character to the binary value between starting at
    # 00000 for A and ending with 11111 for 7.
    foreach ($char in $Base32.ToUpper().ToCharArray()) {
        $bits += [Convert]::ToString($rfc4648.IndexOf($char), 2).PadLeft(5, '0')
    }

    # Convert 8 bit chunks to bytes, ignore the last bits.
    for ($i = 0; $i -le ($bits.Length - 8); $i += 8) {
        [Byte] [Convert]::ToInt32($bits.Substring($i, 8), 2)
    }
}

function Switch-WindowsDefender {
    param (
        [Parameter(ParameterSetName = 'enable')]
        [switch]$Enable,
        [Parameter(ParameterSetName = 'disable')]
        [switch]$Disable
    )

    if ($Enable) {
        reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /f
        reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /f
        reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpynetRetporting /f
        reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f
    }
    else {
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /t REG_DWORD /v DisableRealtimeMonitoring /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /t REG_DWORD /v SubmitSamplesConsent /d 2 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /t REG_DWORD /v SpynetRetporting /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /t REG_DWORD /v DisableAntiSpyware /d 1 /f
    }
}

Function Export-Function {
    <#
    .Synopsis
       Exports a function from a module into a user given path
    
    .Description
       As synopsis
    
    .PARAMETER Function
       This Parameter takes a String input and is used in Both Parameter Sets
    
    .PARAMETER ResolvedFunction
       This should be passed the Function that you want to work with as an object making use of the following
       $ResolvedFunction = Get-Command "Command"
    
    .PARAMETER OutPath
       This is the location that you want to output all the module files to. It is recommended not to use the same location as where the module is installed.
       Also always check the files output what you expect them to.
    
    .PARAMETER PrivateFunction
       This is a switch that is used to correctly export Private Functions and is used internally in Export-AllModuleFunction
    
    .EXAMPLE
        Export-Function -Function Get-TwitterTweet -OutPath C:\TextFile\
    
        This will export the function into the C:\TextFile\Get\Get-TwitterTweet.ps1 file and also create a basic test file C:\TextFile\Get\Get-TwitterTweet.Tests.ps1
    
    .EXAMPLE
        Get-Command -Module SPCSPS | Where-Object {$_.CommandType -eq 'Function'} | ForEach-Object { Export-Function -Function $_.Name -OutPath C:\TextFile\SPCSPS\ }
    
        This will get all the Functions in the SPCSPS module (if it is loaded into memory or in a $env:PSModulePath as required by ModuleAutoLoading) and will export all the Functions into the C:\TextFile\SPCSPS\ folder under the respective Function Verbs. It will also create a basic Tests.ps1 file just like the prior example
    #>
    [cmdletbinding(DefaultParameterSetName = 'Basic')]
    
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Basic', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Parameter(Mandatory = $true, ParameterSetName = 'Passthru', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [ValidateNotNull()]
        [Alias('Command')]
        [Alias('Name')]
        [String]
        $Function,
    
        [Parameter(Mandatory = $true, ParametersetName = 'Passthru')]
        $ResolvedFunction,
    
        [Parameter(Mandatory = $true, ParameterSetName = 'Basic')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Passthru')]
        [Alias('Path')]
        [String]
        $OutPath,
    
        [Parameter(Mandatory = $false, ParametersetName = 'Passthru')]
        [Alias('Private')]
        [Switch]
        $PrivateFunction
    
    )
    
    $sb = New-Object -TypeName System.Text.StringBuilder
    
    If (!($ResolvedFunction)) { $ResolvedFunction = Get-Command $function }
    $code = $ResolvedFunction | Select-Object -ExpandProperty Definition
    $PublicOutPath = "$OutPath\"
    $ps1 = "$PublicOutPath$($ResolvedFunction.Verb)\$($ResolvedFunction.Name).ps1"
    
    foreach ($line in ($code -split '\r?\n')) {
        $sb.AppendLine('{0}' -f $line) | Out-Null
    }
    
    New-Item $ps1 -ItemType File -Force | Out-Null
    Write-Verbose -Message "Created File $ps1"

    Set-Content -Path $ps1 -Value $($sb.ToString())  -Encoding UTF8
    Write-Verbose -Message "Added the content of function $Function into the file"
    
}

Function Install-OpenSSH {
    Param(
        [parameter(Mandatory = $false)]
        [String]$port = "22"
    )

    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    Start-Service sshd
    (Get-Content -ReadCount 0 "$env:ProgramData\ssh\sshd_config") -replace "#Port 22", "Port $port" | Set-Content "$env:ProgramData\ssh\sshd_config"
    (Get-Content -ReadCount 0 "$env:ProgramData\ssh\sshd_config") -replace "Match Group administrators", '' | Set-Content "$env:ProgramData\ssh\sshd_config"
    (Get-Content -ReadCount 0 "$env:ProgramData\ssh\sshd_config") -replace "       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys", '' | Set-Content "$env:ProgramData\ssh\sshd_config"
    Remove-NetFirewallRule -DisplayName 'OpenSSH SSH Server (sshd)'
    Restart-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'
    New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort $port
}

Function Set-tom42 {
}

Function Get-IniFile ($file) {
    $ini = @{}
  
    $section = "NO_SECTION"
    $ini[$section] = @{}
  
    switch -regex -file $file {
        "^\[(.+)\]$" {
            $section = $matches[1].Trim()
            $ini[$section] = @{}
        }
        "^\s*([^#].+?)\s*=\s*(.*)" {
            $name, $value = $matches[1..2]
            # skip comments that start with semicolon:
            if (!($name.StartsWith(";"))) {
                $ini[$section][$name] = $value.Trim()
            }
        }
    }
    $ini
}

function Backup-Firefox {
    $firefox = Get-Process firefox -ErrorAction SilentlyContinue
    if ($firefox) {
        $firefox | Stop-Process -Force
    }
    Start-Sleep -Seconds 3
    Try {
        get-command "7z" -ErrorAction Stop -ErrorVariable ModFail             
    }
    Catch {
        choco install 7zip.install
    }

    $CurrentPath = (Get-Location).path
    $profilepath = ("$env:APPDATA\Mozilla\Firefox\") + ((Get-IniFile "$env:APPDATA\Mozilla\Firefox\profiles.ini").Profile0.Path).replace('/', '\')
    $extensionsJSON = Get-Content -Raw "$profilepath\extensions.json" | ConvertFrom-Json
    $extactive = New-Object System.Collections.ArrayList
    $extdisabled = New-Object System.Collections.ArrayList
    $i = 0


    foreach ($EXT in $extensionsJSON.addons) {
        if ($extensionsJSON.addons[$i].active -eq $true) {
            if (isURIWeb $extensionsJSON.addons[$i].sourceURI) {
                $extensionsJSONsuncle = $extensionsJSON.addons[$i].sourceURI -replace '-(?!media).*.xpi', "-latest.xpi" -replace '\?.*'
                $extactive.Add($extensionsJSONsuncle.split('?')[0])
                New-Item -Path "$CurrentPath\activeextensions" -ItemType Directory -Force  -ErrorAction SilentlyContinue
                $extensionsJSONsuncle = $extensionsJSON.addons[$i].id
                $extensionsJSONsuncle2 = $extensionsJSON.addons[$i].path
                Copy-Item -Path $extensionsJSONsuncle2 -Destination "$CurrentPath\activeextensions\$extensionsJSONsuncle.xpi"
            }
        }
        else {
            if (isURIWeb $extensionsJSON.addons[$i].sourceURI) {
                $extensionsJSONsuncle = $extensionsJSON.addons[$i].sourceURI -replace '-(?!media).*.xpi', "-latest.xpi" -replace '\?.*'
                $extdisabled.Add($extensionsJSONsuncle.split('?')[0])
                New-Item -Path "$CurrentPath\extensions" -ItemType Directory -Force  -ErrorAction SilentlyContinue
                $extensionsJSONsuncle = $extensionsJSON.addons[$i].id
                $extensionsJSONsuncle2 = $extensionsJSON.addons[$i].path
                Copy-Item -Path $extensionsJSONsuncle2 -Destination "$CurrentPath\extensions\$extensionsJSONsuncle.xpi"
            }
        }
        $i++
    }

    Remove-Item -Path "$CurrentPath\extensions\formautofill@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\pictureinpicture@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\screenshots@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\webcompat-reporter@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\webcompat@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\default-theme@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\addons-search-detection@mozilla.com.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\google@search.mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\amazondotcom@search.mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\wikipedia@search.mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\bing@search.mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\ddg@search.mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\firefox-compact-light@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\firefox-compact-dark@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\firefox-alpenglow@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\extensions\ebay@search.mozilla.org.xpi" -ErrorAction SilentlyContinue

    Remove-Item -Path "$CurrentPath\activeextensions\formautofill@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\pictureinpicture@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\screenshots@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\webcompat-reporter@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\webcompat@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\default-theme@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\addons-search-detection@mozilla.com.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\google@search.mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\amazondotcom@search.mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\wikipedia@search.mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\bing@search.mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\ddg@search.mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\firefox-compact-light@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\firefox-compact-dark@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\firefox-alpenglow@mozilla.org.xpi" -ErrorAction SilentlyContinue
    Remove-Item -Path "$CurrentPath\activeextensions\ebay@search.mozilla.org.xpi" -ErrorAction SilentlyContinue

    $extactive | Out-File "$CurrentPath\extensions.txt"
    $extdisabled | Out-File "$CurrentPath\disabled-extensions.txt"

    $ProfileFileName = Get-Date -Format FileDateTime | ForEach-Object { $_ -replace ":", "." }
    $ArgumentList = 'a -spm -m0=lzma2 -mx=9 -mfb=64 -md=256m "' + "$CurrentPath\activeextensions.7z" + '" "' + "$CurrentPath\activeextensions\*" + '"'
    Start-Process -FilePath "7z" -ArgumentList $ArgumentList -Wait -NoNewWindow
    $ArgumentList = 'a -spm -m0=lzma2 -mx=9 -mfb=64 -md=256m "' + "$CurrentPath\extensions.7z" + '" "' + "$CurrentPath\extensions\*" + '"'
    Start-Process -FilePath "7z" -ArgumentList $ArgumentList -Wait -NoNewWindow
    $filelist = New-Object System.Collections.ArrayList
    $filelist.Add("$profilepath\places.sqlite")
    $filelist.Add("$profilepath\favicons.sqlite")
    $filelist.Add("$profilepath\key4.db")
    $filelist.Add("$profilepath\logins.json")
    $filelist.Add("$profilepath\permissions.sqlite")
    $filelist.Add("$profilepath\content-prefs.sqlite")
    $filelist.Add("$profilepath\search.json.mozlz4")
    $filelist.Add("$profilepath\persdict.dat")
    $filelist.Add("$profilepath\formhistory.sqlite")
    $filelist.Add("$profilepath\cookies.sqlite")
    $filelist.Add("$profilepath\webappsstore.sqlite")
    $filelist.Add("$profilepath\chromeappsstore.sqlite")
    $filelist.Add("$profilepath\cert9.db")
    $filelist.Add("$profilepath\pkcs11.txt")
    $filelist.Add("$profilepath\handlers.json")
    $filelist.Add("$profilepath\sessionstore.jsonlz4")
    $filelist.Add("$profilepath\xulstore.json")
    $filelist.Add("$profilepath\prefs.js")
    $filelist.Add("$profilepath\containers.json")
    $filelist.Add("$CurrentPath\extensions.txt")
    $filelist.Add("$CurrentPath\disabled-extensions.txt")
    $filelist.Add("$CurrentPath\activeextensions.7z")
    $filelist.Add("$CurrentPath\extensions.7z")
    $filelist | Out-File "$CurrentPath\filelist.txt"

    $ArgumentList = 'a -spm -m0=lzma2 -mx=9 -mfb=64 -md=256m "' + "$CurrentPath\Firefox-Profile-Backup-$ProfileFileName.7z" + '" @"' + "$CurrentPath\filelist.txt" + '"'
    Start-Process -FilePath "7z" -ArgumentList $ArgumentList -Wait -NoNewWindow

    Remove-Item -Path "$CurrentPath\extensions" -Recurse -Force
    Remove-Item -Path "$CurrentPath\activeextensions" -Recurse -Force
    Remove-Item -Path "$CurrentPath\extensions.txt" -Recurse -Force
    Remove-Item -Path "$CurrentPath\disabled-extensions.txt" -Recurse -Force
    Remove-Item -Path "$CurrentPath\activeextensions.7z" -Recurse -Force
    Remove-Item -Path "$CurrentPath\extensions.7z" -Recurse -Force
    Remove-Item -Path "$CurrentPath\filelist.txt" -Recurse -Force
    if ($firefox) {
        $FirefoxVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Mozilla\Mozilla Firefox" -Name CurrentVersion).CurrentVersion
        $FirefoxEXE = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Mozilla\Mozilla Firefox\$FirefoxVersion\Main" -Name PathToExe).PathToExe
        Start-Process -FilePath $FirefoxEXE
    }
}

function Restore-Firefox {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $True)]
        [string]
        $FILE = "C:\WORK\Firefox-Profile-Backup-20221020T1227110604.7z"

    )
    
    Try {
        get-command "7z" -ErrorAction Stop -ErrorVariable ModFail             
    }
    Catch {
        choco install 7zip.install
    }

    $firefox = Get-Process firefox -ErrorAction SilentlyContinue
    if ($firefox) {
        $firefox | Stop-Process -Force
    }

    [string]$BackupTempFolder = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetRandomFileName().Split('.')[0] + "\")
    New-Item -Path $BackupTempFolder -ItemType Directory -Force
    $ArgumentList = 'x "' + "$FILE" + '" -o"' + "$BackupTempFolder" + '"'
    Start-Process -FilePath "7z" -ArgumentList $ArgumentList -Wait -NoNewWindow

    #disable Start
    [string]$DisableExtensionsFolder = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetRandomFileName().Split('.')[0] + "\")
    New-Item -Path $DisableExtensionsFolder -ItemType Directory -Force
    $ArgumentList = 'x "' + "$BackupTempFolder\extensions.7z" + '" -o"' + "$DisableExtensionsFolder" + '"'
    Start-Process -FilePath "7z" -ArgumentList $ArgumentList -Wait -NoNewWindow
    Remove-Item -Path "$BackupTempFolder\extensions.7z" -Force
    Remove-Item -Path "$BackupTempFolder\disabled-extensions.txt" -Force
    $XPIList = Get-ChildItem -Path "$DisableExtensionsFolder*" -Include ("*.xpi") -ErrorAction SilentlyContinue -Force | ForEach-Object { $_.fullname }
    $profilepath = ("$env:APPDATA\Mozilla\Firefox\") + ((Get-IniFile "$env:APPDATA\Mozilla\Firefox\profiles.ini").Profile0.Path).replace('/', '\')
    New-Item -Path "$profilepath\extensions" -ItemType Directory -Force
    foreach ($file in $XPIList) {

        Copy-Item -Path $file -Destination "$profilepath\extensions"
    }
    #disable Start

    $FirefoxVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Mozilla\Mozilla Firefox" -Name CurrentVersion).CurrentVersion
    $FirefoxEXE = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Mozilla\Mozilla Firefox\$FirefoxVersion\Main" -Name PathToExe).PathToExe
    Start-Process -FilePath $FirefoxEXE 
    Start-Sleep -Seconds 5
    
    $firefox = Get-Process firefox -ErrorAction SilentlyContinue
    if ($firefox) {
        $firefox | Stop-Process -Force
    }

    #Active Start
    [string]$ActiveExtensionsFolder = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetRandomFileName().Split('.')[0] + "\")
    New-Item -Path $ActiveExtensionsFolder -ItemType Directory -Force
    $ArgumentList = 'x "' + "$BackupTempFolder\activeextensions.7z" + '" -o"' + "$ActiveExtensionsFolder" + '"'
    Start-Process -FilePath "7z" -ArgumentList $ArgumentList -Wait -NoNewWindow
    Remove-Item -Path "$BackupTempFolder\activeextensions.7z" -Force

    $XPIList = Get-ChildItem -Path "$ActiveExtensionsFolder*" -Include ("*.xpi") -ErrorAction SilentlyContinue -Force | ForEach-Object { $_.fullname }

    Remove-Item -Path "$BackupTempFolder\extensions.txt" -Force

    $RegType = 'ExpandString'
    $UserDir = "$env:windir\system32\GroupPolicy\User\registry.pol"
    $RegPath = 'Software\Policies\Mozilla\Firefox\Extensions\Install'
    $RegName = 1

    foreach ($RegData in $XPIList) {
        Set-PolicyFileEntry -Path $UserDir -Key $RegPath -ValueName $RegName.ToString() -Data $RegData -Type $RegType
        $RegName++
    }
    Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -Wait -PassThru -NoNewWindow
    #Active end

    


    $fileList = Get-ChildItem -Path "$BackupTempFolder*" -Include ("*.*") -ErrorAction SilentlyContinue -Force | ForEach-Object { $_.fullname }

    foreach ($file in $fileList) {
        Copy-Item -Path $file -Destination $profilepath -Force
    }

    Remove-Item -Path "$BackupTempFolder" -Force -Recurse
    $FirefoxVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Mozilla\Mozilla Firefox" -Name CurrentVersion).CurrentVersion
    $FirefoxEXE = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Mozilla\Mozilla Firefox\$FirefoxVersion\Main" -Name PathToExe).PathToExe
    Start-Process -FilePath $FirefoxEXE 
    Start-Sleep -Seconds 5
    
    $firefox = Get-Process firefox -ErrorAction SilentlyContinue
    if ($firefox) {
        $firefox | Stop-Process -Force
    }

}