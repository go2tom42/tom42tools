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
        (New-Object System.Net.WebClient).DownloadFile($URL,"$env:TEMP\part1.ps1");Start-Process -FilePath "powershell.exe" -ArgumentList "-executionpolicy bypass -File $env:TEMP\part1.ps1" -Verb RunAs    
    } else {
        Write-Host 'NOT VALID URL'
        Pause
    }
    
}

function isURIWeb($address) {
	$uri = $address -as [System.URI]
	$null -ne $uri.AbsoluteURI -and $uri.Scheme -match '[http|https]'
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
        [parameter(Mandatory=$True)]
        [string]
        $URL='NA',

        [parameter(Mandatory=$True)]
        [string]
        $PATH='NA',

        [parameter(Mandatory=$True)]
        [string]
        $USER='NA',

        [parameter(Mandatory=$True)]
        [string]
        $PASS='NA'
    )

    if ($PATH -eq 'NA') {Write-Host 'NOT VALID PATH';exit}
    if ($PASS -eq 'NA') {Write-Host 'NOT VALID PASS';exit}
    if ($USER -eq 'NA') {Write-Host 'NOT VALID USER';exit}

    if (isURIWeb $URL) {
        $WebClient = New-Object System.Net.WebClient;
        $WebClient.Credentials = New-Object System.Net.Networkcredential($user, $pass)
        $WebClient.DownloadFile($url, $path)
    } else {
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
    } else {
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'Run' -Value $Command -PropertyType ExpandString
    }
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
    [parameter(Mandatory=$True)]
    # Provide path to image
    [string]$Image,
    # Provide wallpaper style that you would like applied
    [parameter(Mandatory=$False)]
    [ValidateSet('Fill', 'Fit', 'Stretch', 'Tile', 'Center', 'Span')]
    [string]$Style
)
 
$WallpaperStyle = Switch ($Style) {
  
    "Fill" {"10"}
    "Fit" {"6"}
    "Stretch" {"2"}
    "Tile" {"0"}
    "Center" {"0"}
    "Span" {"22"}
  
}
 
If($Style -eq "Tile") {
 
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
$numberOfSeconds   = ($Timestamp - $Baseline).TotalSeconds
$numberOfIntervals = [Convert]::ToInt64([Math]::Floor($numberOfSeconds / $Interval))
$byteArrayInterval = [System.BitConverter]::GetBytes($numberOfIntervals)
[Array]::Reverse($byteArrayInterval)

# Use the shared secret as a key to convert the number of intervals to a
# hash value.
$KeyedHashAlgorithm.Key = Convert-Base32ToByte -Base32 $SharedSecret
$hash = $KeyedHashAlgorithm.ComputeHash($byteArrayInterval)

# Calculate offset, binary and otp according to RFC 6238 page 13.
$offset = $hash[($hash.Length-1)] -band 0xf
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
foreach ($char in $Base32.ToUpper().ToCharArray())
{
    $bits += [Convert]::ToString($rfc4648.IndexOf($char), 2).PadLeft(5, '0')
}

# Convert 8 bit chunks to bytes, ignore the last bits.
for ($i = 0; $i -le ($bits.Length - 8); $i += 8)
{
    [Byte] [Convert]::ToInt32($bits.Substring($i, 8), 2)
}
}
function Switch-WindowsDefender {
    param (
        [Parameter(ParameterSetName='enable')]
        [switch]$Enable,
        [Parameter(ParameterSetName='disable')]
        [switch]$Disable
    )

    if ($Enable) {
        reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /f
        reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /f
        reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpynetRetporting /f
        reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f
    } else {
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
    [cmdletbinding(DefaultParameterSetName='Basic')]
    
    Param(
        [Parameter(Mandatory=$true,ParameterSetName='Basic',ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [Parameter(Mandatory=$true,ParameterSetName='Passthru',ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [ValidateNotNull()]
        [Alias('Command')]
        [Alias('Name')]
        [String]
        $Function,
    
        [Parameter(Mandatory=$true,ParametersetName='Passthru')]
        $ResolvedFunction,
    
        [Parameter(Mandatory=$true,ParameterSetName='Basic')]
        [Parameter(Mandatory=$true,ParameterSetName='Passthru')]
        [Alias('Path')]
        [String]
        $OutPath,
    
        [Parameter(Mandatory=$false,ParametersetName='Passthru')]
        [Alias('Private')]
        [Switch]
        $PrivateFunction
    
        )
    
    $sb = New-Object -TypeName System.Text.StringBuilder
    
     If (!($ResolvedFunction)) { $ResolvedFunction = Get-Command $function}
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
