# Skip loading profile when running in Cursor sandbox (fast, no network/modules)
if ($env:NPM_CONFIG_CACHE -and $env:NPM_CONFIG_CACHE -eq 'cursor-sandbox-cache') { return }

#region functions

function Get-FileHash256 {
  <#
  .SYNOPSIS
    Compute the SHA-256 hash for a given file.
  .DESCRIPTION
    Wrapper function for Get-FileHash which defaulst the Algorithm parameter to
    SHA256 and copies the returned hash to the clipboard.
  .PARAMETER Path
    Fully qualified path to the file for which to obtain the SHA-256 hash.
  .EXAMPLE
    Get-FileHash256 -Path C:\Windows\System32\notepad.exe
  #>
  [CmdletBinding()]
  param (
    [System.IO.FileInfo]$Path
  )

  if (-not (Test-Path $Path)) {
    throw "File $Path not found, could not determine hash."
  }

  $sha_256_hash = (Get-FileHash -Algorithm SHA256 $Path).hash
  Write-Host "SHA-256 hash copied to clipboard for [$Path]: " -NoNewline
  Write-Host $sha_256_hash -ForegroundColor Green
  return $sha_256_hash | Set-Clipboard
}

function Edit-Profile {
  & code $profile.CurrentUserAllHosts
}

function Open-HistoryFile {
  <#
  .SYNOPSIS
    Opens the PowerShell history file.
  .DESCRIPTION
    Opens the (Get-PSReadLineOption).HistorySavePath file conditionally in one
    of the following programs:
    1. PowerShell ISE, if detected as the current host.
    2. VSCode, if detected as the current host.
    3. Notepad, if the current host is netiher of the above.
  .EXAMPLE
    Open-HistoryFile
  #>

  if (-not (Get-Module PSReadLine)) {
    Write-Warning 'PSReadLine not loaded; cannot open history file.'
    return
  }
  $HISTORY_PATH = (Get-PSReadLineOption).HistorySavePath

  if (Get-Command 'code' -ErrorAction SilentlyContinue)
  {
    code $HISTORY_PATH
  }
  else
  {
    if ($IsWindows)
    {
      Start-Process "$env:windir\system32\notepad.exe" -ArgumentList $HISTORY_PATH
    }
    else
    {
      vi $HISTORY_PATH
    }
  }
}

function Read-JWT {
  <#
  .SYNOPSIS
    Parses a valid JWT and returns its details within a PSObject
  .DESCRIPTION
    Parses the header and payload base64 strings of a valid JWT.
    The header is printed out as a PSObject while the payload is returned as a PSObject.
  .PARAMETER Token
    Valid JWT (https://tools.ietf.org/html/rfc7519)
  .EXAMPLE
    Read-JWT -Token $token # must be a valid JWT
  .LINK
    https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
  #>

  [cmdletbinding()]
  param([Parameter(Mandatory = $true)][string]$Token)

  #Validate as per https://tools.ietf.org/html/rfc7519
  #Access and ID tokens are fine, Refresh tokens will not work
  if (!$Token.Contains(".") -or !$Token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }

  #Header
  $tokenheader = $Token.Split(".")[0].Replace('-', '+').Replace('_', '/')
  #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
  while ($tokenheader.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }
  Write-Verbose "Base64 encoded (padded) header:"
  Write-Verbose $tokenheader
  #Convert from Base64 encoded string to PSObject all at once
  Write-Verbose "Decoded header:"
  [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json | Format-List | Out-Default

  #Payload
  $tokenPayload = $Token.Split(".")[1].Replace('-', '+').Replace('_', '/')
  #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
  while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
  Write-Verbose "Base64 encoded (padded) payoad:"
  Write-Verbose $tokenPayload
  #Convert to Byte array
  $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
  #Convert to string array
  $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
  Write-Verbose "Decoded array in JSON format:"
  Write-Verbose $tokenArray
  #Convert from JSON to PSObject
  $tokobj = $tokenArray | ConvertFrom-Json
  Write-Verbose "Decoded Payload:"
  
  return $tokobj
}

function Get-StringHash {
  [CmdletBinding()]
  [OutputType([System.String])]
  param (
      [ValidateScript({ ![System.String]::IsNullOrEmpty($PSItem) })][System.String]$String,
      [ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')][System.String]$Algorithm
  )
  process {
      $ErrorActionPreference = 'stop'
      Set-StrictMode -Version 'latest'

      $inputBytes    = [System.Text.Encoding]::UTF8.GetBytes($String)
      $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
      # [System.Security.Cryptography.HashAlgorithmName]

      return ( [System.BitConverter]::ToString( $hashAlgorithm.ComputeHash($inputBytes) ) -replace '-' )
  }
}

function Write-Definition($command) {
  Write-Output (Get-Command $command).Definition
}

function Get-PublicIP {
  Invoke-RestMethod http://ifconfig.me/ip
}

if ($IsWindows) {
  function Update-InsecurePEM {
    <#
    .SYNOPSIS
      Updates a private key file so that it's secure enough for ssh
    .DESCRIPTION
      ssh complains when private keys with default permissions are supplied. This function
      will change the security settings on the given file:
      - Disable inheritance
      - Set Ownership to Owner
      - Remove all users except for Owner
    .PARAMETER Token
      Private key file
    .EXAMPLE
      Update-InsecurePEM ~/.ssh/id_rsa
    .LINK
      https://superuser.com/a/1329702
    #>
  
    [cmdletbinding()]
    param([Parameter(Mandatory = $true)][string]$PrivateKey)
    
    # Remove Inheritance:
    Icacls $PrivateKey /c /t /Inheritance:d
  
    # Set Ownership to Owner:
    # Key's within $env:UserProfile:
    Icacls $PrivateKey /c /t /Grant ${env:UserName}:F
  
    # Key's outside of $env:UserProfile:
    TakeOwn /F $PrivateKey
    Icacls $PrivateKey /c /t /Grant:r ${env:UserName}:F
  
    # Remove All Users, except for Owner:
    Icacls $PrivateKey /c /t /Remove:g Administrator "Authenticated Users" BUILTIN\Administrators BUILTIN Everyone System Users
  }

  function sudo {
    Start-Process @args -Verb RunAs -Wait
  }
}

#endregion

#region execution

################################################################################
# Update the console title with current PowerShell elevation and version       #
################################################################################
$baseTitle = "PS | v$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
try {
  $Host.UI.RawUI.WindowTitle = "$baseTitle | $((Invoke-WebRequest -Uri 'https://wttr.in/nyc?format=%c%t&u' -UseBasicParsing -TimeoutSec 3).Content)"
} catch {
  $Host.UI.RawUI.WindowTitle = "$baseTitle | $env:COMPUTERNAME"
}

################################################################################
# PSReadLine and prompt options                                                #
################################################################################
if (-not (Get-Module PSReadline)) {
  Write-Warning 'Failed to locate PSReadLine module'
}
else {
  Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
  Set-PSReadLineOption -ShowToolTips -BellStyle Visual -HistoryNoDuplicates
  try {
    Set-PSReadLineOption -PredictionSource History -PredictionViewStyle ListView
  } catch {
    # PredictionSource / PredictionViewStyle require PSReadLine 2.1+ (e.g. not in WinPS 5.1)
  }

  if ($env:STARSHIP_SHELL -in 'powershell', 'pwsh') {
    # Set the prompt character to change color based on syntax errors
    # https://github.com/PowerShell/PSReadLine/issues/1541#issuecomment-631870062
    $esc = [char]0x1b
    $symbol = [char]0x276F  # ❯
    $fg = '0'
    $bg = '8;2;78;213;93'  # 24-bit color
    $err_bg = '1'
    $csi = "$esc" + "["
    Set-PSReadLineOption -PromptText (
      " ${csi}4${fg};3${bg}m$symbol ",
      " ${csi}4${fg};3${err_bg}m$symbol "
    )
    $env:STARSHIP_LOG = 'error'
  }
}

# https://starship.rs/ — cache init script so we don't spawn starship every startup
$starshipCacheDir = if ($env:XDG_CACHE_HOME) { $env:XDG_CACHE_HOME } elseif ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $env:HOME '.cache' }
$starshipCache = Join-Path $starshipCacheDir 'starship-init.ps1'
$cacheMaxAgeHours = 24
$useCache = (Test-Path $starshipCache) -and ((Get-Item $starshipCache).LastWriteTime -gt (Get-Date).AddHours(-$cacheMaxAgeHours))
if ($useCache) {
  . $starshipCache
} else {
  $init = & starship init powershell 2>$null
  if ($init) {
    New-Item -ItemType Directory -Path $starshipCacheDir -Force | Out-Null
    $init | Set-Content -Path $starshipCache -Encoding utf8 -Force
    Invoke-Expression ($init -join "`n")
  } else {
    Invoke-Expression (&starship init powershell)
  }
}

################################################################################
# Windows/Linux differences                                                    #
################################################################################
if ($IsLinux -or $IsMacOs) {
  # PSDepend doesn't seem to work on PS7 on Linux, install modules here.
  Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
  $modules = @('PowerShellGet', 'PSReadLine', 'Get-ChildItemColor', 'PSWriteHTML')
  $available = (Get-Module -ListAvailable).Name
  foreach ($module in $modules) {
    if ($module -notin $available) {
      Install-Module $module -AllowClobber -AllowPrerelease -Scope CurrentUser -Force
    }
  }

  # Initialise homebrew if available
  $brewPath = if ($IsMacOs) { '/opt/homebrew/bin/brew' } else { '/home/linuxbrew/.linuxbrew/bin/brew' }
  if (Test-Path $brewPath) {
    & $brewPath shellenv | Invoke-Expression
  }
} else {
  # Chezmoi edit command defaults to vi, which doesn't exist on Windows
  $env:EDITOR = 'code'
}

################################################################################
# Set common aliases                                                           #
################################################################################
if (Get-Command Get-ChildItemColor -ErrorAction SilentlyContinue) {
  Set-Alias -Name ll -Value Get-ChildItemColor -Scope Global -Option AllScope
  Set-Alias -Name ls -Value Get-ChildItemColorFormatWide -Scope Global -Option AllScope
  Set-Alias -Name dir -Value Get-ChildItemColorFormatWide -Scope Global -Option AllScope
}
Set-Alias -Name g -Value git
Set-Alias -Name History -Value Open-HistoryFile -Scope Global -Option AllScope

#endregion
