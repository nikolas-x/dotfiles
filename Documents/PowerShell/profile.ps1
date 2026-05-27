# Source main profile (Windows location for $profile.CurrentUserAllHosts)
$mainProfile = "$env:HOMEDRIVE\$env:HOMEPATH\.config\profile.ps1"
if (Test-Path $mainProfile) {
    . $mainProfile
}