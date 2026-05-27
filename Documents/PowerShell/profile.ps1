# Source main profile
$mainProfile = "$env:HOMEDRIVE\$env:HOMEPATH\.config\profile.ps1"
if (Test-Path $mainProfile) {
    . $mainProfile
}