# Cross-platform main profile sourcing
$mainProfile = "$env:HOME/.config/profile.ps1"
if (Test-Path $mainProfile) {
    . $mainProfile
}