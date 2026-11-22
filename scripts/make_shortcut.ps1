# Creates "Sentinel Test Lab.lnk" in the project root, pointing at the built exe.
# Run again after moving or renaming the project folder:
#   powershell -ExecutionPolicy Bypass -File scripts\make_shortcut.ps1
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'dist\SentinelTestLab\SentinelTestLab.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    Write-Error "Build the app first: .venv\Scripts\python.exe -m PyInstaller sentinel.spec --noconfirm"
    exit 1
}
$shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $root 'Sentinel Test Lab.lnk'))
$shortcut.TargetPath = $exe
$shortcut.WorkingDirectory = Split-Path -Parent $exe
$shortcut.IconLocation = "$exe,0"
$shortcut.Description = 'Sentinel Test Lab'
$shortcut.Save()
Write-Output "Shortcut created: $(Join-Path $root 'Sentinel Test Lab.lnk')"
