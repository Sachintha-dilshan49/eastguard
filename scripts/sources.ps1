# Regenerates sources.txt (the javac argument file) from every .java file under src/ and test/.
# Run from the project root:  .\scripts\sources.ps1
# If the execution policy blocks it:  powershell -ExecutionPolicy Bypass -File scripts\sources.ps1
# Output is stable across runs: forward slashes, ordinal sort, LF line endings, UTF-8 without BOM.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$prefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar

$files = New-Object System.Collections.Generic.List[string]
foreach ($dir in 'src', 'test') {
    $path = Join-Path $root $dir
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Recurse -File -Filter *.java | ForEach-Object {
            $files.Add($_.FullName.Substring($prefix.Length).Replace('\', '/'))
        }
    }
}
$sorted = $files.ToArray()
[Array]::Sort($sorted, [StringComparer]::Ordinal)

$text = if ($sorted.Length -gt 0) { ($sorted -join "`n") + "`n" } else { '' }
[IO.File]::WriteAllText((Join-Path $root 'sources.txt'), $text, (New-Object System.Text.UTF8Encoding $false))
Write-Output "sources.txt: $($sorted.Length) files"
