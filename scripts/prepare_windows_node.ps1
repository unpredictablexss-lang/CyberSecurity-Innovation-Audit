param([string]$Distribution = 'Ubuntu')
$ErrorActionPreference = 'Stop'
function Get-ArchiveSha256([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}
$arch = ((& wsl.exe -d $Distribution --exec uname -m) -join '').Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify WSL architecture.' }
switch ($arch) {
    'x86_64' { $nodeArch='x64'; $expected='f4cb75bb036f0d0eddf6b79d9596df1aaab9ddccd6a20bf489be5abe9467e84e' }
    'aarch64' { $nodeArch='arm64'; $expected='eab80cb88f8fda1e65f5e8d0420c9809bdb320b03fd34976ab7161b6e703b910' }
    default { throw "Unsupported WSL architecture: $arch" }
}
$sourceRoot = Split-Path -Parent $PSScriptRoot
$cache = Join-Path $sourceRoot '.deploy\downloads'
New-Item -ItemType Directory -Path $cache -Force | Out-Null
$name = "node-v22.16.0-linux-$nodeArch.tar.xz"
$archive = Join-Path $cache $name
if ((Test-Path -LiteralPath $archive) -and (Get-ArchiveSha256 $archive) -eq $expected) {
    Write-Host 'Using checksum-verified Node archive from the Windows download cache.'
    return
}
$url = [Uri]("https://nodejs.org/dist/v22.16.0/" + $name)
$downloadArgs = @('--fail','--location','--retry','2','--connect-timeout','15','--max-time','180')
# curl does not automatically use the Windows Internet Options proxy. Resolve it
# here, where 127.0.0.1 is the Windows host, rather than inside WSL's NAT network.
$proxy = [System.Net.WebRequest]::DefaultWebProxy
if ($proxy -and -not $proxy.IsBypassed($url)) {
    $proxyUri = $proxy.GetProxy($url)
    if ($proxyUri.AbsoluteUri -ne $url.AbsoluteUri) { $downloadArgs += @('--proxy', $proxyUri.AbsoluteUri) }
}
$partial = $archive + '.part'
Write-Host 'Downloading the Linux Node runtime through Windows networking (including the Windows proxy).'
& curl.exe @downloadArgs $url.AbsoluteUri '--output' $partial
if ($LASTEXITCODE -ne 0) { throw 'Node download failed on Windows. Check Internet/Windows proxy access to nodejs.org, then rerun; the service has not started.' }
if ((Get-ArchiveSha256 $partial) -ne $expected) { throw 'Node archive SHA-256 mismatch; refusing to use the download.' }
Move-Item -LiteralPath $partial -Destination $archive -Force
Write-Host 'Windows Node download and SHA-256 verification passed.'
