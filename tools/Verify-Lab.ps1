$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    dotnet restore .\NotPetyaForensicLab.sln
    if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed with exit code $LASTEXITCODE" }
    dotnet build .\NotPetyaForensicLab.sln -c Release --no-restore
    if ($LASTEXITCODE -ne 0) { throw "dotnet build failed with exit code $LASTEXITCODE" }
    dotnet test .\NotPetyaForensicLab.sln -c Release --no-build --logger 'trx;LogFileName=forensic-lab-tests.trx'
    if ($LASTEXITCODE -ne 0) { throw "dotnet test failed with exit code $LASTEXITCODE" }

    $forbidden = @(
        'System.Net.Sockets', 'TcpClient', 'UdpClient', 'HttpClient', 'Process.Start',
        'OpenSCManager', 'CreateService', 'System.Management.Automation', 'RegistryKey'
    )
    $production = Get-ChildItem .\src -Recurse -Filter *.cs
    foreach ($pattern in $forbidden) {
        $matches = $production | Select-String -SimpleMatch $pattern
        if ($matches) { throw "Forbidden production API marker found: $pattern`n$matches" }
    }
    Write-Host 'Release build, tests, and source boundary scan completed.' -ForegroundColor Green
}
finally { Pop-Location }
