# inject-runsc.ps1
# Injects the gVisor (runsc) runtime into the Docker Desktop daemon config after Docker starts.
# Schedule via Task Scheduler: trigger = At log on, action = powershell -File <this script>

$runscPath = "/mnt/docker-desktop-disk/gvisor/runsc"
$maxWait   = 120  # seconds
$interval  = 3    # poll interval

Write-Host "Waiting for Docker Desktop to start..."

$elapsed = 0
while ($elapsed -lt $maxWait) {
    $result = & wsl -d docker-desktop -e sh -lc "pidof dockerd" 2>$null
    if ($result -match '^\d+$') { break }
    Start-Sleep -Seconds $interval
    $elapsed += $interval
}

if ($elapsed -ge $maxWait) {
    Write-Error "Timed out waiting for dockerd to start."
    exit 1
}

$dockerdPid = $result.Trim()
Write-Host "dockerd PID: $dockerdPid"

# Read active daemon.json from dockerd process namespace
$json = & wsl -d docker-desktop -e sh -lc "cat /proc/$dockerdPid/root/run/config/docker/daemon.json"
if (-not $json) {
    Write-Error "Could not read daemon.json"
    exit 1
}

$obj = $json | ConvertFrom-Json

# Ensure runtimes property exists
if (-not $obj.runtimes) {
    $obj | Add-Member -MemberType NoteProperty -Name runtimes -Value (New-Object PSCustomObject) -Force
}

# Check if runsc is already registered
if ($obj.runtimes.PSObject.Properties.Name -contains 'runsc') {
    Write-Host "runsc runtime already registered. Nothing to do."
    exit 0
}

# Inject runsc
$obj.runtimes | Add-Member -MemberType NoteProperty -Name runsc -Value @{ path = $runscPath } -Force

$newJson = $obj | ConvertTo-Json -Depth 10
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($newJson))

# Write updated config back into dockerd process namespace
& wsl -d docker-desktop -e sh -lc "printf '%s' $b64 | base64 -d > /proc/$dockerdPid/root/run/config/docker/daemon.json"

# Reload dockerd
& wsl -d docker-desktop -e sh -lc "kill -HUP $dockerdPid"

Start-Sleep -Seconds 2

# Verify
$runtimes = & wsl -d Ubuntu-24.04 -e sh -lc "docker info | grep -i runtime"
Write-Host "Registered runtimes: $runtimes"

if ($runtimes -match 'runsc') {
    Write-Host "SUCCESS: runsc runtime registered."
} else {
    Write-Error "runsc runtime not found after reload."
    exit 1
}
