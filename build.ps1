param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$upstreamRoot = Join-Path $projectRoot 'upstream\amneziawg-go'
$tag = 'v3.1.20260828'
$commit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'
if (!(Test-Path -LiteralPath $upstreamRoot)) {
 git clone --depth 1 --branch $tag https://github.com/amnezia-vpn/amneziawg-go.git $upstreamRoot
 if ($LASTEXITCODE -ne 0) { throw 'Git clone failed' }
}
$actual = git -C $upstreamRoot rev-parse HEAD
if ($actual -ne $commit) { throw 'Unexpected upstream revision' }
$overlay = Join-Path $upstreamRoot 'asusctl'
New-Item -ItemType Directory -Path $overlay -Force | Out-Null
Copy-Item -Path (Join-Path $projectRoot 'src\asusctl\*.go') -Destination $overlay -Force
$originalMain = (git -C $upstreamRoot show HEAD:main.go) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'Cannot read upstream main.go' }
$patched = $originalMain.Replace('"fmt"', '"fmt"' + "`n" + '"github.com/amnezia-vpn/amneziawg-go/v3/asusctl"').Replace('func main() {', 'func main() {' + "`n" + 'if asusctl.Run(os.Args) { return }')
[IO.File]::WriteAllText((Join-Path $upstreamRoot 'main.go'), $patched, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $upstreamRoot 'version.go'), "package main`nconst Version = `"3.1.20260828-asus-0.4.0`"`n", [Text.UTF8Encoding]::new($false))
if (!$SkipTests) {
 python (Join-Path $projectRoot 'scripts\test_shell_compat.py')
 if ($LASTEXITCODE -ne 0) { throw 'Shell compatibility tests failed' }
 node (Join-Path $projectRoot 'scripts\test_web_response.js')
 if ($LASTEXITCODE -ne 0) { throw 'Web response tests failed' }
 node (Join-Path $projectRoot 'scripts\test_ui_form.js')
 if ($LASTEXITCODE -ne 0) { throw 'Guided form tests failed' }
 node (Join-Path $projectRoot 'scripts\test_config_view.js')
 if ($LASTEXITCODE -ne 0) { throw 'Configuration preview tests failed' }
 node (Join-Path $projectRoot 'scripts\test_hot_ui.js')
 if ($LASTEXITCODE -ne 0) { throw 'Hot peer UI tests failed' }
 node (Join-Path $projectRoot 'scripts\test_server_ui.js')
 if ($LASTEXITCODE -ne 0) { throw 'Server UI tests failed' }
}
$oldGOOS=$env:GOOS; $oldGOARCH=$env:GOARCH; $oldCGO=$env:CGO_ENABLED
Push-Location $upstreamRoot
try {
 $env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
 if (!$SkipTests) { go test ./asusctl; if ($LASTEXITCODE -ne 0) { throw 'Tests failed' } }
 $env:GOOS='linux'; $env:GOARCH='arm64'
 New-Item -ItemType Directory -Path (Join-Path $projectRoot 'plugin\bin') -Force | Out-Null
 go build -trimpath -ldflags '-s -w -buildid=' -o (Join-Path $projectRoot 'plugin\bin\amneziawg-go') .
 if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
} finally { Pop-Location; $env:GOOS=$oldGOOS; $env:GOARCH=$oldGOARCH; $env:CGO_ENABLED=$oldCGO }
python (Join-Path $projectRoot 'scripts\package.py')
if ($LASTEXITCODE -ne 0) { throw 'Packaging failed' }
