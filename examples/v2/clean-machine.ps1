# Clean-machine run of one v2 example: a fresh venv and profile dirs, tracekit-ai[signer] from this checkout plus the
# example's framework, then the example in scripted mode, timed.
#   examples\v2\clean-machine.ps1 [custom|langchain|openai_agents|claude_agent_sdk|mcp]   (default: custom)
param([ValidateSet("custom", "langchain", "openai_agents", "claude_agent_sdk", "mcp")][string]$Example = "custom")
$ErrorActionPreference = "Stop"
$extra = @{
    custom = @(); langchain = @("langchain>=1.4,<1.5", "langgraph>=1.2,<1.3"); openai_agents = @("openai-agents>=0.23.1,<0.24")
    claude_agent_sdk = @("claude-agent-sdk>=0.2.165,<0.3"); mcp = @("mcp>=2.3,<2.4")
}[$Example]
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$work = Join-Path ([IO.Path]::GetTempPath()) ("tk-clean-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
$env:HOME = $env:USERPROFILE = "$work\home"
$env:LOCALAPPDATA = "$work\home\local"
$env:TRACEKIT_RUNTIME_DIR = "$work\run"
Remove-Item Env:TRACEKIT_SIGNER, Env:PYTHONPATH -ErrorAction SilentlyContinue
$py = "$work\venv\Scripts\python.exe"
$clock = [Diagnostics.Stopwatch]::StartNew()
try {
    python -m venv "$work\venv"; if ($LASTEXITCODE) { throw "venv failed" }
    & $py -m pip install -q "$root[signer]" @extra; if ($LASTEXITCODE) { throw "pip install failed" }
    Push-Location $work
    & $py "$root\examples\v2\$Example\agent.py" --scripted; if ($LASTEXITCODE) { throw "the example failed" }
    Pop-Location
    "clean-machine ${Example}: {0:N0} s" -f $clock.Elapsed.TotalSeconds
} finally {
    if (Test-Path $py) { & $py -m tracekit down *> $null }
    Set-Location $root
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
