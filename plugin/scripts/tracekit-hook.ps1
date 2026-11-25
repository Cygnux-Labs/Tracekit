# The plugin's hook entry point on native Windows without Git Bash, where Claude Code runs hooks/claude.json's command
# in PowerShell: there `./tracekit-hook` runs this script, and sh runs tracekit-hook beside it. It does what
# tracekit-hook does for Claude Code, with the same exit codes and messages: read that script's header first. System
# mode is left out: Windows has none (tracekit.client.system_config ignores /etc/tracekit/client.json there).
# Windows PowerShell 5.1 drops the double quotes inside an argument it passes to a program, so the Python below has
# none.
$ev = if ($args.Count) { [string]$args[0] } else { '' }

# Finish status what fix: as tracekit-hook's finish, without fail_mode open (system mode only).
function Finish($status, $what, $fix) {
    if ($status -eq 0) { exit 0 }
    if ($ev -eq 'PreToolUse') {
        if ($status -eq 2) { exit 2 }
        [Console]::Error.WriteLine("tracekit plugin: $what, so this call was blocked (fail-closed). $fix")
        exit 2
    }
    if ($status -ne 1 -and $status -ne 2) {
        [Console]::Error.WriteLine("tracekit plugin: $what, so this $ev event was NOT recorded. $fix")
    }
    exit 1
}
# an error this script didn't expect blocks a tool call too, as a hook that starts but can't finish does
trap { Finish 3 "the plugin's hook script failed ($_)" 'Ask the person to reinstall the plugin.' }

$min = '1.7.3'   # the oldest tracekit it runs with, as tracekit-hook's MIN_TRACEKIT
$userSite = 'import site, sys; sys.path.append(site.getusersitepackages())'   # (addsitedir would run its .pth files)
$run = "`nMIN = '$min'" + @'

import inspect
pre = sys.argv[1:2] == ['PreToolUse']
try:
    from tracekit.integrations.claude_code import _entry
    why = '' if inspect.signature(_entry).parameters else 'is older than 1.2'
except Exception as e:
    why = 'cannot import its hook (%s: %s)' % (type(e).__name__, e)
if not why:
    import re, tracekit
    now = tuple(map(int, re.findall(r'\d+', getattr(tracekit, '__version__', '0'))[:3]))
    why = '' if now >= tuple(map(int, MIN.split('.'))) else 'is older than this plugin, which needs %s' % MIN
if why:
    import tracekit
    print('tracekit plugin: tracekit %s in %s %s, so this %s. Ask the person to run: uv tool install tracekit-ai==1.7.3 && '
          'tracekit init --dev --v2 --no-hooks' % (getattr(tracekit, '__version__', '?'), sys.executable, why,
                                     'call was blocked' if pre else 'event was NOT recorded'), file=sys.stderr)
    raise SystemExit(2 if pre else 1)
raise SystemExit(_entry(*sys.argv[1:2]))
'@
# <plugins root>\cache\<marketplace>\<plugin>\<version>, as tracekit-hook reads it
$off = 'turn the plugin off in /plugin'
$parts = @(([string]$env:CLAUDE_PLUGIN_ROOT).TrimEnd('\', '/') -split '[\\/]')
if ($parts.Count -ge 4 -and $parts[-4] -eq 'cache' -and $parts[-3] -and $parts[-2]) {
    $off = "turn the plugin off: /plugin disable $($parts[-2])@$($parts[-3])"
}

# As tracekit-hook: once `tracekit init` has recorded its Python (hook_python in ~\.tracekit-client\config.json, a folder
# TK-D007 keeps from the agent), that one runs the hook and no other: not TRACEKIT_PYTHON, PATH or a default folder. It
# must be the Python of a uv tool or pipx install of Tracekit (install.tool_venvs' folders), unless init recorded that a
# person allowed it. A record that can't run the hook, or a Tracekit that is set up with none recorded, blocks the call.
$share = if ($env:XDG_DATA_HOME) { $env:XDG_DATA_HOME } else { Join-Path $HOME '.local\share' }
$uvTools = if ($env:UV_TOOL_DIR) { $env:UV_TOOL_DIR } else { Join-Path $share 'uv\tools' }
$pipx = if ($env:PIPX_HOME) { $env:PIPX_HOME } else { Join-Path $share 'pipx' }
$venvs = @($uvTools, (Join-Path $pipx 'venvs'), (Join-Path $HOME '.local\pipx\venvs'),
           (Join-Path $HOME 'Library\Application Support\pipx\venvs'))
$cfg = Join-Path $HOME '.tracekit-client\config.json'
$recorded = if (Test-Path -LiteralPath $cfg -PathType Leaf) { Get-Content -LiteralPath $cfg -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
$rec = if ($recorded) { [string]$recorded.hook_python } else { '' }
if ($rec) {
    $inside = $false
    $recPath = $rec -replace '/', '\'
    foreach ($v in $venvs) {
        $tool = ($v.TrimEnd('\', '/') + '/tracekit-ai/') -replace '/', '\'
        if ($recPath.StartsWith($tool, [StringComparison]::OrdinalIgnoreCase)) { $inside = $true }
    }
    if (-not $inside -and $recorded.hook_python_allowed -ne $true) {
        Finish 3 "the Python tracekit init recorded for this hook ($rec) is not one of a uv tool or pipx install of Tracekit" 'Ask the person to run: uv tool install --reinstall tracekit-ai==1.7.3 && tracekit init --dev --v2 --no-hooks'
    }
    if (Test-Path -LiteralPath $rec -PathType Leaf) {
        & $rec -I -c 'import tracekit' *> $null
        if ($LASTEXITCODE -eq 0) {
            & $rec -I -c ('import sys' + $run) @args
            Finish $LASTEXITCODE "$rec could not run the tracekit hook" 'Ask the person to reinstall: uv tool install --reinstall tracekit-ai==1.7.3 && tracekit init --dev --v2 --no-hooks'
        }
    }
    Finish 3 "$rec, the Python tracekit init recorded for this hook, cannot import tracekit" 'Ask the person to run: uv tool install --reinstall tracekit-ai==1.7.3 && tracekit init --dev --v2 --no-hooks'
}
$setUp = $env:LOCALAPPDATA -and (Test-Path -PathType Container (Join-Path $env:LOCALAPPDATA 'tracekit'))
if ($setUp) {
    Finish 3 'tracekit init has recorded no Python for this hook, though Tracekit is set up' "Ask the person to run: uv tool install tracekit-ai==1.7.3 && tracekit init --dev --v2 --no-hooks, or $off"
}
# Before Tracekit is set up: the first of TRACEKIT_PYTHON, python3 and python that has the package.
# lean: unlike tracekit-hook, no uv tool or pipx install's Python comes first and no `tracekit` command's Python is tried;
# port them when native Windows without Git Bash is run in CI.
foreach ($py in @($env:TRACEKIT_PYTHON, 'python3', 'python')) {
    if (-not $py) { continue }
    # Application only: never a function or alias the profile defines. The Store's python3 stub fails the import.
    if (-not (Get-Command $py -CommandType Application -ErrorAction SilentlyContinue)) { continue }
    & $py -I -c "$userSite; import tracekit" *> $null
    if ($LASTEXITCODE -eq 0) {
        & $py -I -c ($userSite + $run) @args
        Finish $LASTEXITCODE "$py could not run the tracekit hook" 'Ask the person to reinstall: uv tool install --reinstall tracekit-ai==1.7.3'
    }
}
if ($env:TRACEKIT_PYTHON -or $env:TRACEKIT_SIGNER) {
    Finish 3 'no Python here (TRACEKIT_PYTHON, python3, python) has the tracekit package, though Tracekit is set up' "Ask the person to install it (uv tool install tracekit-ai==1.7.3), set TRACEKIT_PYTHON to the Python that has it, or $off"
}
[Console]::Error.WriteLine("tracekit plugin: the tracekit package is not installed for python3, so this $ev event was NOT recorded. Ask the person to set it up: uv tool install tracekit-ai==1.7.3 && tracekit init --dev --v2 --no-hooks")
exit 1
