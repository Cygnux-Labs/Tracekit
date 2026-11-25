# The plugin's hook entry point on native Windows without Git Bash, where Claude Code runs hooks.json's command in
# PowerShell: there `./tracekit-hook` runs this script, and sh runs tracekit-hook beside it. It does what tracekit-hook
# does, with the same exit codes and messages: read that script's header first. System mode is left out: Windows has
# none (tracekit.client.system_config ignores /etc/tracekit/client.json there).
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

$paths = 'import site, sys; site.addsitedir(site.getusersitepackages())'
$run = $paths + @'

import inspect
pre = sys.argv[1:2] == ['PreToolUse']
try:
    from tracekit.integrations.claude_code import _entry
    why = '' if inspect.signature(_entry).parameters else 'is older than 1.2'
except Exception as e:
    why = 'cannot import its hook (%s: %s)' % (type(e).__name__, e)
if why:
    import tracekit
    print('tracekit plugin: tracekit %s in %s %s, so this %s. Ask the person to run: pip install tracekit-ai==1.7.3 && '
          'tracekit init --dev --v2 --no-hooks' % (getattr(tracekit, '__version__', '?'), sys.executable, why,
                                     'call was blocked' if pre else 'event was NOT recorded'), file=sys.stderr)
    raise SystemExit(2 if pre else 1)
raise SystemExit(_entry(*sys.argv[1:2]))
'@
foreach ($py in @($env:TRACEKIT_PYTHON, 'python3', 'python')) {
    if (-not $py) { continue }
    # Application only: never a function or alias the profile defines. The Store's python3 stub fails the import.
    if (-not (Get-Command $py -CommandType Application -ErrorAction SilentlyContinue)) { continue }
    & $py -I -c "$paths; import tracekit" *> $null
    if ($LASTEXITCODE -eq 0) {
        & $py -I -c $run @args
        Finish $LASTEXITCODE "$py could not run the tracekit hook" 'Ask the person to reinstall: pip install tracekit-ai==1.7.3'
    }
}
if ($env:TRACEKIT_PYTHON -or $env:TRACEKIT_SIGNER -or ($env:LOCALAPPDATA -and (Test-Path -PathType Container (Join-Path $env:LOCALAPPDATA 'tracekit')))) {
    # <plugins root>\cache\<marketplace>\<plugin>\<version>, as tracekit-hook reads it
    $off = 'turn the plugin off in /plugin'
    $parts = @(([string]$env:CLAUDE_PLUGIN_ROOT).TrimEnd('\', '/') -split '[\\/]')
    if ($parts.Count -ge 4 -and $parts[-4] -eq 'cache' -and $parts[-3] -and $parts[-2]) {
        $off = "turn the plugin off: /plugin disable $($parts[-2])@$($parts[-3])"
    }
    Finish 3 'no Python here (TRACEKIT_PYTHON, python3, python) has the tracekit package, though Tracekit is set up' "Ask the person to install it (pip install tracekit-ai==1.7.3), set TRACEKIT_PYTHON to the Python that has it, or $off"
}
[Console]::Error.WriteLine("tracekit plugin: the tracekit package is not installed for python3, so this $ev event was NOT recorded. Ask the person to set it up: pip install tracekit-ai==1.7.3 && tracekit init --dev --v2 --no-hooks")
exit 1
