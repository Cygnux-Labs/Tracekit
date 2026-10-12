# A short cut of tour.tape for the GIF in docs/demos/README.md: guardrails, prompt injection, a tampered bundle and
# tracekit why. From the repo root, with tracekit installed (pip install -e .), or in the repo's .venv:
# vhs docs/demos/highlights.tape

Output docs/demos/highlights.gif

Set Shell bash
Set FontSize 16
Set Width 1400
Set Height 860
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set CursorBlink false
Set Framerate 15
Set TypingSpeed 40ms
Set WaitTimeout 120s
Set WaitPattern /^\$ ?$/

Hide
Type@5ms `export R=$PWD T=/tmp/tracekit-highlights PS1='$ ' && export PATH=$R/.venv/bin:$PATH PYTHONPATH=$R TMPDIR=$T HOME=$T/home XDG_DATA_HOME=$T/home/data TRACEKIT_RUNTIME_DIR=$T/run PYTHONUNBUFFERED=1` Enter
Type@5ms `unset TRACEKIT_SIGNER TRACEKIT_SIGNER_TOKEN TRACEKIT_SIGNER_TOKEN_FILE TRACEKIT_EGRESS_PROXY; tracekit down >/dev/null 2>&1; rm -rf $T` Enter
Type@5ms `for d in guardrails prompt-injection completeness why; do mkdir -p $T/$d && ln -s $R/examples $T/$d/examples; done; mkdir -p $T/home` Enter
Type@5ms `b() { clear; printf '\033[1;36m%s\033[0m\n%s\n\n' "$1" "$2"; }; cd $T` Enter
Type@5ms `b "Tracekit: tamper-evident tracing for AI agents" "Each tool call is decided and signed by a signer the agent can't control, and exported as a bundle anyone can verify offline."` Enter
Wait
Show
Sleep 3500ms

Hide
Type@5ms `cd $T/guardrails; b "Guardrails: allow, deny, or ask a person" "A coding agent's shell calls are allowed, denied or held for a person, each decision signed before the call runs."` Enter
Wait
Show
Sleep 2500ms
Type "python examples/v2/custom/agent.py --scripted"
Sleep 400ms
Enter
Wait
Sleep 6s

Hide
Type@5ms `cd $T/prompt-injection; b "Prompt injection held by provenance" "A fetched page plants an email address; the send is held because its recipient came only from that page, and a person says no."` Enter
Wait
Show
Sleep 2500ms
Type "python examples/v2/demos/prompt_injection.py"
Sleep 400ms
Enter
Wait
Sleep 1s
ScrollUp@1ms 100
Sleep 8s
ScrollDown@1ms 25
Sleep 4s

Hide
Type@5ms `cd $T/completeness; b "Tamper evidence" "An agent's run with a signed gap, then one byte changed in a copy of its bundle."` Enter
Wait
Show
Sleep 2500ms
Type "python examples/v2/demos/completeness.py"
Sleep 400ms
Enter
Wait
Sleep 3s
Hide
Type@5ms `b "Tamper evidence: the changed copy" "The gap's call-2 now reads call-1."` Enter
Wait
Show
Sleep 1s
Type "tracekit verify tampered.tkb --trust trust.json"
Sleep 400ms
Enter
Wait
Sleep 6s

Hide
Type@5ms `cd $T/why; b "Why: which input caused the action" "Every untrusted input reached an exfiltration email; replaying the run without each one shows which caused it."` Enter
Wait
Show
Sleep 2500ms
Type "tracekit why demo --out runs --n 10"
Sleep 400ms
Enter
Wait
Sleep 1s
ScrollUp@1ms 100
Sleep 5s
ScrollDown@1ms 20
Sleep 10s

Hide
Type@5ms `tracekit down >/dev/null 2>&1; cd /; rm -rf $T` Enter
Wait
