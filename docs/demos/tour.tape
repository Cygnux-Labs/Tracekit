# The demos in docs/demos/ as one terminal video (charmbracelet/vhs). From the repo root, with tracekit installed
# (pip install -e .), or in the repo's .venv: vhs docs/demos/tour.tape
# Each demo runs in its own dir under /tmp/tracekit-tour (HOME and the dev signer's runtime dir too, never yours),
# with examples/ linked there, so the commands are the ones the demos' READMEs give; each run's bundle is renamed
# run.tkb, as in the demos' folders, before it is verified.

Output docs/demos/tracekit-tour.mp4

Set Shell bash
Set FontSize 16
Set Width 1400
Set Height 860
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set CursorBlink false
Set Framerate 20
Set TypingSpeed 40ms
Set WaitTimeout 120s
Set WaitPattern /^\$ ?$/

Hide
Type@5ms `export R=$PWD T=/tmp/tracekit-tour PS1='$ ' && export PATH=$R/.venv/bin:$PATH PYTHONPATH=$R TMPDIR=$T HOME=$T/home XDG_DATA_HOME=$T/home/data TRACEKIT_RUNTIME_DIR=$T/run PYTHONUNBUFFERED=1` Enter
Type@5ms `unset TRACEKIT_SIGNER TRACEKIT_SIGNER_TOKEN TRACEKIT_SIGNER_TOKEN_FILE TRACEKIT_EGRESS_PROXY; tracekit down >/dev/null 2>&1; rm -rf $T` Enter
Type@5ms `for d in guardrails mcp prompt-injection agent-approvers containment completeness egress why; do mkdir -p $T/$d && ln -s $R/examples $T/$d/examples; done; mkdir -p $T/home` Enter
Type@5ms `b() { clear; printf '\033[1;36m%s\033[0m\n%s\n\n' "$1" "$2"; }; cd $T` Enter
Type@5ms `b "Tracekit: tamper-evident tracing for AI agents" "Each tool call is decided and signed by a signer the agent can't control, and exported as a bundle anyone can verify offline."; echo "Eight recorded demos, offline: mock models, no API key, every outside host on this machine."` Enter
Wait
Show
Sleep 4500ms

# 1. Guardrails
Hide
Type@5ms `cd $T/guardrails; b "1/8  Guardrails: allow, deny, or ask a person" "A coding agent's shell calls are allowed, denied or held for a person, each decision signed before the call runs."` Enter
Wait
Show
Sleep 2500ms
Type "python examples/v2/custom/agent.py --scripted"
Sleep 300ms
Enter
Wait
Sleep 5s
Hide
Type@5ms `mv [0-9a-f]*.tkb run.tkb; b "1/8  Guardrails: verify" "The bundle, checked offline: only the signer's key, pinned in trust.json."` Enter
Wait
Show
Sleep 1s
Type "tracekit verify run.tkb --trust trust.json"
Sleep 300ms
Enter
Wait
Sleep 4s

# 2. MCP tools
Hide
Type@5ms `cd $T/mcp; b "2/8  MCP tools, gated and recorded" "MCP tool calls go through the same policy, approvals and signed record as the agent's own tools."` Enter
Wait
Show
Sleep 2500ms
Type "python examples/v2/mcp/agent.py --scripted"
Sleep 300ms
Enter
Wait
Sleep 5s
Hide
Type@5ms `mv [0-9a-f]*.tkb run.tkb; b "2/8  MCP tools: verify" "The bundle, checked offline: only the signer's key, pinned in trust.json."` Enter
Wait
Show
Sleep 1s
Type "tracekit verify run.tkb --trust trust.json"
Sleep 300ms
Enter
Wait
Sleep 3500ms

# 3. Prompt injection
Hide
Type@5ms `cd $T/prompt-injection; b "3/8  Prompt injection held by provenance" "A fetched page plants an email address; the send is held because its recipient came only from that page, and a person says no."` Enter
Wait
Show
Sleep 2500ms
Type "python examples/v2/demos/prompt_injection.py"
Sleep 300ms
Enter
Wait
Sleep 1s
ScrollUp@1ms 100
Sleep 8s
ScrollDown@20ms 25
Sleep 4s
Hide
Type@5ms `mv [0-9a-f]*.tkb run.tkb; b "3/8  Prompt injection: verify" "The bundle, checked offline: only the signer's key, pinned in trust.json."` Enter
Wait
Show
Sleep 1s
Type "tracekit verify run.tkb --trust trust.json"
Sleep 300ms
Enter
Wait
Sleep 3500ms

# 4. Agent approvers
Hide
Type@5ms `cd $T/agent-approvers; b "4/8  Agent approvers within bounds" "A reviewer agent clears only refunds within its bounds; people answer the rest, and a person's reject sticks."` Enter
Wait
Show
Sleep 2500ms
Type "python examples/v2/demos/agent_approvers.py"
Sleep 300ms
Enter
Wait
Sleep 1s
ScrollUp@1ms 100
Sleep 9s
ScrollDown@20ms 40
Sleep 4s
Hide
Type@5ms `mv [0-9a-f]*.tkb run.tkb; b "4/8  Agent approvers: verify" "The bundle, checked offline: only the signer's key, pinned in trust.json."` Enter
Wait
Show
Sleep 1s
Type "tracekit verify run.tkb --trust trust.json"
Sleep 300ms
Enter
Wait
Sleep 3500ms

# 5. Detection and containment
Hide
Type@5ms `cd $T/containment; b "5/8  Detection and containment" "A secret read, then an upload: the signer opens an incident and holds the run until a person resumes it."` Enter
Wait
Show
Sleep 2500ms
Type "python examples/v2/demos/containment.py"
Sleep 300ms
Enter
Wait
Sleep 1s
ScrollUp@1ms 100
Sleep 5s
ScrollDown@20ms 20
Sleep 5s
ScrollDown@20ms 35
Sleep 4s
Hide
Type@5ms `mv [0-9a-f]*.tkb run.tkb; b "5/8  Containment: verify" "The bundle, checked offline: the incident is recomputed from the bundle's own records and policy."` Enter
Wait
Show
Sleep 1s
Type "tracekit verify run.tkb --trust trust.json"
Sleep 300ms
Enter
Wait
Sleep 4s

# 6. Completeness and tamper evidence
Hide
Type@5ms `cd $T/completeness; b "6/8  Completeness and tamper evidence" "A call decided but never completed becomes a signed gap; then one byte is changed in a copy of the bundle."` Enter
Wait
Show
Sleep 2500ms
Type "python examples/v2/demos/completeness.py"
Sleep 300ms
Enter
Wait
Sleep 1s
ScrollUp@1ms 100
Sleep 5s
ScrollDown@20ms 30
Sleep 3s
Hide
Type@5ms `mv [0-9a-f]*.tkb run.tkb; b "6/8  Completeness: verify" "The bundle verifies, with the gap as a warning: nobody can remove it or move it to another call."` Enter
Wait
Show
Sleep 1s
Type "tracekit verify run.tkb --trust trust.json"
Sleep 300ms
Enter
Wait
Sleep 4s
Hide
Type@5ms `b "6/8  Completeness: the tampered copy" "The same bundle with one byte changed (the gap's call-2 now reads call-1)."` Enter
Wait
Show
Sleep 1s
Type "tracekit verify tampered.tkb --trust trust.json"
Sleep 300ms
Enter
Wait
Sleep 5s

# 7. Egress
Hide
Type@5ms `cd $T/egress; b "7/8  Network coverage: an egress observer" "An observer outside the agent records the hosts a run reached; one that no call explains is flagged."` Enter
Wait
Show
Sleep 2500ms
Type "python examples/v2/demos/egress.py"
Sleep 300ms
Enter
Wait
Sleep 1s
ScrollUp@1ms 100
Sleep 4s
ScrollDown@20ms 10
Sleep 5s
Hide
Type@5ms `mv [0-9a-f]*.tkb run.tkb; b "7/8  Egress: verify" "The bundle, checked offline: the observed host is a coverage warning."` Enter
Wait
Show
Sleep 1s
Type "tracekit verify run.tkb --trust trust.json"
Sleep 300ms
Enter
Wait
Sleep 4s

# 8. Why
Hide
Type@5ms `cd $T/why; b "8/8  Why: which input caused the action" "Every untrusted input reached an exfiltration email; replaying the run without each one shows which caused it."` Enter
Wait
Show
Sleep 2500ms
Type "tracekit why demo --out runs --n 10"
Sleep 300ms
Enter
Wait
Sleep 1s
ScrollUp@1ms 100
Sleep 6s
ScrollDown@20ms 20
Sleep 10s

Hide
Type@5ms `b "Tracekit" "Each demo's README, transcript, bundle and verify report are in docs/demos/."` Enter
Wait
Show
Sleep 3500ms
Hide
Type@5ms `tracekit down >/dev/null 2>&1; cd /; rm -rf $T` Enter
Wait
