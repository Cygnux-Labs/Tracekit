# Renders docs/demo/demo.gif with VHS (https://github.com/charmbracelet/vhs): vhs docs/demo/demo.tape
# Needs `tracekit` on PATH. The demo makes its own temp folder: scripted agent, policy block, export, verify, tamper test.
Output docs/demo/demo.gif
Set Width 1400
Set Height 1100
Set FontSize 13
Set Padding 16
Set TypingSpeed 50ms

Hide
Type "export TMPDIR=/tmp && cd $(mktemp -d) && clear"
Enter
Show

Type "tracekit demo"
Sleep 500ms
Enter
Sleep 12s
