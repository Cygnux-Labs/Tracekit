# Renders docs/demo/demo.gif with VHS (https://github.com/charmbracelet/vhs): vhs docs/demo/demo.tape
# Needs `tracekit` on PATH. The demo makes its own temp folder: scripted agent, policy block, export, verify, tamper test.
Output docs/demo/demo.gif
Set Width 1000
Set Height 600
Set FontSize 14
Set TypingSpeed 50ms

Hide
Type "cd $(mktemp -d) && clear"
Enter
Show

Type "tracekit demo"
Sleep 500ms
Enter
Sleep 20s
