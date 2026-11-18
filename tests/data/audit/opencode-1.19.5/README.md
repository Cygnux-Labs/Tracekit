# OpenCode 1.19.5 recording

One real OpenCode 1.19.5 session on Windows 11 (model `big-pickle`): list a folder, create `hello.txt`, read it, edit it,
read it again. OpenCode keeps its sessions in `~/.local/share/opencode/opencode.db`, a SQLite database.

`rows.json` holds that database's `session` row and all 24 `part` rows (columns `id`, `message_id`, `session_id`,
`time_created`, `time_updated`, `data`), as they were written. Only the person's Windows user name was replaced
(`user`); the tests load the rows into a database with the `session` and `part` columns the reader uses.
