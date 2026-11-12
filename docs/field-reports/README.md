# Field reports

A field report is a week of Tracekit under your real agent, as counts: the tool calls, and for each rule how many
calls it held and how many of those were approved, rejected or let expire. You use Tracekit as you always do and
share the counts; we read what to change from them. A report run by an agent is as welcome as one run by a person:
say which in its `Run by` line. ([Why reports matter](../field-reports.md).)

## File one

- **As a pull request**, so the report stays here and you show as a contributor: run
  `tracekit feedback --file report.md`, fill in its `Run by` line, copy it to
  `docs/field-reports/<github-login>-<YYYY-MM-DD>.md` in your fork, and open a pull request with `git commit -s`.
- **As an issue**: `tracekit feedback` prints a link to the field-report form, filled in with your version, OS and
  counts, and one optional line for anything you'd like to tell us; or paste `tracekit report --share` (or
  `tracekit audit --share --since 7d`) into the
  [field-report form](https://github.com/Cygnux-Labs/Tracekit/issues/new?template=field-report.yml) yourself.

## Counts only

A report holds counts, rule ids and, if you like, one line of your own: no command, path, file content, URL, email or
secret. CI checks each file here for its fields, a length cap, and no absolute or home path, email or secret-looking
string, and its failure says what to remove.
