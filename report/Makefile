PY ?= python3

# Checks the report's tables against eval/results and its links; renders the PDF when pandoc is installed.
all:
	cd .. && $(PY) -m pytest -q tests/test_report.py
	@if command -v pandoc >/dev/null; then pandoc tracekit-v2.md -s -o tracekit-v2.pdf && echo wrote tracekit-v2.pdf; \
	else echo "pandoc not installed: Markdown checked, no PDF"; fi

tables:
	$(PY) tables.py

.PHONY: all tables
