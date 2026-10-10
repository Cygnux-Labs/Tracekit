.PHONY: help install test quickstart test-contrib test-ts eval-scale lint build check demo eval eval-agents clean
PY ?= python3

help:
	@echo "make install   editable install with dev extras"
	@echo "make test      run the test suite"
	@echo "make quickstart  build the wheel into a fresh venv and run the v2 quickstart end to end (needs the package index)"
	@echo "make test-contrib  run the contrib/ packages' tests against the installed packages (pip install . ./contrib/*)"
	@echo "make lint      pyflakes over the package, SDK and tests"
	@echo "make build     build the sdist and wheel into dist/"
	@echo "make check     lint + test + build + twine check"
	@echo "make demo      run the scripted end-to-end demo"
	@echo "make eval      offline evaluations E1 (integrity), E2 (overhead), E3 (policy gate), E4 (seeded faults, v1 and v2), E6 (findings), on Linux E9 --quick (signer perf); rewrites eval/results/"
	@echo "make eval-agents  E5: real Claude Code runs (needs the claude CLI; spends model usage)"
	@echo "make eval-scale   E7: SQL index over a million-event ledger (contrib/query)"
	@echo "E8 (insider attacks) needs root and a Linux system-mode signer; CI runs it, see eval/e8_insider.py"
	@echo "E9 (signer perf, gates on Linux) and E15 (kill -9 durability, POSIX): eval/e9_signer_perf.py, eval/e15_durability.py"
	@echo "make clean     remove build artefacts"

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

quickstart:
	TRACEKIT_QUICKSTART=1 $(PY) -m pytest -q -s -m quickstart tests/test_quickstart.py

eval-scale:
	$(PY) contrib/query/e7_sql_scale.py

test-contrib:
	$(PY) -m pytest -q contrib

test-ts:
	cd sdk/typescript && npm install --no-audit --no-fund && npm test

lint:
	$(PY) -m pyflakes tracekit tracekit_sdk.py tests eval examples contrib

build:
	$(PY) -m pip install -q build twine
	$(PY) -m build
	$(PY) -m twine check dist/*

check: lint test build

demo:
	$(PY) -m tracekit demo

eval:
	$(PY) eval/e1_integrity.py
	$(PY) eval/e2_perf.py
	$(PY) eval/e3_policy.py
	$(PY) eval/e4_seeded_faults.py
	$(PY) eval/e4_seeded_faults_v2.py
	$(PY) eval/e6_findings.py
	$(PY) eval/e10_reconcile.py
	$(PY) eval/e11_l1_tampering.py
	$(PY) eval/e12_cross_tenant.py
	$(PY) eval/e14_outage.py --quick
	$(PY) eval/e16_doctor.py
	if [ "$$(uname)" = Linux ]; then $(PY) eval/e9_signer_perf.py --quick; fi

eval-agents:
	E5=1 $(PY) eval/e5_agents.py

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
