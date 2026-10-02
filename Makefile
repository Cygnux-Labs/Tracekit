.PHONY: help install test lint build check demo eval clean
PY ?= python3

help:
	@echo "make install   editable install with dev extras"
	@echo "make test      run the test suite"
	@echo "make lint      pyflakes over the package, SDK and tests"
	@echo "make build     build the sdist and wheel into dist/"
	@echo "make check     lint + test + build + twine check"
	@echo "make demo      run the scripted end-to-end demo"
	@echo "make eval      offline evaluations E1 (integrity) and E3 (policy gate); rewrites eval/results/"
	@echo "make clean     remove build artefacts"

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m pyflakes tracekit tracekit_sdk.py tests eval examples

build:
	$(PY) -m pip install -q build twine
	$(PY) -m build
	$(PY) -m twine check dist/*

check: lint test build

demo:
	$(PY) -m tracekit demo

eval:
	$(PY) eval/e1_integrity.py
	$(PY) eval/e3_policy.py

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
