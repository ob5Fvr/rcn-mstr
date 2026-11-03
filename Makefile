.PHONY: install dev test cov selftest lint clean
install:
	pip install -e .
dev:
	pip install -e ".[dev]"
test:
	pytest -q
cov:
	pytest -q --cov=rcnmstr --cov-report=term-missing
selftest:
	python -m rcnmstr --self-test -o rcn-selftest-out
lint:
	python -m pyflakes rcnmstr || true
clean:
	rm -rf rcn-out rcn-selftest-out .pytest_cache .coverage htmlcov build dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
