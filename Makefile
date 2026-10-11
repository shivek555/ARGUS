.PHONY: test poc

test:
	python -m pytest -q

poc:
	python -m argus.eval.poc
