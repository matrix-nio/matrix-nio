PYTHON   ?= python

all:

test:
	python3 -m pytest
	python2 -m pytest
	python3 -m pytest --flake8
	python3 -m pytest --isort
	python3 -m pytest --cov

clean:
	-rm -r dist/ __pycache__/

.PHONY: all clean test
