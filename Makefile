PYTHON   ?= python

all:

test:
	python3 -m pytest
	python3 -m pytest --flake8 nio
	python3 -m pytest --isort nio
	python3 -m pytest --cov nio

clean:
	-rm -r dist/ __pycache__/

.PHONY: all clean test
