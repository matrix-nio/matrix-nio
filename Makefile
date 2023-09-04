PYTHON   ?= python

all:

init:
	pre-commit install --install-hooks

test:
	python3 -m pytest --benchmark-disable

typecheck:
	mypy -p nio --ignore-missing-imports --warn-redundant-casts

coverage:
	python3 -m pytest --cov nio --benchmark-disable

clean:
	-rm -r dist/ __pycache__/
	-rm -r packages/

arch-git-pkg:
	-rm -r packages/
	umask 0022 && poetry build --format sdist
	cp contrib/archlinux/pkgbuild/PKGBUILD.git dist/PKGBUILD
	cd dist && makepkg -ci


.PHONY: all clean init test typecheck coverage
