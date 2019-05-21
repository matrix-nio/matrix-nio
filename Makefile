PYTHON   ?= python

all:

test:
	python3 -m pytest --benchmark-disable
	python3 -m pytest --flake8 nio --benchmark-disable

typecheck:
	mypy -p nio --ignore-missing-imports --warn-redundant-casts

coverage:
	python3 -m pytest --cov nio --benchmark-disable

isort:
	isort -p nio

clean:
	-rm -r dist/ __pycache__/
	-rm -r packages/

install:
	$(PYTHON) setup.py build
	$(PYTHON) setup.py install --skip-build -O1 --root=$(DESTDIR)

archpkg:
	-rm -r packages/
	mkdir packages
	cp contrib/archlinux/pkgbuild/PKGBUILD packages/
	cd packages && makepkg -ci

arch-git-pkg:
	-rm -r packages/
	umask 0022 && $(PYTHON) setup.py sdist --dist-dir packages
	cp contrib/archlinux/pkgbuild/PKGBUILD.git packages/PKGBUILD
	cd packages && makepkg -ci


.PHONY: all clean test typecheck coverage
