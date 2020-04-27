Contributing
============

There are lots of ways to contribute, from adding new features via pull
requests to opening issues for missing features. Check out our
`issues list <https://github.com/poljar/matrix-nio/issues>`_ and
filter for good first issues to find something we think you could tackle.

We recommend creating a Python 3 `virtual environment
<https://docs.python.org/3/tutorial/venv.html>`_ (or using `pipenv
<https://docs.python-guide.org/dev/virtualenvs/>`_) before you start coding to
keep the packages you need for nio separate from the packages you might need
for other projects. Throughout the rest of the document, we'll assume you're
working in your virtual environment.

Prerequisites
-------------

You'll need to install the following:

- ``make``
- `matrix-org/olm <https://gitlab.matrix.org/matrix-org/olm>`_ version 3.x

You'll also need to install some pip packages:

.. code-block:: sh

    pip install -r test-requirements.txt
    pip install -r rtd-requirements.txt


.. _Testing:

Testing
-------

As you write, you may want to test your changes. You can add new tests and test
files in ``tests/`` to be picked up by pytest. To run the full test suite
(please do this before submitting your pull request!), run

.. code-block:: sh

    make test


If you only want to test your changes (and not run all of the test suite), you can run the following:

.. code-block:: sh

	python3 -m pytest --benchmark-disable tests/your-test.py


Getting ready for a pull request
--------------------------------

`Get early feedback. <https://requests.readthedocs.io/en/master/dev/contributing/#get-early-feedback>`_
You don't need to perfect your changes to submit them; early feedback can help
guide you in the right direction, especially if you're struggling.

Make sure any new classes or methods you've added are properly documented, and if you've changed any existing methods make sure their docstrings are still up-to-date. It's really important to have good documentation because you encourage other people to use that great feature you just added!

Before you submit your code for discussion, please make sure your code passes
the test suite by reading Testing_. Next, run ``make typecheck`` to verify that
mypy is happy with the types in your code. Not sure about an error you got from
either? No worries; submit your changes and we'll talk about it.

When ready, push your changes to a fork of
`poljar/matrix-nio <https://github.com/poljar/matrix-nio>`_ and open up a pull
request. Give us a bit of a description of what changes you've made and why. If
you are trying to close an open issue, you can link to it just by writing
"Closes #104" in the description.

Adding documentation
--------------------

Writing might be hard, but with a few instructions we'll get you started. As
you code, you can just write docstrings in your classes and methods, but if you
want to document the architecture of nio (and we'd love if you did!) you can
help us write documentation in the `reStructuredText
<http://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html>`_
format.

You'll need to install
`Sphinx <https://www.sphinx-doc.org/en/master/index.html>`_
if you'd like to preview your changes:

.. code-block:: sh

    pip install sphinx

Once that is done, edit the ``.rst`` files in ``doc/`` and run ``make html``
in the same directory. You'll now have HTML pages in ``doc/build/html`` you
can review.
