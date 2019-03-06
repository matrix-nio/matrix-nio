# -*- coding: utf-8 -*-
import os
import pytest
import helpers
import shutil
import tempfile

from nio import Client, HttpClient


@pytest.fixture
def tempdir():
    newpath = tempfile.mkdtemp()
    yield newpath
    shutil.rmtree(newpath)


@pytest.fixture
def client(tempdir):
    return Client("ephemeral", "DEVICEID", tempdir)


@pytest.fixture
def http_client(tempdir):
    return HttpClient("example.org", "ephemeral", "DEVICEID", tempdir)


@pytest.fixture
def frame_factory():
    return helpers.FrameFactory()
