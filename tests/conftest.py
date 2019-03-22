# -*- coding: utf-8 -*-
import sys
import pytest
import helpers
import shutil
import tempfile

from nio import Client


@pytest.fixture
def tempdir():
    newpath = tempfile.mkdtemp()
    yield newpath
    shutil.rmtree(newpath)


@pytest.fixture
def client(tempdir):
    return Client("ephemeral", "DEVICEID", tempdir)


if sys.version_info >= (3, 5):
    from nio import AsyncClient
    from aioresponses import aioresponses

    @pytest.fixture
    def async_client(tempdir):
        return AsyncClient(
            "https://example.org",
            "ephemeral",
            "DEVICEID",
            tempdir
        )

    @pytest.fixture
    def aioresponse():
        with aioresponses() as m:
            yield m


@pytest.fixture
def frame_factory():
    return helpers.FrameFactory()
