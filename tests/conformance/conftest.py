"""Fixtures for the opt-in `conformance_docker` suite.

These tests drive 1EdTech's official validators running as local Docker
services (see docker-compose.yml). They are deselected by default (the
`addopts = -m 'not conformance_docker'` in pyproject.toml) so the normal test
run and the release gate stay hermetic; the nightly conformance workflow opts
in with `pytest -m conformance_docker`.

Every test SKIPS (never fails) when its validator service is unreachable, so
running the suite without the Docker services up is a no-op, not a red build.
"""
import os
import threading
import urllib.error
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import pytest


def _reachable(url: str, timeout: float = 2.0) -> bool:
    """True if *url* answers any HTTP status (the service is up), False on a
    connection error/timeout (it is not)."""
    try:
        urllib.request.urlopen(url, timeout=timeout)   # noqa: S310 (localhost)
        return True
    except urllib.error.HTTPError:
        return True                     # a 4xx/5xx still means the port is live
    except (urllib.error.URLError, OSError):
        return False


def _validator_url(env_var: str, default: str) -> str:
    url = os.environ.get(env_var, default).rstrip('/')
    if not _reachable(url):
        pytest.skip(
            '%s (%s) is not reachable — bring the validator up with '
            '`docker compose -f tests/conformance/docker-compose.yml up -d '
            '--build` (see tests/conformance/README.md)' % (env_var, url))
    return url


@pytest.fixture
def ob2_validator_url() -> str:
    """Base URL of the official OB 2.0 validator (default http://localhost:8000)."""
    return _validator_url('OB2_VALIDATOR_URL', 'http://localhost:8000')


@pytest.fixture
def ob3_validator_url() -> str:
    """Base URL of the official OB 3.0 validator (default http://localhost:8080)."""
    return _validator_url('OB3_VALIDATOR_URL', 'http://localhost:8080')


@pytest.fixture
def serve_directory():
    """Factory: serve a directory over HTTP on an ephemeral port; yields the
    base URL the validator container should fetch from.

    The advertised host defaults to ``host.docker.internal`` — how a container
    reaches the host, built in on Docker Desktop and mapped to the host gateway
    via the compose ``extra_hosts`` on Linux/CI. Override with
    ``CONFORMANCE_ADVERTISE_HOST`` if the validator can reach the host another
    way (e.g. ``localhost`` under host networking).
    """
    servers = []

    def _serve(root: str) -> str:
        handler = partial(SimpleHTTPRequestHandler, directory=str(root))
        httpd = ThreadingHTTPServer(('0.0.0.0', 0), handler)   # noqa: S104
        port = httpd.socket.getsockname()[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        servers.append((httpd, thread))
        host = os.environ.get('CONFORMANCE_ADVERTISE_HOST', 'host.docker.internal')
        return 'http://%s:%d' % (host, port)

    yield _serve

    for httpd, thread in servers:
        httpd.shutdown()
        thread.join(timeout=5)
