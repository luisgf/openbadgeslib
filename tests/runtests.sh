#!/bin/sh
# Run the test suite with pytest (the runner configured in pyproject.toml).
exec python3 -m pytest "$@"
