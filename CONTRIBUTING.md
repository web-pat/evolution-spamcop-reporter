# Contributing

Use Python 3.12+ and a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Runtime code uses the standard library. Keep adapters, parsing, storage, submission,
transports, analytics and CLI responsibilities separate. Add type hints and meaningful
tests for changed behavior. Any state-machine change must test restart and concurrent
operation. A new external interface needs primary-source documentation, failure
semantics and a working fallback, not an invented API.

Tests must use synthetic mail and mocked transports. Never contact SpamCop, fetch
private mail or embed real credentials in a test. GUI/MTA integration testing should
use an isolated local capture transport with no network delivery. Review diffs for
personal addresses, paths, configuration and generated artifacts before submitting.

Send pull requests with a short behavioral description, test results, compatibility
notes and updated docs. Contributions are provided under Apache-2.0. Do not commit
virtual environments, databases, reports, real spam or personal configuration.
