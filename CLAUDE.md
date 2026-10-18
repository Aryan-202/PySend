# PyLan

PyLan is an early-stage Python package for local-network file and data
sharing. The package supports Python 3.10 and newer; dependency metadata is
maintained in `pyproject.toml`, with the resolved environment in `uv.lock`.

Before making changes, inspect the relevant implementation and tests. Follow
the project-specific requirements in [`.claude/rules/engineering.md`](.claude/rules/engineering.md).

The key implementation areas are `pylan/core/protocol.py` (message framing),
`pylan/core/models.py` (device models and storage), and
`pylan/core/discovery.py` (multicast discovery and TCP probes). Preserve the
existing public API and wire format unless the requested change requires an
explicitly compatible update.

Tests are under `tests/` and use `unittest` test cases, runnable with pytest.
Prefer deterministic tests that mock network operations. For relevant
changes, run the focused tests and then `uv run pytest` when practical. State
clearly which checks were run and their results.
