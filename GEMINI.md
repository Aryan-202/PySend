# PyLan project guidance

## Project overview

PyLan is an early-stage Python project for transferring files and other data
between nearby devices on a local network. It is intended to become both a
standalone application and a reusable package. Security and privacy are
important project goals, but do not describe planned or incomplete safeguards
as implemented.

The package requires Python 3.10 or newer. Dependencies and package metadata
are defined in `pyproject.toml`; `uv.lock` records the resolved environment.

## Repository map

- `pylan/core/protocol.py` implements the binary message header and payload
  serialization.
- `pylan/core/models.py` defines discovery data models and the in-memory
  device store.
- `pylan/core/discovery.py` implements multicast discovery, TCP probing, and
  subnet scanning.
- `pylan/main.py` is the current console-script entry point; keep its
  intentionally limited behavior in mind when making CLI changes.
- `tests/` contains the unit tests for protocol framing and peer discovery.

Keep changes within the relevant layer. Preserve existing public names and the
wire format unless a requested change explicitly requires a compatible
protocol update.

## Engineering expectations

- Match the surrounding Python style: four-space indentation, clear names,
  useful type annotations, and focused docstrings for public APIs.
- Prefer small, testable changes and the standard library or existing
  dependencies. Add a dependency only when the task requires it, and update
  `pyproject.toml` and `uv.lock` together.
- Treat all network input as untrusted. Validate message shape and values
  before using them; keep resource lifetimes explicit and asynchronous
  concurrency bounded.
- Keep discovery and transfer behavior local-network scoped. Do not add
  unrelated remote-service dependencies, broad network scanning, or claims
  that the current implementation provides complete security.
- Avoid logging payload contents, secrets, or unnecessary personal/device
  information.
- Tests should be deterministic and should mock sockets, connections, and
  timing rather than depend on a live network.
- Do not add formatter, linter, or type-checker configuration unless requested
  or needed for the change; the repository does not currently configure those
  tools.

## Validation

Run the smallest relevant test selection, then the full unit suite when the
change affects shared behavior:

```sh
uv run pytest tests/test_protocol.py
uv run pytest tests/test_discovery.py
uv run pytest
```

If `uv` is unavailable, use the project's active environment with
`python -m pytest` and report the command actually run. Do not claim a check
passed unless it was run successfully.

## Change workflow

1. Read the implementation and its tests before changing behavior.
2. Add or update tests for observable behavior, including error paths where
   appropriate.
3. Keep the patch focused; do not rewrite unrelated files or generated
   artifacts.
4. Review the final diff for accidental changes and summarize behavior,
   validation, and any remaining limitations.
