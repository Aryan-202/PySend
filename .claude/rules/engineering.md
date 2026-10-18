# Engineering rules

## Python and dependencies

- Support the declared minimum of Python 3.10; avoid syntax or library APIs
  that require a newer version unless the project requirement is deliberately
  changed.
- Follow neighboring code: four-space indentation, type annotations, clear
  names, and concise docstrings on public APIs.
- Prefer the standard library and dependencies already declared in
  `pyproject.toml`. When a dependency change is necessary, update
  `pyproject.toml` and `uv.lock` consistently.
- Do not introduce lint, format, or type-check tooling as incidental cleanup.

## Network behavior and privacy

- Treat UDP datagrams and TCP responses as untrusted input. Check the expected
  structure and values before using them.
- Preserve the established message header and payload format unless the task
  explicitly calls for a protocol change; account for compatibility when
  doing so.
- Keep network resource cleanup explicit and async task/concurrency behavior
  bounded. Surface actionable errors using the existing logging or return
  conventions rather than silently masking new failure cases.
- Keep discovery and sharing local-network oriented. Do not add broad scans
  or remote-service behavior beyond the requested scope.
- Avoid logging payloads, secrets, or unnecessary device-identifying data.
  Describe security properties accurately; do not imply unfinished goals are
  already guarantees.

## Tests and changes

- Read the relevant code and tests before editing, and add tests for changed
  behavior and important failure paths.
- Keep tests deterministic. Mock sockets, TCP streams, and timing instead of
  relying on live network access.
- Run the most relevant test module first, followed by `uv run pytest` for
  cross-cutting changes. If `uv` is unavailable, use `python -m pytest` in the
  active project environment and state that substitution.
- Keep edits focused. Do not change unrelated code, generated files, or
  documentation outside the scope of the behavior being changed.
- Review the diff before finishing and report the implementation, actual
  validation results, and any known limitations.
