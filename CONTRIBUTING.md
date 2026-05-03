# Contributing to Bulwark

Thanks for considering a contribution. Bulwark protects production AI
agents — bug fixes and new defensive surfaces are very welcome. This
document is the contract for contributing.

## Code of Conduct

Be respectful, be specific, be patient. Disagreements about technical
trade-offs are normal; personal attacks are not.

## How to report a bug

Open an issue with:

1. Bulwark version (`bulwark --version`).
2. Python version and OS.
3. A minimal code sample that reproduces the bug.
4. What you expected vs. what you got.
5. Stack trace if there is one.

If the bug has security impact, do **not** open a public issue. See
[SECURITY.md](SECURITY.md) instead.

## How to request a feature

Open a discussion (not an issue) describing:

1. The use case — what real workflow needs this?
2. Why existing surfaces don't cover it.
3. A rough API sketch.

Bulwark deliberately stays small. New surfaces require a clear contract
and a path to test coverage.

## Development setup

```bash
git clone https://github.com/bulwark-security/bulwark
cd bulwark
python -m venv .venv && source .venv/bin/activate    # or .venv\Scripts\activate on Windows
pip install -e ".[dev,test]"
pre-commit install
```

Run the full test + lint cycle:

```bash
pytest                # tests + coverage
ruff check bulwark tests examples
black --check bulwark tests examples
mypy bulwark
```

Tests must pass on Python 3.10, 3.11, and 3.12; CI enforces this.

## Style

* `black` formatting (line-length 100).
* `ruff` lint clean.
* `mypy --strict` clean for `bulwark/`. Tests are exempt from strict mode.
* Type hints **everywhere** in `bulwark/`. The `py.typed` marker promises
  this to downstream users.
* Docstrings on every public class and function. Use the
  [Google docstring style](https://google.github.io/styleguide/pyguide.html#383-functions-and-methods)
  for arg / return / raise sections.

## Testing requirements

* Every new feature needs a unit test. Aim for >90% coverage; CI fails the
  PR below this threshold.
* Edge cases worth thinking about explicitly: empty input, non-string
  input, oversized input, concurrent calls, malformed config.
* Security-sensitive changes (sanitizer, detector, RBAC, audit) need an
  attack scenario test in the relevant `test_*.py`.
* Don't mock the cipher. Use `generate_audit_key()` and run real
  encryption in the test — past projects shipped silent crypto bugs because
  the tests mocked Fernet.

## Pull request checklist

- [ ] Branch name is descriptive (`fix/sanitizer-bidi-edge-case`).
- [ ] Single logical change per PR. Split refactors from feature work.
- [ ] Tests added or updated.
- [ ] `pytest`, `ruff`, `black`, `mypy` all pass locally.
- [ ] [CHANGELOG.md](CHANGELOG.md) updated under the `Unreleased` section.
- [ ] Public API changes documented in [docs/API_REFERENCE.md](docs/API_REFERENCE.md).
- [ ] If touching compliance surfaces, update [docs/COMPLIANCE.md](docs/COMPLIANCE.md).
- [ ] PR description explains *why*, not just *what*.

## Versioning and release

We follow [Semantic Versioning](https://semver.org). Public API surfaces
are everything documented in
[docs/API_REFERENCE.md](docs/API_REFERENCE.md). Internal helpers
(prefixed `_`) may move between minor versions.

Releases are cut by maintainers via a tagged commit (`vX.Y.Z`); the
`publish.yml` workflow builds and publishes to PyPI via OIDC trusted
publishing.

## License

By submitting a contribution you agree to license it under the
[Apache 2.0 License](LICENSE) on the same terms as the rest of Bulwark.
You retain copyright on your contribution; you grant the project a
perpetual license to use, modify, and redistribute it.
