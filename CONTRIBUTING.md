# Contributing

Thanks for your interest in improving sectools.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Checks (must pass before a PR)

```bash
ruff check .          # lint
ruff format --check . # formatting
mypy src              # types
pytest                # tests
```

CI runs the same checks on Python 3.10–3.13.

## Adding a new tool

Each tool is a self-contained module in `src/sectools/tools/` that exposes four names:

```python
NAME = "mytool"
HELP = "one-line description shown in --help"


def add_arguments(parser: argparse.ArgumentParser) -> None: ...
def run(args: argparse.Namespace) -> Finding: ...
```

Then register it by adding it to `TOOLS` in `src/sectools/tools/__init__.py`.
Put reusable logic (integrity checks, evidence writing, Markdown) in
`src/sectools/core/` so tools stay thin and consistent. Add tests under `tests/`,
with any sample inputs in `tests/fixtures/`. Keep network and subprocess calls in
small, mockable functions so the parsing logic can be tested offline.

## Guidelines

- The core must stay dependency-free (standard library only). Heavier needs go
  into an optional extra in `pyproject.toml`.
- Tools that touch a remote target must keep the "authorized testing only"
  framing and default to passive behaviour.
- Prefer clear, commented code over clever one-liners.
