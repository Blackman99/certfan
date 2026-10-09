# Contributing

Thanks for helping! Read [GOAL.md](GOAL.md) first: every change must make "does every node serve the right certificate?" more accurate or easier to answer.

## Dev setup

```bash
git clone https://github.com/Blackman99/certfan && cd certfan
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
certfan demo
```

No runtime dependencies are allowed (stdlib only). `pytest` is the only required dev dependency.

## Pull requests

- Keep PRs focused; include tests.
- `pytest -q` and `ruff check src tests --select F,E9` must pass.
- Do not add runtime deps. Tests must not need the network: use the local TLS servers in `certfan.demo`.
- Changes to JSON/Prometheus output need a CHANGELOG entry.
