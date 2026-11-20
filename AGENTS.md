# TrustedHand: agent instructions

Read `docs/DESIGN.md` first. It is the contract (rules, layers, tables, tool schemas, APIs, names).

- Python 3.13 for Lambdas, `uv` locally. Run tests with `uv run pytest -q`. Tests use `moto` (`aws` fixture in `tests/conftest.py`).
- AWS: personal account, always `--profile sarcastic-soul --region us-east-1`. Never export `AWS_PROFILE`. boto3 locally needs `botocore[crt]` (in the dev group).
- Shared code lives in `src/trustedhand/` and is copied into every Lambda zip. Lambda entry: `lambdas/<name>/handler.py`, function `handler`.
- Never log or return secrets: strip `Authorization` and `X-Amz-Security-Token` headers before logging, never log chat tokens or approval tokens, never return stack traces or ARNs to the model or the browser.
- Refusals from tools are normal JSON results with `status: "refused"` and a `rule` id from DESIGN.md.
- Plain English in docs and comments. Commit messages without AI attribution.
- Do not write `CLAUDE.md` files.
