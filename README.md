# TDX Quote Verify

## CLI

Offline verification:

```bash
python3 verify_tdx_quote.py examples/quote.json
```

Quote dump only:

```bash
python3 verify_tdx_quote.py examples/quote.json --dump-quote --dump-only
```

Online Intel verification (requires API key):

```bash
python3 verify_tdx_quote.py examples/quote.json --online-only --intel-api-key "<KEY>"
```

## Web UI

Start local web server:

```bash
python3 web_ui.py --host 127.0.0.1 --port 8080
```

Then open:

- http://127.0.0.1:8080

Web UI features:

- Paste quote JSON or raw quote hex
- Offline checks with per-check evidence
- Optional Intel online verification
- Expandable quote dump (YAML-like object tree)
- Cross-linking between checks and dump paths (click a check/reference to highlight dump fields)
