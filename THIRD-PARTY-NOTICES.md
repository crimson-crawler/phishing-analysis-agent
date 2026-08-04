# Third-party notices

`phish-check` is licensed under the Apache License 2.0 (see [LICENSE](LICENSE) and
[NOTICE](NOTICE)). It **bundles no third-party source code** — the packages below are
resolved from PyPI at install time and each remains under its own license.

Every license listed here is compatible with an Apache-2.0 distribution. This is
checked deliberately: a copyleft runtime dependency would make the Apache-2.0 claim
in `LICENSE` incorrect, which is why the plain-text URL fallback is implemented in
`phish_check/defang.py` (`refang()`) rather than taken from a GPL library.

Licenses are recorded as each package declares them in its own distribution metadata.
Regenerate this list whenever `uv.lock` changes. `uv.lock` is the authoritative
package set — the installed set is platform-specific, so packages gated behind a
marker (`colorama`, `sys_platform == 'win32'`) never appear on a Linux or macOS
host and would silently go unlisted. Take the names from the lockfile, then read
licenses from the installed set:

```bash
# Authoritative package list, all platforms:
grep -A1 '^\[\[package\]\]' uv.lock | grep '^name = ' | cut -d'"' -f2 | sort

# Declared licenses (installed set only — cross-check against the list above):
uv run python -c "
import importlib.metadata as md
for d in sorted(md.distributions(), key=lambda d: (d.metadata['Name'] or '').lower()):
    n = d.metadata['Name']
    if n and n != 'phish-check':
        print(n, d.version, d.metadata.get('License-Expression') or d.metadata.get('License'))
"
```

## Direct runtime dependencies

| Package | License |
|---|---|
| beautifulsoup4 | MIT |
| httpx | BSD-3-Clause |
| openai | Apache-2.0 |
| python-dotenv | BSD-3-Clause |
| rich | MIT |
| tldextract | BSD-3-Clause |

## Transitive runtime dependencies

| Package | License |
|---|---|
| annotated-types | MIT |
| anyio | MIT |
| certifi | MPL-2.0 |
| charset-normalizer | MIT |
| colorama | BSD-3-Clause (Windows only — `tqdm` dependency) |
| distro | Apache-2.0 |
| filelock | MIT |
| h11 | MIT |
| httpcore | BSD-3-Clause |
| idna | BSD-3-Clause |
| jiter | MIT |
| markdown-it-py | MIT |
| mdurl | MIT |
| pydantic | MIT |
| pydantic-core | MIT |
| Pygments | BSD-2-Clause |
| requests | Apache-2.0 |
| requests-file | Apache-2.0 |
| sniffio | MIT OR Apache-2.0 |
| soupsieve | MIT |
| tqdm | MPL-2.0 AND MIT |
| typing-extensions | PSF-2.0 |
| typing-inspection | MIT |
| urllib3 | MIT |

## Development-only dependencies

Not installed by `pip install .`; present in the `dev` dependency group.

| Package | License |
|---|---|
| iniconfig | MIT |
| packaging | Apache-2.0 OR BSD-2-Clause |
| pluggy | MIT |
| pytest | MIT |
| ruff | MIT |

## Bundled data

`tldextract` ships a snapshot of the [Public Suffix List](https://publicsuffix.org/)
(Mozilla Public License 2.0). `phish-check` constructs it with `suffix_list_urls=()`
so that snapshot is used offline and never fetched at runtime.

## Brand assets

The files under `assets/` are Def-Logix trademarks and are **not** covered by the
Apache License — see [NOTICE](NOTICE).
