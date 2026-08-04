import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text())


def test_build_backend_is_pinned_exactly():
    # The build backend is not in uv.lock (uv locks runtime dependencies, not
    # build-time ones) and it *runs* during every install, editable included. A
    # floating requirement makes "uv sync installs the exact locked versions"
    # untrue of the one package that executes code while installing.
    requires = _pyproject()["build-system"]["requires"]
    assert requires, "build-system.requires must not be empty"
    for requirement in requires:
        assert "==" in requirement, f"{requirement!r} is not pinned to an exact version"


def test_sdist_include_is_an_anchored_allowlist():
    # Allowlist, not exclusions, so tests/, sample-emails/ and any local .env
    # cannot reach a source distribution; anchored, or a bare "README.md" also
    # matches sample-emails/README.md.
    include = _pyproject()["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    assert include
    for pattern in include:
        assert pattern.startswith("/"), f"{pattern!r} is unanchored and matches by basename"


def test_public_samples_use_no_routable_third_party_addresses():
    # The samples are published, and one that names an address as a phishing
    # origin attributes criminal activity to whoever holds it. Fabricated
    # addresses must come from an IANA special-purpose range that is still
    # `is_global` (the origin-IP path filters anything is_global rejects, which
    # is why RFC 5737 documentation ranges cannot be used here).
    import ipaddress
    import re

    ALLOWED = (
        ipaddress.ip_network("192.88.99.0/24"),  # RFC 7526, deprecated 6to4 anycast
        ipaddress.ip_network("233.252.0.0/24"),  # RFC 5771, MCAST-TEST-NET
    )
    # Accurate addresses of the real senders the benign samples imitate. These
    # are attributions of legitimate infrastructure to its actual owner, which is
    # the point of those samples looking genuine.
    REAL_BENIGN_RELAYS = {"192.30.252.198", "209.85.128.182", "198.2.185.120"}
    root = PYPROJECT.parent
    found = False
    for path in sorted((root / "sample-emails").glob("*")) + sorted(
        (root / "tests" / "samples").glob("*")
    ):
        if path.is_dir():
            continue
        for literal in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", path.read_text(errors="replace")):
            try:
                addr = ipaddress.ip_address(literal)
            except ValueError:
                continue
            if not addr.is_global or literal in REAL_BENIGN_RELAYS:
                continue
            found = True
            assert any(addr in net for net in ALLOWED), f"{path.name}: {literal} is routable"
    assert found, "no globally routable sample address found — did the corpus move?"
