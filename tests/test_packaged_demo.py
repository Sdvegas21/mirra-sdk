"""The installable demo (`mirra-demo`) proves all pillars and reports honestly."""

import pytest

from mirra import demo as packaged_demo


def test_mirra_demo_passes_end_to_end(sdk_home, monkeypatch, capsys):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-packaged-demo")
    exit_code = packaged_demo.main(["--home", str(sdk_home), "--reset"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "RESULT: 7/7 PASS" in out
    assert "UNTRUSTED_TO_CRITICAL_SINK" in out
    # The Ed25519 claim must be asserted by the check itself, not narrated.
    assert "Ed25519 witness verified against its embedded public key" in out
    # The recognition gate must render the three-part scenario a stranger reads:
    # known allowed / stranger refused for the stated reason / stranger earns it.
    assert "stranger REFUSED (CONTINUITY_NOT_ESTABLISHED)" in out
    assert "EARNED the allow after 3 verified sessions" in out


def test_mirra_demo_refuses_stale_components(sdk_home, monkeypatch, capsys):
    """Pre-hardening versions left in place by pip ('already satisfied') must
    cause a REFUSAL with upgrade guidance — never a passing report on old code."""
    real = packaged_demo._installed_version

    def stale(name, module):
        if name == "clawzero":
            return "0.3.0"
        return real(name, module)

    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-packaged-demo")
    monkeypatch.setattr(packaged_demo, "_installed_version", stale)
    exit_code = packaged_demo.main(["--home", str(sdk_home), "--reset"])
    out = capsys.readouterr().out
    assert exit_code == 1
    assert "STALE" in out
    assert "pip install --upgrade" in out
    assert "Checks did not run" in out
    assert "recognition" not in out  # no checks executed on stale code


def test_mirra_demo_recognizes_returning_session(sdk_home, monkeypatch, capsys):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-packaged-demo")
    assert packaged_demo.main(["--home", str(sdk_home), "--reset"]) == 0
    capsys.readouterr()
    assert packaged_demo.main(["--home", str(sdk_home)]) == 0
    out = capsys.readouterr().out
    assert "returning session" in out


def test_mirra_demo_fails_closed_without_memory_backend(sdk_home, monkeypatch, capsys):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-packaged-demo")

    import mirra.errors

    def broken(*args, **kwargs):
        raise mirra.errors.MemoryUnavailable("backend gone")

    monkeypatch.setattr("mirra.wrapper.default_memory", broken)
    exit_code = packaged_demo.main(["--home", str(sdk_home), "--reset"])
    out = capsys.readouterr().out
    assert exit_code == 1
    assert "pip install clawseal" in out
