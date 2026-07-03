"""The installable demo (`mirra-demo`) proves all pillars and reports honestly."""

import pytest

from mirra import demo as packaged_demo


def test_mirra_demo_passes_end_to_end(sdk_home, monkeypatch, capsys):
    monkeypatch.setenv("QSEAL_SECRET", "test-secret-for-packaged-demo")
    exit_code = packaged_demo.main(["--home", str(sdk_home), "--reset"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "RESULT: 5/5 PASS" in out
    assert "UNTRUSTED_TO_CRITICAL_SINK" in out


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
