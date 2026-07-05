"""Every framework adapter is import-safe without its framework installed.

Importing any adapter module must never require the framework; using the
framework-bound classes without the framework must raise a clear ImportError
with an install hint. (Full behavior is verified against each real library in
CI/dev; these tests pin the import contract that protects strangers.)
"""

import importlib

import pytest

ADAPTERS = ["langchain", "llamaindex", "openai_agents", "crewai"]


@pytest.mark.parametrize("name", ADAPTERS)
def test_adapter_module_imports_without_framework(name):
    mod = importlib.import_module(f"mirra.adapters.{name}")
    assert mod is not None


def test_langchain_memory_raises_clean_without_lib(sdk_home, monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "t")
    try:
        import langchain_core  # noqa: F401
        pytest.skip("langchain installed")
    except Exception:
        pass
    from mirra.adapters.langchain import MirraChatMessageHistory
    with pytest.raises(ImportError) as e:
        MirraChatMessageHistory(principal="a", subject_id="x", home=str(sdk_home))
    assert "pip install" in str(e.value)


def test_llamaindex_raises_clean_without_lib(sdk_home, monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "t")
    try:
        import llama_index.core  # noqa: F401
        pytest.skip("llama-index installed")
    except Exception:
        pass
    from mirra.adapters.llamaindex import MirraLlamaIndexMemory
    with pytest.raises(ImportError) as e:
        MirraLlamaIndexMemory(principal="a", subject_id="x", home=str(sdk_home))
    assert "pip install" in str(e.value)


def test_openai_agents_raises_clean_without_lib(sdk_home, monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "t")
    try:
        import agents  # noqa: F401
        pytest.skip("openai-agents installed")
    except Exception:
        pass
    from mirra.adapters.openai_agents import MirraSession
    with pytest.raises(ImportError) as e:
        MirraSession(principal="a", subject_id="x", home=str(sdk_home))
    assert "pip install" in str(e.value)


def test_crewai_raises_clean_without_lib(sdk_home, monkeypatch):
    monkeypatch.setenv("QSEAL_SECRET", "t")
    try:
        import crewai  # noqa: F401
        pytest.skip("crewai installed")
    except Exception:
        pass
    from mirra.adapters.crewai import protect_tool
    with pytest.raises(ImportError) as e:
        protect_tool(lambda: None, principal="a", home=str(sdk_home))
    assert "pip install" in str(e.value)
