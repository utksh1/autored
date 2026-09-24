"""Unit tests for the Chroma vector store (cross-engagement similarity)."""
import pytest
from autored.persistence.chroma_store import ChromaStore


@pytest.fixture
def store(tmp_path):
    return ChromaStore(path=str(tmp_path / "chroma"))


def test_store_initializes(store):
    assert store.client is not None
    assert store.findings_collection is not None
    assert store.techniques_collection is not None


def test_upsert_and_query_finding(store):
    store.upsert_finding_sync(
        finding_id="finding-001",
        text="CVE-2014-6271 Shellshock on Apache httpd 2.2.22",
        metadata={"cve": "CVE-2014-6271", "host": "10.10.10.56"},
    )
    results = store.query_similar_findings_sync(
        text="Shellshock vulnerability in Apache",
        top_k=5,
    )
    assert len(results) >= 1
    assert any(r["metadata"].get("cve") == "CVE-2014-6271" for r in results)


def test_upsert_and_query_technique(store):
    store.upsert_technique_sync(
        technique_id="T1059.004",
        text="Unix Shell exploit via environment variable injection",
        metadata={"mitre_id": "T1059.004"},
    )
    results = store.query_similar_techniques_sync(
        text="shell command execution via env vars",
        top_k=5,
    )
    assert len(results) >= 1


def test_query_empty_store_returns_empty(store):
    results = store.query_similar_findings_sync(text="anything", top_k=5)
    assert results == []


def test_query_with_filter(store):
    store.upsert_finding_sync("f1", "nginx vulnerability", {"service": "nginx"})
    store.upsert_finding_sync("f2", "apache vulnerability", {"service": "apache"})
    results = store.query_similar_findings_sync(
        text="web server vuln",
        top_k=5,
        where={"service": "nginx"},
    )
    assert all(r["metadata"]["service"] == "nginx" for r in results)
