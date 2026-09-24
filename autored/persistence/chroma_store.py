"""Chroma vector store for cross-engagement finding/technique similarity search.

Provides two collections, both using cosine similarity:

* ``finding_embeddings`` — past findings, keyed by ``finding_id``.
* ``technique_patterns`` — MITRE ATT&CK technique text patterns, keyed by
  ``technique_id``.

Chroma's PersistentClient API is synchronous, so each async method delegates
to a sync method via ``asyncio.to_thread`` to avoid blocking the event loop.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import chromadb

from autored.logging import get_logger

log = get_logger("persistence.chroma")


class ChromaStore:
    """Chroma vector store for cross-engagement finding/technique similarity search."""

    def __init__(self, path: str = "db/chroma"):
        Path(path).mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=path)
        self.findings_collection = self.client.get_or_create_collection(
            name="finding_embeddings",
            metadata={"hnsw:space": "cosine"},
        )
        self.techniques_collection = self.client.get_or_create_collection(
            name="technique_patterns",
            metadata={"hnsw:space": "cosine"},
        )
        log.info("chroma_initialized", path=path)

    # Synchronous methods (Chroma's API is sync) — wrapped for use from async code

    def upsert_finding_sync(self, finding_id: str, text: str, metadata: dict) -> None:
        self.findings_collection.upsert(
            ids=[finding_id],
            documents=[text],
            metadatas=[metadata],
        )

    def query_similar_findings_sync(
        self, text: str, top_k: int = 5, where: dict | None = None,
    ) -> list[dict]:
        if self.findings_collection.count() == 0:
            return []
        kwargs = {"query_texts": [text], "n_results": top_k}
        if where:
            kwargs["where"] = where
        results = self.findings_collection.query(**kwargs)
        if not results["ids"] or not results["ids"][0]:
            return []
        return [
            {"id": id_, "document": doc, "metadata": meta, "distance": dist}
            for id_, doc, meta, dist in zip(
                results["ids"][0],
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0],
            )
        ]

    def upsert_technique_sync(self, technique_id: str, text: str, metadata: dict) -> None:
        self.techniques_collection.upsert(
            ids=[technique_id],
            documents=[text],
            metadatas=[metadata],
        )

    def query_similar_techniques_sync(
        self, text: str, top_k: int = 5, where: dict | None = None,
    ) -> list[dict]:
        if self.techniques_collection.count() == 0:
            return []
        kwargs = {"query_texts": [text], "n_results": top_k}
        if where:
            kwargs["where"] = where
        results = self.techniques_collection.query(**kwargs)
        if not results["ids"] or not results["ids"][0]:
            return []
        return [
            {"id": id_, "document": doc, "metadata": meta, "distance": dist}
            for id_, doc, meta, dist in zip(
                results["ids"][0],
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0],
            )
        ]

    # Async wrappers (run sync methods in thread pool)

    async def upsert_finding(self, finding_id: str, text: str, metadata: dict) -> None:
        await asyncio.to_thread(self.upsert_finding_sync, finding_id, text, metadata)

    async def query_similar_findings(
        self, text: str, top_k: int = 5, where: dict | None = None,
    ) -> list[dict]:
        return await asyncio.to_thread(self.query_similar_findings_sync, text, top_k, where)

    async def upsert_technique(self, technique_id: str, text: str, metadata: dict) -> None:
        await asyncio.to_thread(self.upsert_technique_sync, technique_id, text, metadata)

    async def query_similar_techniques(
        self, text: str, top_k: int = 5, where: dict | None = None,
    ) -> list[dict]:
        return await asyncio.to_thread(self.query_similar_techniques_sync, text, top_k, where)
