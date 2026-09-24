"""Cross-engagement memory writer — the Phase 6 write side (spec §13.6).

The read side has existed since Phase 2 (the Vuln Agent queries Chroma for
similar past findings); until now nothing wrote to it. This module runs at
report time and persists the engagement into:

* SQLite ``db/engagements.sqlite`` — engagements / findings / credentials /
  lessons rows (schema already shipped in engagement_db.py);
* Chroma ``db/chroma`` — finding embeddings + technique patterns.

Secret material is **hashed** before it touches the DB (spec §3.3:
"credential_value TEXT -- hashed/encrypted form, never plaintext
passwords in DB") and never enters Chroma at all. SQLite and Chroma are
isolated failure domains: one failing never blocks the other and never
raises to the Report Agent.
"""
import hashlib
from datetime import datetime

from pydantic import BaseModel

from autored.logging import get_logger
from autored.persistence.engagement_db import (
    init_db,
    insert_credential,
    insert_engagement,
    insert_finding,
    insert_lesson,
)
from autored.persistence.chroma_store import ChromaStore

log = get_logger("reporting.memory_writer")

_SECRET_TYPE_TO_CRED_TYPE = {
    "password": "password",
    "hash": "ntlm_hash",
    "key": "ssh_key",
    "token": "token",
    "config": "other",
    "other": "other",
}


class MemoryWriteResult(BaseModel):
    db_path: str
    engagement_written: bool = False
    findings_written: int = 0
    credentials_written: int = 0
    lessons_written: int = 0
    chroma_findings_upserted: int = 0
    chroma_techniques_upserted: int = 0
    db_error: str | None = None
    chroma_error: str | None = None


def _iso(dt: datetime | None) -> str:
    return (dt or datetime.utcnow()).isoformat()


def _engagement_row(state) -> dict:
    return {
        "id": state.engagement_id,
        "target": ", ".join(state.target_scope),
        "start_ts": _iso(state.started_at),
        "end_ts": _iso(datetime.utcnow()),
        "summary": state.summary,
        "report_path": (
            state.report_paths.markdown_path if state.report_paths else None
        ),
        "operator": state.operator,
        "phase": state.phase,
        "parent_engagement_id": state.parent_engagement_id,
    }


def _finding_row(state, vuln) -> dict:
    foothold_hosts = {f.host_ip for f in state.footholds}
    status = "exploited" if vuln.host_ip in foothold_hosts else "open"
    return {
        "id": vuln.id,
        "engagement_id": state.engagement_id,
        "host": vuln.host_ip,
        "port": vuln.port,
        "service": vuln.service,
        "cve": vuln.cve,
        "severity": vuln.severity,
        "status": status,
        "evidence_path": vuln.evidence_path,
        "discovered_at": _iso(vuln.discovered_at),
    }


def _credential_rows(state) -> list[dict]:
    rows = []
    for secret in state.harvested_secrets:
        username = secret.source.rsplit("/", 1)[-1] if "/" in secret.source else ""
        rows.append({
            "id": secret.id,
            "engagement_id": state.engagement_id,
            "username": username,
            "credential_type": _SECRET_TYPE_TO_CRED_TYPE.get(secret.secret_type, "other"),
            # spec §3.3: hashed form only — never the plaintext value.
            "credential_value": hashlib.sha256(secret.secret_value.encode()).hexdigest(),
            "source": secret.source,
            "target_host": secret.host_ip,
            "cracked": 0,
            "cracked_value": None,
            "discovered_at": _iso(secret.discovered_at),
        })
    return rows


def _lesson_rows(state) -> list[dict]:
    return [
        {
            "id": lesson.id,
            "engagement_id": state.engagement_id,
            "category": lesson.category,
            "body": lesson.body,
            "mitre_technique_id": lesson.mitre_technique_id,
            "created_at": _iso(lesson.created_at),
        }
        for lesson in state.lessons
    ]


async def persist_engagement_memory(
    state,
    db_path: str = "db/engagements.sqlite",
    chroma: ChromaStore | None = None,
) -> MemoryWriteResult:
    """Persist the engagement into SQLite + Chroma. Never raises.

    Args:
        state: the final EngagementState (report node runs this last).
        db_path: cross-engagement SQLite path.
        chroma: optional ChromaStore instance (None skips vector writes —
            instantiating it here would double-open the store the Vuln
            Agent may already hold).

    Returns:
        MemoryWriteResult with per-store write counts and isolated errors.
    """
    result = MemoryWriteResult(db_path=db_path)

    # --- SQLite (isolated failure domain) -------------------------------- #
    try:
        await init_db(db_path)
        await insert_engagement(db_path, _engagement_row(state))
        result.engagement_written = True

        for vuln in state.vulnerabilities:
            await insert_finding(db_path, _finding_row(state, vuln))
            result.findings_written += 1

        for cred_row in _credential_rows(state):
            await insert_credential(db_path, cred_row)
            result.credentials_written += 1

        for lesson_row in _lesson_rows(state):
            await insert_lesson(db_path, lesson_row)
            result.lessons_written += 1
    except Exception as e:  # noqa: BLE001 — memory must never break the report
        result.db_error = str(e)
        log.warning("memory_sqlite_failed", engagement_id=state.engagement_id, error=str(e))

    # --- Chroma (isolated failure domain) -------------------------------- #
    if chroma is not None:
        try:
            for vuln in state.vulnerabilities:
                await chroma.upsert_finding(
                    vuln.id,
                    f"CVE {vuln.cve or 'n/a'} {vuln.severity} {vuln.title} on {vuln.host_ip}",
                    {
                        "engagement_id": state.engagement_id,
                        "cve": vuln.cve or "",
                        "severity": vuln.severity,
                        "host": vuln.host_ip,
                    },
                )
                result.chroma_findings_upserted += 1

            technique_docs: list[tuple[str, str, dict]] = []
            for mapping in state.mitre_mappings:
                technique_docs.append((
                    f"{state.engagement_id}:{mapping.technique_id}:{mapping.source}",
                    f"Technique {mapping.technique_id} {mapping.technique_name} "
                    f"via {mapping.detail}",
                    {"engagement_id": state.engagement_id,
                     "technique_id": mapping.technique_id, "tactic": mapping.tactic},
                ))
            for foothold in state.footholds:
                technique_docs.append((
                    f"{state.engagement_id}:foothold:{foothold.id}",
                    f"Foothold via {foothold.method} as {foothold.username} "
                    f"on {foothold.host_ip}",
                    {"engagement_id": state.engagement_id, "method": foothold.method},
                ))
            for pivot in state.pivots:
                if pivot.success:
                    technique_docs.append((
                        f"{state.engagement_id}:pivot:{pivot.id}",
                        f"Pivot via {pivot.method} to {pivot.target_host}",
                        {"engagement_id": state.engagement_id, "method": pivot.method},
                    ))
            for doc_id, doc, metadata in technique_docs:
                await chroma.upsert_technique(doc_id, doc, metadata)
                result.chroma_techniques_upserted += 1
        except Exception as e:  # noqa: BLE001
            result.chroma_error = str(e)
            log.warning("memory_chroma_failed", engagement_id=state.engagement_id, error=str(e))

    log.info(
        "memory_written",
        engagement_id=state.engagement_id,
        findings=result.findings_written,
        credentials=result.credentials_written,
        lessons=result.lessons_written,
        chroma_findings=result.chroma_findings_upserted,
        chroma_techniques=result.chroma_techniques_upserted,
    )
    return result
