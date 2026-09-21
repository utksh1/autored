import aiosqlite
from pathlib import Path
from autored.logging import get_logger

log = get_logger("persistence.engagement_db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    start_ts TEXT NOT NULL,
    end_ts TEXT,
    summary TEXT,
    report_path TEXT,
    operator TEXT NOT NULL,
    phase TEXT NOT NULL,
    parent_engagement_id TEXT,
    FOREIGN KEY (parent_engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_engagements_target ON engagements(target);
CREATE INDEX IF NOT EXISTS idx_engagements_start_ts ON engagements(start_ts);
CREATE INDEX IF NOT EXISTS idx_engagements_parent ON engagements(parent_engagement_id);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER,
    service TEXT,
    cve TEXT,
    severity TEXT CHECK(severity IN ('critical','high','medium','low','info')),
    status TEXT CHECK(status IN ('open','confirmed','exploited','false_positive','remediated')),
    evidence_path TEXT,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    username TEXT NOT NULL,
    credential_type TEXT CHECK(credential_type IN ('password','ntlm_hash','kerberos_ticket','ssh_key','private_key','token','other')),
    credential_value TEXT,
    source TEXT,
    target_host TEXT,
    cracked INTEGER DEFAULT 0,
    cracked_value TEXT,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_creds_engagement ON credentials(engagement_id);
CREATE INDEX IF NOT EXISTS idx_creds_username ON credentials(username);

CREATE TABLE IF NOT EXISTS lessons (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    category TEXT CHECK(category IN ('technique_worked','cve_exploited','tool_issue','opsec_failure','misconfiguration','other')),
    body TEXT NOT NULL,
    mitre_technique_id TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_lessons_category ON lessons(category);
CREATE INDEX IF NOT EXISTS idx_lessons_mitre ON lessons(mitre_technique_id);
"""

async def init_db(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()
    log.info("engagement_db_initialized", db_path=db_path)

async def insert_engagement(db_path: str, engagement: dict) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            """INSERT OR REPLACE INTO engagements
               (id, target, start_ts, end_ts, summary, report_path, operator, phase, parent_engagement_id)
               VALUES (:id, :target, :start_ts, :end_ts, :summary, :report_path, :operator, :phase, :parent_engagement_id)""",
            engagement,
        )
        await db.commit()

async def insert_finding(db_path: str, finding: dict) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            """INSERT OR REPLACE INTO findings
               (id, engagement_id, host, port, service, cve, severity, status, evidence_path, discovered_at)
               VALUES (:id, :engagement_id, :host, :port, :service, :cve, :severity, :status, :evidence_path, :discovered_at)""",
            finding,
        )
        await db.commit()

async def insert_credential(db_path: str, credential: dict) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            """INSERT OR REPLACE INTO credentials
               (id, engagement_id, username, credential_type, credential_value, source, target_host, cracked, cracked_value, discovered_at)
               VALUES (:id, :engagement_id, :username, :credential_type, :credential_value, :source, :target_host, :cracked, :cracked_value, :discovered_at)""",
            credential,
        )
        await db.commit()

async def insert_lesson(db_path: str, lesson: dict) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            """INSERT OR REPLACE INTO lessons
               (id, engagement_id, category, body, mitre_technique_id, created_at)
               VALUES (:id, :engagement_id, :category, :body, :mitre_technique_id, :created_at)""",
            lesson,
        )
        await db.commit()

async def get_findings_by_cve(db_path: str, cve: str) -> list[dict]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM findings WHERE cve = ?", (cve,))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

async def get_findings_by_engagement(db_path: str, engagement_id: str) -> list[dict]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM findings WHERE engagement_id = ?", (engagement_id,))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

async def list_engagements_with_findings(db_path: str) -> list[dict]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM engagements ORDER BY start_ts DESC")
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

async def get_lessons_by_engagement(db_path: str, engagement_id: str) -> list[dict]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM lessons WHERE engagement_id = ?", (engagement_id,))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
