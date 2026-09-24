"""Neo4j store for BloodHound data (Phase 4 T2 — spec §3.4 / §9.2).

Wraps a Neo4j 5.25 community container running via docker-compose so the
post-ex phase can import BloodHound JSON output and (in Phase 5) query
shortest attack paths between identities.

All shell-out calls use ``subprocess.run`` synchronously — unit tests mock
``subprocess.run`` directly so no Docker daemon is required to exercise
this module. The async signatures are preserved so callers can ``await``
without needing a thread wrapper (and so future Phase 5 work can swap in
the async ``neo4j`` Python driver without touching call sites).
"""
from __future__ import annotations

import subprocess

from autored.logging import get_logger

log = get_logger("persistence.neo4j")

COMPOSE_FILE = "docker-compose.neo4j.yml"
NEO4J_CONTAINER = "neo4j-neo4j-1"


class Neo4jStore:
    """Manages a Neo4j container for BloodHound data storage.

    Start/stop via docker-compose. Upload BloodHound JSON data via
    the ``neo4j-admin`` import tool. Query via Cypher (stubbed here —
    real Cypher implementation lands in Phase 5 per the T2 brief).
    """

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "autored_local_dev",
    ):
        self.uri = uri
        self.user = user
        self.password = password

    async def start(self) -> None:
        """Start Neo4j via ``docker compose up -d``.

        Raises ``RuntimeError`` if the compose command exits non-zero
        (e.g., docker daemon not running, port already bound).
        """
        log.info("neo4j_start")
        result = subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "up", "-d"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            log.error("neo4j_start_failed", stderr=result.stderr)
            raise RuntimeError(f"Failed to start Neo4j: {result.stderr}")
        log.info("neo4j_started")

    async def stop(self) -> None:
        """Stop Neo4j via ``docker compose down``.

        Best-effort — failures are logged but not raised so cleanup paths
        can call this from a ``finally:`` block without masking the
        original exception.
        """
        log.info("neo4j_stop")
        result = subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "down"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            log.warning("neo4j_stop_failed", stderr=result.stderr)

    async def is_running(self) -> bool:
        """Check if the Neo4j container is up.

        Filters ``docker ps`` by name and inspects the ``{{.Names}}``
        column — if ``neo4j`` appears in stdout, the container is
        considered running.
        """
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=neo4j", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
        )
        return "neo4j" in result.stdout

    async def upload_bloodhound_data(self, json_path: str) -> bool:
        """Upload BloodHound JSON data to Neo4j.

        Shells out to ``neo4j-admin database import full`` inside the
        running container. Returns ``True`` on success, ``False`` if
        the import command exits non-zero (e.g., malformed JSON, DB
        already populated and ``--overwrite-destination`` not honoured).
        """
        log.info("neo4j_upload_bloodhound", path=json_path)
        cmd = [
            "docker", "exec", NEO4J_CONTAINER,
            "neo4j-admin", "database", "import", "full",
            "--nodes", json_path,
            "--overwrite-destination", "neo4j",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            log.error("neo4j_upload_failed", stderr=result.stderr, path=json_path)
            return False
        log.info("neo4j_upload_done", path=json_path)
        return True

    async def query_shortest_path(self, source: str, target: str) -> list[dict]:
        """Query shortest attack path from ``source`` to ``target`` (DA path).

        STUB — returns ``[]`` unconditionally. Real Cypher implementation
        (``MATCH p = shortestPath(...)`` via the ``neo4j`` Python driver)
        is deferred to Phase 5 per the T2 brief.
        """
        log.info("neo4j_query_path", source=source, target=target)
        return []
