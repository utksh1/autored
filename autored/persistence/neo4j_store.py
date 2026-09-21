"""Neo4j store for BloodHound data storage.

Manages a Neo4j container via ``docker compose`` (see ``docker-compose.neo4j.yml``
at the project root). All Docker interaction happens through
``asyncio.create_subprocess_exec`` so the store is fully async-friendly and easy
to unit-test by patching ``asyncio.create_subprocess_exec``.

The class exposes:

- ``start()`` — `docker compose -f docker-compose.neo4j.yml up -d`
- ``stop()`` — `docker compose -f docker-compose.neo4j.yml down`
- ``is_running()`` — `docker ps --filter name=neo4j`, checks output for "neo4j"
- ``upload_bloodhound_data(json_path)`` — runs ``neo4j-admin database import``
  inside the container
- ``query_shortest_path(source, target)`` — stub returning ``[]`` (Phase 5 will
  wire up the neo4j Python driver for real Cypher queries)
"""
from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

from autored.logging import get_logger

log = get_logger("persistence.neo4j")

COMPOSE_FILE = "docker-compose.neo4j.yml"
# Default container name as set by docker-compose (`container_name: neo4j`).
# Used for `docker exec` calls when uploading BloodHound data.
NEO4J_CONTAINER = "neo4j"


class Neo4jStore:
    """Manages a Neo4j container for BloodHound data storage.

    Start/stop via docker-compose. Upload BloodHound JSON data via the
    ``neo4j-admin`` import tool. Query via Cypher (Phase 5).
    """

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "autored_local_dev",
        compose_file: str = COMPOSE_FILE,
        container_name: str = NEO4J_CONTAINER,
    ):
        self.uri = uri
        self.user = user
        self.password = password
        self.compose_file = compose_file
        self.container_name = container_name

    async def _run(self, *cmd: str) -> tuple[int, bytes, bytes]:
        """Run a subprocess and return (returncode, stdout, stderr).

        Helper used by the docker-compose/docker-exec methods so the I/O
        boilerplate lives in one place.
        """
        log.debug("neo4j_run_cmd", cmd=list(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout, stderr

    async def start(self) -> None:
        """Start Neo4j via docker-compose.

        Raises ``RuntimeError`` if `docker compose up` returns non-zero.
        """
        log.info("neo4j_start")
        returncode, _stdout, stderr = await self._run(
            "docker", "compose", "-f", self.compose_file, "up", "-d",
        )
        if returncode != 0:
            log.error("neo4j_start_failed", stderr=stderr.decode(errors="replace"))
            raise RuntimeError(
                f"Failed to start Neo4j: {stderr.decode(errors='replace')}"
            )
        log.info("neo4j_started")

    async def stop(self) -> None:
        """Stop Neo4j via docker-compose.

        Best-effort: errors are logged but not raised (mirrors `docker compose down`
        semantics which is safe to call even if containers are already gone).
        """
        log.info("neo4j_stop")
        returncode, _stdout, stderr = await self._run(
            "docker", "compose", "-f", self.compose_file, "down",
        )
        if returncode != 0:
            log.warning(
                "neo4j_stop_nonzero", returncode=returncode,
                stderr=stderr.decode(errors="replace"),
            )
        else:
            log.info("neo4j_stopped")

    async def is_running(self) -> bool:
        """Check if the Neo4j container is running.

        Runs ``docker ps --filter name=neo4j --format {{.Names}}`` and returns
        True iff "neo4j" appears in the output.
        """
        returncode, stdout, _stderr = await self._run(
            "docker", "ps", "--filter", f"name={self.container_name}",
            "--format", "{{.Names}}",
        )
        if returncode != 0:
            # docker ps itself failed — treat as "not running".
            return False
        return self.container_name in stdout.decode(errors="replace")

    async def upload_bloodhound_data(self, json_path: str) -> bool:
        """Upload BloodHound JSON data to Neo4j.

        Runs ``neo4j-admin database import full --nodes <json_path>
        --overwrite-destination neo4j`` inside the running container via
        ``docker exec``. Returns True on success, False on failure.

        NOTE: BloodHound's JSON is multi-collection (users, groups, computers,
        sessions, etc.). Phase 5 will replace this with a proper BloodHound
        CE importer; for Phase 4 we wire up the import command so the data
        flow is exercised end-to-end.
        """
        path = Path(json_path)
        log.info("neo4j_upload_bloodhound", path=str(path))
        cmd = [
            "docker", "exec", self.container_name,
            "neo4j-admin", "database", "import", "full",
            "--nodes", str(path),
            "--overwrite-destination", "neo4j",
        ]
        returncode, stdout, stderr = await self._run(*cmd)
        if returncode != 0:
            log.error(
                "neo4j_upload_failed",
                returncode=returncode,
                stderr=stderr.decode(errors="replace"),
            )
            return False
        log.info("neo4j_upload_done", stdout=stdout.decode(errors="replace").strip())
        return True

    async def query_shortest_path(self, source: str, target: str) -> list[dict]:
        """Query shortest attack path from source to target (DA).

        Stub for Phase 4 — returns ``[]``. Phase 5 will wire this to the neo4j
        Python driver and run a Cypher shortestPath query against the
        BloodHound graph.
        """
        log.info("neo4j_query_path", source=source, target=target)
        return []


__all__ = ["Neo4jStore", "COMPOSE_FILE"]


# Kept for backwards-compat / direct callers that want sync semantics.
# Not used by the async store methods above; provided so that callers from
# non-async contexts (CLI, scripts) can issue a one-shot docker command.
def _sync_run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, check=False)
