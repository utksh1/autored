"""AutoRed certipy tool wrapper — Phase 4, Task 5.

``certipy`` is the canonical AD-CS (Active Directory Certificate Services)
enumeration + abuse tool. Its ``find`` subcommand pulls every CA / template
on the target forest, evaluates each one against the ESC1-ESC15 misconfig
matrix, and prints a JSON report of vulnerable templates. Its ``auth``
subcommand turns a forged-cert NTLM chain into a usable TGT / PRT.

Per the T5 brief, this wrapper does NOT actually execute certipy in
Phase 4. It constructs the certipy command string (``find`` action by
default, with ``-u <user>@<domain>`` UPN auth, ``-p <password>``, and
``-dc-ip <target>`` to direct the LDAP bind at a specific DC) and
persists it via ``_save_raw`` so the Phase 6 FootholdSessionManager can
replay it. The returned ``CertipyResult`` has an empty
``vulnerable_templates`` list. The ``_build_certipy_cmd`` helper is
exported so a Phase 6 caller can reuse the exact argv shape.

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER — see
``autored.tools.hydra`` for the rationale and the regression test in
``test_certipy_ainvoke_works_with_roe_guard``.

Spec ref: §3.4 (post-ex models), §6.8 (RoE guard), §9.2 (RoE categories).
"""
from __future__ import annotations

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.certipy")


class CertipyResult(BaseModel):
    """Parsed AD-CS findings from a certipy run.

    Phase 4 callers receive this with ``vulnerable_templates`` empty —
    real execution is deferred to Phase 6. Phase 6 callers will receive
    this populated by walking the certipy JSON output (each entry has
    a ``template_name`` + ``vulnerability_class`` like ``ESC1`` / ``ESC8``).
    """

    action: str
    target: str
    domain: str = ""
    username: str = ""
    vulnerable_templates: list[str] = Field(default_factory=list)
    raw_output_path: str = ""
    duration_sec: float = 0.0


def _build_certipy_cmd(
    action: str,
    username: str,
    password: str,
    domain: str,
    target: str,
) -> list[str]:
    """Build the certipy argv list.

    Flags:
      ``<action>``     — certipy subcommand (``find``, ``auth``, ``req``,
                          ``forge`` etc.). The T5 brief specifies the
                          ``find`` action.
      ``-u <user>@<dom>`` — AD credentials in UPN form. certipy parses
                            the part after ``@`` as the target domain
                            (overrides ``-domain`` if both are given).
      ``-p <password>``  — bind password. For Kerberos auth or PFX-cert
                            auth, swap this for ``-k`` or ``-pfx``.
      ``-dc-ip <target>`` — DC IP to bind LDAP against (matters in
                            multi-DC forests where the DNS A record for
                            the domain does not point at the PDC).

    Never returns a shell string — the caller passes this directly to
    ``asyncio.create_subprocess_exec`` (no shell, no interpolation) when
    certipy is eventually run on the operator's machine in Phase 6.
    """
    return [
        "certipy",
        action,
        "-u",
        f"{username}@{domain}",
        "-p",
        password,
        "-dc-ip",
        target,
    ]


@tool
@roe_guard(allowed_categories=["read_only"])
async def certipy(
    action: str,
    username: str,
    password: str,
    domain: str,
    target: str,
    engagement_id: str = "",
) -> CertipyResult:
    """Run certipy against an AD-CS target.

    The command is constructed for execution via the foothold's shell
    session (or directly on the operator's machine — Phase 6 will pick
    one). For now, this tool builds the command and saves it to
    ``engagements/<id>/raw/`` so the Phase 6 FootholdSessionManager can
    replay it; the returned ``CertipyResult`` has an empty
    ``vulnerable_templates`` list because no real certipy stdout was
    produced.

    Args:
        action: certipy subcommand (typically ``find`` for ESC1-15
            enumeration).
        username: AD username to bind with (e.g., ``svc_scan``).
        password: AD password for the bind account.
        domain: Domain FQDN (e.g., ``CORP.LOCAL``) — combined with
            ``username`` to form the UPN ``<user>@<domain>``.
        target: DC IP (passed via ``-dc-ip``). Used by the RoE guard
            scope check via the ``target`` kwarg path.
        engagement_id: Current engagement ID for raw output storage +
            RoE registry lookup.

    Returns:
        ``CertipyResult`` with ``raw_output_path`` set (command was
        saved) and ``vulnerable_templates`` empty (Phase 4 stub). Phase 6
        callers will receive a populated result.
    """
    cmd = _build_certipy_cmd(action, username, password, domain, target)
    cmd_str = " ".join(cmd)
    log.info(
        "certipy_start",
        action=action,
        domain=domain,
        target=target,
        username=username,
        # NOTE: never log the password — even at DEBUG. The brief's
        # parser is the only thing that needs to know it.
    )

    raw_path = await _save_raw(
        "certipy_cmd", target, cmd_str, "", engagement_id
    )

    log.info(
        "certipy_done",
        action=action,
        domain=domain,
        target=target,
        note="command saved, execution deferred to Phase 6",
    )
    return CertipyResult(
        action=action,
        target=target,
        domain=domain,
        username=username,
        raw_output_path=raw_path,
    )
