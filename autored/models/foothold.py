from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal

class Foothold(BaseModel):
    """A successfully exploited access point on a target host.

    Recorded when the Exploit Agent verifies that an exploit produced
    actionable access (shell, webshell, RPC session, etc.).
    """
    id: str
    host_ip: str
    username: str
    context: Literal["user", "root", "system", "service_account"]
    method: str  # "ms17_010", "sqli", "ssh_brute", etc.
    access_type: Literal["shell", "webshell", "rpc", "ssh", "winrm"]
    evidence_path: str
    established_at: datetime
    hypothesis_rank: int  # which hypothesis worked
