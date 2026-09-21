from pydantic import BaseModel, Field


class WebApp(BaseModel):
    url: str
    host_ip: str
    port: int
    status_code: int
    title: str | None = None
    tech_stack: list[str] = Field(default_factory=list)
    web_server: str | None = None
    redirects: bool = False
    final_url: str | None = None
