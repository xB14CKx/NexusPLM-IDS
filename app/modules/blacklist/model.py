from pydantic import BaseModel


class BlacklistResponse(BaseModel):
    ip: str
    action: str  # added | removed


class BlacklistListResponse(BaseModel):
    ips: list[str]
    total: int
