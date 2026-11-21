from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, JsonValue, StringConstraints

from .schemas import Identifier


MAX_USER_PLUGINS = 100


class PluginDraft(BaseModel):
    description: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1200, pattern=r"^[^\x00]+$")]
    visibility: Literal["private", "public"] = "private"
    config: dict[str, JsonValue]


class UserPlugin(PluginDraft):
    id: Identifier
    author: str
    owned: bool
    updatedAt: datetime
