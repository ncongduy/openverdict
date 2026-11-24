"""Job request and response schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from openverdict.views.url_checks import UrlResultView

JOB_MAX_URLS = 10_000


class JobCreateRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=JOB_MAX_URLS)


class JobCreatedView(BaseModel):
    job_id: uuid.UUID
    status: str
    total: int


class ProgressView(BaseModel):
    done: int
    total: int


class JobView(BaseModel):
    job_id: uuid.UUID
    status: str
    progress: ProgressView
    created_at: datetime
    finished_at: datetime | None
    error: str | None
    offset: int
    limit: int
    results: list[UrlResultView]
