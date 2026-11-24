"""Async URL-check jobs."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from openverdict.controllers.deps import get_resources, require
from openverdict.models.api_keys import Principal, Role
from openverdict.models.jobs import JobStatus
from openverdict.resources import Resources
from openverdict.views.jobs import JobCreatedView, JobCreateRequest, JobView, ProgressView
from openverdict.views.url_checks import UrlResultView

router = APIRouter(prefix="/v1", tags=["jobs"])
Caller = Annotated[Principal, Depends(require(Role.CLIENT, Role.ANALYST))]
Res = Annotated[Resources, Depends(get_resources)]


@router.post("/jobs", status_code=202)
async def submit_job(
    body: JobCreateRequest, caller: Caller, resources: Res, response: Response
) -> JobCreatedView:
    job = await resources.jobs.submit(caller, body.urls)
    response.headers["Location"] = f"/v1/jobs/{job.id}"
    return JobCreatedView(job_id=job.id, status=job.status.value, total=job.total)


@router.get("/jobs/{job_id}")
async def get_job(
    job_id: uuid.UUID,
    caller: Caller,
    resources: Res,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> JobView:
    job = await resources.jobs.visible_job(job_id, caller)
    if job is None:
        raise HTTPException(status_code=404, detail="not_found")
    results = []
    if job.status is JobStatus.DONE:
        rows = await resources.job_repo.results(job.id, offset, limit)
        results = [UrlResultView.model_validate(r) for r in rows]
    return JobView(
        job_id=job.id,
        status=job.status.value,
        progress=ProgressView(done=job.done, total=job.total),
        created_at=job.created_at,
        finished_at=job.finished_at,
        error=job.error,
        offset=offset,
        limit=limit,
        results=results,
    )
