import uuid

from openverdict.models.api_keys import ApiKeyRepo, Role
from openverdict.services.jobs import JOB_STREAM, JobService


async def test_submit_and_get(api, client_key, analyst_key, valkey):
    h = {"X-API-Key": client_key}
    body = {"urls": ["http://a.test/", "http://b.test/", "bad"]}
    r = await api.post("/v1/jobs", headers=h, json=body)
    assert r.status_code == 202
    job = r.json()
    assert job["status"] == "queued" and job["total"] == 3
    assert r.headers["Location"] == f"/v1/jobs/{job['job_id']}"
    [(_, fields)] = await valkey.xrange(JOB_STREAM)
    assert fields == {"job_id": job["job_id"]}
    got = (await api.get(f"/v1/jobs/{job['job_id']}", headers=h)).json()
    assert got["progress"] == {"done": 0, "total": 3} and got["results"] == []
    as_analyst = await api.get(f"/v1/jobs/{job['job_id']}", headers={"X-API-Key": analyst_key})
    assert as_analyst.status_code == 200


async def test_visibility_and_validation(api, client_key, db):
    _, other = await ApiKeyRepo(db).create("other-app", Role.CLIENT)
    h = {"X-API-Key": client_key}
    r = await api.post("/v1/jobs", headers=h, json={"urls": ["http://a.test/"]})
    job_id = r.json()["job_id"]
    assert (await api.get(f"/v1/jobs/{job_id}", headers={"X-API-Key": other})).status_code == 404
    assert (await api.get(f"/v1/jobs/{uuid.uuid4()}", headers=h)).status_code == 404
    assert (await api.get("/v1/jobs/not-a-uuid", headers=h)).status_code == 422
    assert (await api.get(f"/v1/jobs/{job_id}?limit=1001", headers=h)).status_code == 422
    too_many = {"urls": ["http://a.test/"] * 10_001}
    assert (await api.post("/v1/jobs", headers=h, json=too_many)).status_code == 422


async def test_enqueue_failure_still_accepted(api, client_key, monkeypatch):
    async def broken(self, job_id):
        raise ConnectionError("valkey down")

    monkeypatch.setattr(JobService, "enqueue", broken)
    h = {"X-API-Key": client_key}
    r = await api.post("/v1/jobs", headers=h, json={"urls": ["http://a.test/"]})
    assert r.status_code == 202
