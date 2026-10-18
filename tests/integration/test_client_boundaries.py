import asyncio

import anyio

from mcp_hub.gateway import RequestContext


async def test_mcp_delegation_does_not_include_admin_configuration_rights(harness):
    token = (
        await harness.hub.oauth._issue(harness.principal, "external-client", management=False)
    )["access_token"]
    headers = {"Authorization": "Bearer " + token}
    assert (await harness.client.get("/admin/api/whoami", headers=headers)).status_code == 200
    for endpoint in (
        "/admin/api/users",
        "/admin/api/access",
        "/admin/api/groups",
        "/admin/api/servers-dynamic",
        "/admin/api/audit",
    ):
        assert (await harness.client.get(endpoint, headers=headers)).status_code == 403
    assert (await harness.rpc("tools/list", headers=headers)).status_code == 200


async def test_public_client_cannot_self_enable_management(harness):
    response = await harness.client.post(
        "/oauth/register",
        json={"redirect_uris": ["http://localhost/callback"], "management_allowed": True},
    )
    assert response.status_code == 400


async def test_management_service_client_still_needs_a_role(harness):
    response = await harness.client.post(
        "/admin/api/clients",
        headers=harness.headers,
        json={"client_name": "management-ci", "management_allowed": True},
    )
    client = response.json()
    token = (
        await harness.client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client["client_id"],
                "client_secret": client["client_secret"],
            },
        )
    ).json()["access_token"]
    headers = {"Authorization": "Bearer " + token}
    assert (await harness.client.get("/admin/api/users", headers=headers)).status_code == 403
    await harness.hub.redis.sadd(harness.hub.store.key("acl:admins"), "bot_" + client["client_id"])
    assert (await harness.client.get("/admin/api/users", headers=headers)).status_code == 200


async def test_anyio_level_cancellation_finishes_audit_and_releases_request_tracking(harness):
    entered, finished = asyncio.Event(), asyncio.Event()
    holder = {}

    class Blocking:
        alive = True

        async def call(self, *args):
            entered.set()
            await asyncio.Event().wait()

        async def close(self):
            pass

    harness.hub.upstreams.sessions["alpha"] = Blocking()

    async def worker():
        with anyio.CancelScope() as scope:
            holder["scope"] = scope
            holder["result"] = await harness.hub.gateway.call(
                "alpha.lookup", {"query": "x"}, RequestContext(harness.principal)
            )
        finished.set()

    async with anyio.create_task_group() as group:
        group.start_soon(worker)
        await entered.wait()
        holder["scope"].cancel()
        await asyncio.wait_for(finished.wait(), timeout=5)
    assert holder["result"]["isError"]
    assert not harness.hub.gateway.tasks
    assert await harness.hub.redis.llen(harness.hub.store.key("audit:spool")) == 1
