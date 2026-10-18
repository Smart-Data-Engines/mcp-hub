"""Actual deployment acceptance: run with make dev, then explicitly opt in.

Only resources created with a unique qa-* server name are changed or removed.
The Redis backup test uses a unique namespace, separate from the demo gateway.
"""

import asyncio
import json
import os
import secrets
import textwrap
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import docker
import httpx
import pytest
from cryptography.fernet import Fernet
from dotenv import dotenv_values
from redis.asyncio import Redis
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from mcp_hub.cli import export_state, import_state
from mcp_hub.config import Settings
from mcp_hub.oauth import challenge
from mcp_hub.runtime import container_name
from mcp_hub.security import Cipher
from mcp_hub.store import Store
from tests.integration.test_live_protocol import serving

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        os.environ.get("MCP_HUB_RUN_DOCKER") != "1",
        reason="Set MCP_HUB_RUN_DOCKER=1 after make dev; requires Docker socket access",
    ),
]


async def login(client):
    redirect = str(client.base_url).rstrip("/") + "/admin/"
    client_id = "mcp-hub-admin"
    verifier = secrets.token_urlsafe(48)
    response = await client.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": redirect,
            "response_type": "code",
            "code_challenge": challenge(verifier),
            "code_challenge_method": "S256",
            "state": "test-browser-state",
        },
    )
    assert response.status_code == 302, response.text
    response = await client.get(
        response.headers["location"] + "&" + urlencode({"demo_subject": "admin"})
    )
    assert response.status_code == 302, response.text
    response = await client.get(response.headers["location"])
    assert response.status_code == 302, response.text
    code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
    response = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": redirect,
            "code": code,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200, response.text
    client.headers["Authorization"] = "Bearer " + response.json()["access_token"]
    me = await client.get("/admin/api/whoami")
    assert me.status_code == 200 and me.json()["admin"], me.text
    return me.json()


async def rpc(client, name, arguments):
    response = await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert response.status_code == 200, response.text
    return response.json()["result"]


def source(version):
    return textwrap.dedent("""
        import os
        import asyncio
        from mcp.server.fastmcp import FastMCP
        from mcp.server.transport_security import TransportSecuritySettings
        from mcp.types import ToolAnnotations
        from mcp_hub.upstream import serve
        mcp=FastMCP(os.environ['SERVER_NAME'],stateless_http=True,json_response=True,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
        effects={'writes':0,'deletes':0}
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True,destructiveHint=False))
        async def hello(query:str,credentials:dict|None=None)->dict:
            return {'version':'VERSION','caller':(credentials or {}).get('_hub_username'),
                'password':(credentials or {}).get('password'),'query':query}
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False,destructiveHint=False))
        async def create_ticket(subject:str,credentials:dict|None=None)->dict:
            effects['writes']+=1
            return {'created':effects['writes']}
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False,destructiveHint=True))
        async def delete_ticket(ticket:str,credentials:dict|None=None)->dict:
            effects['deletes']+=1
            return {'deleted':effects['deletes']}
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True,destructiveHint=False))
        async def counts(credentials:dict|None=None)->dict:
            return effects
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True,destructiveHint=False))
        async def pause(delay:float=1.0,credentials:dict|None=None)->str:
            await asyncio.sleep(delay)
            return 'drained successfully'
        if __name__=='__main__':serve(mcp)
    """).replace("VERSION", version)


async def wait_tool(client, name):
    for _ in range(40):
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        if name in {tool["name"] for tool in response.json()["result"]["tools"]}:
            return
        await asyncio.sleep(0.25)
    raise AssertionError("Tool did not enter the shared catalog")


async def wait_ready(url):
    async with httpx.AsyncClient(timeout=2, trust_env=False) as client:
        for _ in range(120):
            try:
                if (await client.get(url + "/ready")).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.25)
    raise AssertionError("Replica did not become ready")


async def replicas_and_cutover(daemon, client, server_name):
    original = daemon.containers.get("mcp-hub")
    identifier = uuid.uuid4().hex[:10]
    replica_name, alias = "qa-hub-" + identifier, "qa-control-" + identifier
    environment = {
        key: value
        for raw in original.attrs["Config"]["Env"]
        for key, _, value in [raw.partition("=")]
    }
    environment.update(RUNTIME_HUB_CONTAINER=replica_name, HUB_BIND_HOST=alias)
    volumes = {
        mount["Source"]: {"bind": mount["Destination"], "mode": "rw" if mount["RW"] else "ro"}
        for mount in original.attrs["Mounts"]
        if mount["Type"] == "bind"
    }
    endpoint = daemon.api.create_endpoint_config(aliases=[alias])
    networking = {"mcp-hub-ingress": endpoint}
    replica = daemon.containers.create(
        "mcp-hub:local",
        name=replica_name,
        environment=environment,
        user=original.attrs["Config"]["User"],
        group_add=original.attrs["HostConfig"]["GroupAdd"],
        ulimits=original.attrs["HostConfig"].get("Ulimits"),
        volumes=volumes,
        network="mcp-hub-ingress",
        networking_config=networking,
        ports={"8000/tcp": ("127.0.0.1", None)},
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
    )
    third = "qa-c-" + identifier
    third_created = False
    original_signalled = False
    try:
        daemon.networks.get("mcp-hub-state").connect(replica)
        replica.start()
        replica.reload()
        port = replica.attrs["NetworkSettings"]["Ports"]["8000/tcp"][0]["HostPort"]
        replica_url = "http://localhost:" + port
        await wait_ready(replica_url)
        headers = {"Authorization": client.headers["Authorization"]}
        async with httpx.AsyncClient(
            base_url=replica_url, headers=headers, timeout=20, trust_env=False
        ) as peer:
            # This server is created after the second controller has started.
            response = await client.post(
                "/admin/api/servers-dynamic", json={"name": third, "memory_mb": 128}
            )
            assert response.status_code == 201, response.text
            third_created = True
            assert (
                await client.post("/admin/api/servers-dynamic/" + third + "/start")
            ).status_code == 200
            for _ in range(60):
                result = await rpc(peer, third + ".hello", {"name": "second replica"})
                if not result["isError"]:
                    break
                await asyncio.sleep(0.25)
            else:
                raise AssertionError("Second replica did not attach to the new server network")
            network_name = next(
                iter(
                    daemon.containers.get(container_name(third)).attrs["NetworkSettings"][
                        "Networks"
                    ]
                )
            )
            network = daemon.networks.get(network_name)
            assert len(network.attrs["Containers"]) == 3  # one upstream, two controllers
            assert (
                await client.post("/admin/api/servers-dynamic/" + third + "/stop")
            ).status_code == 200
            assert not daemon.networks.list(names=[network_name])
            selector = {"target": str(client.base_url).rstrip("/")}
            async with httpx.AsyncClient(timeout=10, trust_env=False) as forwarding:

                async def proxy(request: Request):
                    response = await forwarding.request(
                        request.method,
                        selector["target"] + request.url.path,
                        headers=dict(request.headers),
                        content=await request.body(),
                    )
                    return Response(
                        response.content, response.status_code, headers=dict(response.headers)
                    )

                proxy_app = Starlette(
                    routes=[Route("/{path:path}", proxy, methods=["GET", "POST", "DELETE"])]
                )
                async with (
                    serving(proxy_app) as (proxy_url, _),
                    httpx.AsyncClient(
                        base_url=proxy_url, headers=headers, timeout=10, trust_env=False
                    ) as stable_client,
                ):
                    active = asyncio.create_task(
                        rpc(stable_client, server_name + ".pause", {"delay": 1.0})
                    )
                    for _ in range(100):
                        metrics = (await client.get("/metrics")).text
                        if f'hub_inflight{{server="{server_name}"}} 1.0' in metrics:
                            break
                        await asyncio.sleep(0.01)
                    else:
                        raise AssertionError("Long call never entered the original controller")
                    selector["target"] = replica_url

                    async def observe_readiness():
                        for _ in range(200):
                            ready = await client.get("/ready")
                            if ready.status_code == 503:
                                return time.monotonic_ns()
                            await asyncio.sleep(0.002)
                        raise AssertionError("Controller never entered drain readiness")

                    observing = asyncio.create_task(observe_readiness())
                    original_signalled = True
                    code, output = await asyncio.to_thread(
                        original.exec_run,
                        [
                            "python",
                            "-c",
                            "import os,time,signal; moment=time.monotonic_ns(); os.kill(1,signal.SIGTERM); print(moment,flush=True)",
                        ],
                    )
                    assert code == 0, output.decode(errors="replace")
                    signal_ns = int(output.strip())
                    observed_ns = await observing
                    drained = await active
                    elapsed_ms = (observed_ns - signal_ns) / 1_000_000
                    report = Path("/tmp/mcp-hub-cutover.json")
                    await asyncio.to_thread(
                        report.write_text,
                        json.dumps(
                            {
                                "signal_to_503_ms": elapsed_ms,
                                "active_call_drained": not drained["isError"],
                                "post_cutover_calls": 20,
                            }
                        ),
                    )
                    assert 0 <= elapsed_ms < 100
                    assert not drained["isError"]
                    for _ in range(20):
                        assert not (
                            await rpc(
                                stable_client,
                                server_name + ".hello",
                                {"query": "same client URL after cutover"},
                            )
                        )["isError"]
                    assert (await peer.get("/ready")).status_code == 200
    finally:
        try:
            if original_signalled:
                await asyncio.to_thread(original.restart)
                await wait_ready(str(client.base_url).rstrip("/"))
            if third_created:
                response = await client.delete("/admin/api/servers-dynamic/" + third)
                assert response.status_code == 204, response.text
        finally:
            replica.remove(force=True)


async def test_runtime_git_restart_isolation_capabilities_idempotency_and_human_approval():
    url = os.environ.get("MCP_HUB_LIVE_URL", "http://localhost:8000")
    daemon = docker.from_env()
    names = ["qa-a-" + uuid.uuid4().hex[:8], "qa-b-" + uuid.uuid4().hex[:8]]
    created = []
    async with httpx.AsyncClient(base_url=url, timeout=90, trust_env=False) as client:
        me = await login(client)
        assert me["runtime_enabled"]
        try:
            for name in names:
                response = await client.post(
                    "/admin/api/servers-dynamic", json={"name": name, "memory_mb": 128}
                )
                assert response.status_code == 201, response.text
                created.append(name)
            a, b = names
            base = "/admin/api/servers-dynamic/" + a
            files = (await client.get(base + "/files")).json()
            response = await client.post(
                base + "/commit",
                json={
                    "files": {"server.py": source("one")},
                    "expected_commit": files["commit"],
                    "message": "Acceptance version one",
                },
            )
            assert response.status_code == 200, response.text
            for name in names:
                response = await client.post("/admin/api/servers-dynamic/" + name + "/start")
                assert response.status_code == 200, response.text
                assert response.json()["status"] == "running"
            await wait_tool(client, a + ".hello")
            result = await rpc(
                client, a + ".hello", {"query": "first", "credentials": {"_hub_username": "forged"}}
            )
            assert not result["isError"] and "admin@example.test" in str(result)
            assert "one" in str(result) and "forged" not in str(result)
            container_a, container_b = (
                daemon.containers.get(container_name(name)) for name in names
            )
            hub = daemon.containers.get("mcp-hub")
            store_container = daemon.containers.get("mcp-hub-store-1")
            a_network = next(iter(container_a.attrs["NetworkSettings"]["Networks"]))
            b_network = next(iter(container_b.attrs["NetworkSettings"]["Networks"]))
            assert a_network != b_network
            assert set(container_a.attrs["NetworkSettings"]["Networks"]) == {a_network}
            assert container_a.attrs["HostConfig"]["ReadonlyRootfs"]
            assert container_a.attrs["Config"]["User"] == "10001:10001"
            assert container_a.attrs["HostConfig"]["CapDrop"] == ["ALL"]
            assert container_a.attrs["HostConfig"]["PidsLimit"] == 128
            assert container_a.attrs["HostConfig"]["Memory"] == 128 * 1024 * 1024
            assert all(
                mount["Destination"] != "/var/run/docker.sock" and mount["RW"] is False
                for mount in container_a.attrs["Mounts"]
                if mount["Type"] == "bind"
            )
            environments = [
                {
                    key: value
                    for raw in container.attrs["Config"]["Env"]
                    for key, _, value in [raw.partition("=")]
                }
                for container in (container_a, container_b)
            ]
            assert "STORE_URL" not in environments[0]
            assert (
                environments[0]["HUB_REGISTRATION_SECRET"]
                != environments[1]["HUB_REGISTRATION_SECRET"]
            )
            assert environments[0]["HUB_UPSTREAM_SECRET"] != environments[1]["HUB_UPSTREAM_SECRET"]
            local_master = dotenv_values(".env")["HUB_REGISTRATION_SECRET"]
            assert environments[0]["HUB_REGISTRATION_SECRET"] != local_master
            hub.reload()
            targets = {
                "store": [
                    store_container.attrs["NetworkSettings"]["Networks"]["mcp-hub-state"][
                        "IPAddress"
                    ],
                    6379,
                ],
                "other_server": [
                    container_b.attrs["NetworkSettings"]["Networks"][b_network]["IPAddress"],
                    3000,
                ],
                "admin_on_upstream_interface": [
                    hub.attrs["NetworkSettings"]["Networks"][a_network]["IPAddress"],
                    8000,
                ],
                "admin_on_ingress": [
                    hub.attrs["NetworkSettings"]["Networks"]["mcp-hub-ingress"]["IPAddress"],
                    8000,
                ],
            }
            probe = """import json,socket,urllib.request,urllib.error,os
targets=json.loads(os.environ['PROBE_TARGETS']);results={}
for name,(host,port) in targets.items():
 try:
  connection=socket.create_connection((host,port),timeout=0.7);connection.close();results[name]='REACHABLE'
 except OSError:results[name]='blocked'
try:
 urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:3000/mcp',data=b'{}',headers={'Content-Type':'application/json'}),timeout=2)
 results['upstream_without_secret']='REACHABLE'
except urllib.error.HTTPError as exc:results['upstream_without_secret']=exc.code
try:
 urllib.request.urlopen(os.environ['HUB_URL']+'/admin/api/users',timeout=2)
 results['registration_listener_admin']='REACHABLE'
except urllib.error.HTTPError as exc:results['registration_listener_admin']=exc.code
print(json.dumps(results))"""
            code, output = container_a.exec_run(
                ["python", "-c", probe], environment={"PROBE_TARGETS": json.dumps(targets)}
            )
            assert code == 0, output.decode()
            observed = json.loads(output)
            assert observed == {
                **{name: "blocked" for name in targets},
                "upstream_without_secret": 401,
                "registration_listener_admin": 404,
            }, observed
            # Actual upstream state is the oracle for idempotency, independent of the cache.
            results = await asyncio.gather(
                *(rpc(client, a + ".create_ticket", {"subject": "one-ticket"}) for _ in range(10))
            )
            assert any(not result["isError"] for result in results)
            counts = await rpc(client, a + ".counts", {})
            assert json.loads(counts["content"][0]["text"]) == {"writes": 1, "deletes": 0}
            response = await client.put(base, json={"approval_required": True})
            assert response.status_code == 200
            pending = await rpc(client, a + ".delete_ticket", {"ticket": "one"})
            assert pending["isError"] and pending["_meta"]["hub/error"] == "blocked_approval"
            approvals = (await client.get("/admin/api/approvals")).json()["approvals"]
            approval = next(value for value in approvals if value["tool"] == a + ".delete_ticket")
            async with httpx.AsyncClient(
                base_url=url, headers={"Authorization": client.headers["Authorization"]}
            ) as machine:
                response = await machine.post(
                    "/admin/api/approvals/" + approval["id"],
                    json={"decision": "approve"},
                    headers={"Origin": url, "X-Hub-Interactive": me["interaction_csrf"]},
                )
                assert response.status_code == 403
            response = await client.post(
                "/admin/api/approvals/" + approval["id"],
                json={"decision": "approve"},
                headers={"Origin": url, "X-Hub-Interactive": me["interaction_csrf"]},
            )
            assert response.status_code == 200, response.text
            assert not (await rpc(client, a + ".delete_ticket", {"ticket": "one"}))["isError"]
            # Commit does not deploy; Restart fetches the current registry revision.
            files = (await client.get(base + "/files")).json()
            response = await client.post(
                base + "/commit",
                json={
                    "files": {"server.py": source("two")},
                    "expected_commit": files["commit"],
                    "message": "Acceptance version two",
                },
            )
            assert response.status_code == 200
            assert "one" in str(await rpc(client, a + ".hello", {"query": "before restart"}))
            response = await client.post(base + "/restart")
            assert response.status_code == 200, response.text
            await wait_tool(client, a + ".hello")
            assert "two" in str(await rpc(client, a + ".hello", {"query": "after restart"}))
            assert (
                response.json()["code_version"]
                == (await client.get("/health")).json()["upstreams"][a]["code_version"]
            )
            # Same commit can restart again without attempting to rewrite read-only source.
            assert (await client.post(base + "/restart")).status_code == 200
            await replicas_and_cutover(daemon, client, a)
        finally:
            cleanup_failures = []
            for name in reversed(created):
                response = await client.delete("/admin/api/servers-dynamic/" + name)
                if response.status_code != 204:
                    cleanup_failures.append((name, response.status_code, response.text))
            assert not cleanup_failures, cleanup_failures
    daemon.close()


async def test_bad_dependency_prevents_server_execution_and_preserves_diagnostic_logs():
    name = "qa-fail-" + uuid.uuid4().hex[:8]
    base = "/admin/api/servers-dynamic/" + name
    async with httpx.AsyncClient(
        base_url="http://localhost:8000", timeout=90, trust_env=False
    ) as client:
        await login(client)
        response = await client.post(
            "/admin/api/servers-dynamic", json={"name": name, "memory_mb": 128}
        )
        assert response.status_code == 201, response.text
        try:
            files = (await client.get(base + "/files")).json()
            dependency = "mcp-hub-missing-package-" + uuid.uuid4().hex
            response = await client.post(
                base + "/commit",
                json={
                    "files": {"requirements.txt": "mcp>=1.30,<2\n" + dependency + "==0.0.0\n"},
                    "expected_commit": files["commit"],
                    "message": "Test dependency failure",
                },
            )
            assert response.status_code == 200
            response = await client.post(base + "/start")
            assert response.status_code == 502, response.text
            logs = (await client.get(base + "/logs")).json()["logs"]
            assert dependency in logs and (
                "No matching distribution" in logs or "Could not find" in logs
            )
            assert (await client.get(base)).json()["status"] == "error"
        finally:
            response = await client.delete(base)
            assert response.status_code == 204, response.text


async def test_native_redis_backup_restore_and_outbox_preservation():
    daemon = docker.from_env()
    container = daemon.containers.get("mcp-hub-store-1")
    password = dotenv_values(".env")["STORE_PASSWORD"]
    address = container.attrs["NetworkSettings"]["Networks"]["mcp-hub-state"]["IPAddress"]
    prefix = "qa:backup:" + uuid.uuid4().hex + ":"
    conf = Settings(
        store_url=f"redis://:{password}@{address}:6379/0",
        credentials_encryption_key=Fernet.generate_key().decode(),
        environment="development",
        store_prefix=prefix,
    )
    async with Redis.from_url(conf.store_url, decode_responses=True) as redis:
        store = Store(redis, prefix)
        try:
            await redis.hset(store.key("acl:groups"), "default", '{"servers":{"a":["read"]}}')
            encrypted = Cipher(conf.credentials_encryption_key).encrypt(
                {"password": "backup-only-secret"}
            )
            await redis.set(store.key("creds:person:a"), encrypted)
            await redis.sadd(store.key("creds:person:_index"), "a")
            await redis.rpush(store.key("audit:spool"), '{"request_id":"offline-audit-event"}')
            await redis.set(store.key("idem:expired"), '{"state":"done"}', px=10_000)
            await redis.set(store.key("oauth:access:old-session"), "must-not-restore", ex=86400)
            snapshot = await export_state(conf)
            assert len(snapshot["entries"]) == 5
            snapshot["created_at_ms"] -= 20_000
            keys = [key async for key in redis.scan_iter(match=prefix + "*")]
            await redis.delete(*keys)
            assert await import_state(conf, snapshot) == 4
            assert await redis.get(store.key("idem:expired")) is None
            assert await redis.get(store.key("oauth:access:old-session")) is None
            assert (
                await redis.hget(store.key("acl:groups"), "default") == '{"servers":{"a":["read"]}}'
            )
            assert Cipher(conf.credentials_encryption_key).decrypt(
                await redis.get(store.key("creds:person:a"))
            ) == {"password": "backup-only-secret"}
            assert await redis.smembers(store.key("creds:person:_index")) == {"a"}
            assert await redis.lrange(store.key("audit:spool"), 0, -1) == [
                '{"request_id":"offline-audit-event"}'
            ]
            with pytest.raises(ValueError, match="empty"):
                await import_state(conf, snapshot)
            assert (await redis.info("persistence"))["aof_enabled"] == 1
            assert (await redis.config_get("maxmemory-policy"))["maxmemory-policy"] == "noeviction"
        finally:
            keys = [key async for key in redis.scan_iter(match=prefix + "*")]
            if keys:
                await redis.delete(*keys)
    daemon.close()
