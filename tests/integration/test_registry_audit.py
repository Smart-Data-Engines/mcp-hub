import asyncio
import json
import time

import httpx
import pytest

from mcp_hub.models import HubError
from mcp_hub.registry import LocalGitRegistry


async def test_real_git_batch_commit_and_optimistic_concurrency(tmp_path):
    registry = LocalGitRegistry(str(tmp_path / "registry.git"))
    first = await registry.commit(
        "owner/server", {"server.py": "one", "env.yaml": "env: []"}, "create"
    )
    snapshot = await registry.snapshot("owner/server")
    assert snapshot.commit == first
    second = await registry.commit(
        "owner/server", {"server.py": "two", "env.yaml": "env: [API_KEY]"}, "both in one", first
    )
    assert second != first
    assert (await registry.snapshot("owner/server", first)).files["server.py"] == "one"
    assert (await registry.snapshot("owner/server")).files == {
        "server.py": "two",
        "env.yaml": "env: [API_KEY]",
    }
    with pytest.raises(HubError, match="changed"):
        await registry.commit("owner/server", {"server.py": "stale"}, "stale", first)
    for path in (
        "../outside",
        "/absolute",
        "folder/../../escape",
        ".git/config",
        "a\\b",
        "a//b",
        "a\n100644 injected",
    ):
        with pytest.raises(HubError):
            await registry.commit("owner/server", {path: "bad"}, "bad")
    await registry.commit(
        "owner/server",
        {name: None for name in (await registry.snapshot("owner/server")).files},
        "delete all",
    )
    assert (await registry.snapshot("owner/server")).files == {}


async def test_audit_failure_does_not_delay_tool_and_outbox_replays(harness):
    calls = []
    available = False

    async def sink(request):
        calls.append(request)
        if not available:
            await asyncio.sleep(0.5)
            return httpx.Response(503)
        return httpx.Response(201)

    async with httpx.AsyncClient(transport=httpx.MockTransport(sink)) as client:
        harness.hub.audit.client = client
        harness.hub.settings.audit_sink_url = "https://audit.example.test"
        started = time.monotonic()
        response = await harness.rpc(
            "tools/call", {"name": "alpha.lookup", "arguments": {"query": "select 1"}}
        )
        assert not response.json()["result"]["isError"]
        assert time.monotonic() - started < 0.5
        assert not calls
        with pytest.raises(httpx.HTTPStatusError):
            await harness.hub.audit.flush()
        assert await harness.hub.redis.llen(harness.hub.store.key("audit:spool")) == 1
        available = True
        assert await harness.hub.audit.flush() == 1
        assert await harness.hub.redis.llen(harness.hub.store.key("audit:spool")) == 0
        assert calls[0].url == calls[1].url
        event = json.loads(calls[1].content)
        assert event["arguments"]["query"] == "select 1"


async def test_bounded_outbox_counts_every_dropped_event(harness, caplog):
    harness.hub.settings.audit_spool_max_entries = 2
    for i in range(5):
        await harness.hub.audit.append(
            {"request_id": str(i), "arguments": {"password": "never-log-this", "query": "keep"}}
        )
    assert await harness.hub.redis.llen(harness.hub.store.key("audit:spool")) == 2
    assert int(await harness.hub.redis.get(harness.hub.store.key("audit:dropped"))) == 3
    assert 'audit_dropped_total{reason="spool_full"} 3.0' in harness.hub.metrics.render().decode()
    assert "never-log-this" not in caplog.text
    assert "never-log-this" not in str(
        await harness.hub.redis.lrange(harness.hub.store.key("audit:spool"), 0, -1)
    )
