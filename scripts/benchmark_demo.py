"""Reference-profile measurements against localhost demo; never prints auth tokens."""

import asyncio
import json
import os
import re
import secrets
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

from mcp_hub.oauth import challenge


async def authenticate(client: httpx.AsyncClient) -> None:
    supplied = os.environ.get("HUB_BENCHMARK_TOKEN")
    if supplied:
        client.headers["Authorization"] = "Bearer " + supplied
        return
    if str(client.base_url).rstrip("/") != "http://localhost:8000":
        raise ValueError(
            "Automatic demo login is localhost-only; supply HUB_BENCHMARK_TOKEN otherwise"
        )
    redirect = "http://127.0.0.1:43999/callback"
    registered = await client.post(
        "/oauth/register",
        json={"client_name": "MCP Hub reference benchmark", "redirect_uris": [redirect]},
    )
    registered.raise_for_status()
    client_id = registered.json()["client_id"]
    verifier = secrets.token_urlsafe(48)
    response = await client.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": redirect,
            "response_type": "code",
            "code_challenge": challenge(verifier),
            "code_challenge_method": "S256",
            "state": "local-reference-measurement",
        },
    )
    response = await client.get(response.headers["location"] + "&demo_subject=admin")
    response = await client.get(response.headers["location"])
    consent = re.search(r'name="consent" value="([^"]+)"', response.text)[1]
    response = await client.post("/oauth/consent", data={"consent": consent, "decision": "allow"})
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
    response.raise_for_status()
    client.headers["Authorization"] = "Bearer " + response.json()["access_token"]


def percentiles(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        label: round(ordered[min(len(ordered) - 1, int(fraction * len(ordered)))], 3)
        for label, fraction in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99))
    }


async def main() -> None:
    url = os.environ.get("HUB_BENCHMARK_URL", "http://localhost:8000")
    total, overhead = [], []
    async with httpx.AsyncClient(base_url=url, timeout=30, trust_env=False) as client:
        await authenticate(client)
        for index in range(210):
            began = time.perf_counter()
            response = await client.post(
                "/mcp",
                headers={"Accept": "application/json, text/event-stream"},
                json={
                    "jsonrpc": "2.0",
                    "id": str(uuid.uuid4()),
                    "method": "tools/call",
                    "params": {
                        "name": "demo-directory.search",
                        "arguments": {"query": "Engineering"},
                    },
                },
            )
            response.raise_for_status()
            if response.json()["result"]["isError"]:
                raise RuntimeError("Benchmark tool call failed")
            if index >= 10:
                total.append((time.perf_counter() - began) * 1000)
                overhead.append(float(response.headers["x-hub-overhead-ms"]))
    parsed = urlsplit(url)
    connections = await asyncio.gather(
        *(asyncio.open_connection(parsed.hostname, parsed.port or 80) for _ in range(1000))
    )

    async def probe(reader, writer):
        writer.write(
            b"GET /ready HTTP/1.1\r\nHost: localhost:8000\r\nConnection: keep-alive\r\n\r\n"
        )
        await writer.drain()
        headers = await reader.readuntil(b"\r\n\r\n")
        length = int(re.search(rb"content-length: (\d+)", headers, re.I)[1])
        await reader.readexactly(length)
        return headers.startswith(b"HTTP/1.1 200") and not reader.at_eof()

    try:
        accepted = await asyncio.gather(*(probe(reader, writer) for reader, writer in connections))
        result = {
            "profile": "localhost demo, sequential read calls, 10 warmups",
            "requests": 200,
            "total_client_ms": percentiles(total),
            "gateway_overhead_ms": percentiles(overhead),
            "simultaneous_http_connections": sum(accepted),
        }
        output = Path(".local/verification/benchmark.json")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        if sum(accepted) != 1000:
            raise RuntimeError(
                "Not all 1000 readiness connections were accepted; measurement retained"
            )
    finally:
        for _, writer in connections:
            writer.close()
        await asyncio.gather(
            *(writer.wait_closed() for _, writer in connections), return_exceptions=True
        )


if __name__ == "__main__":
    asyncio.run(main())
