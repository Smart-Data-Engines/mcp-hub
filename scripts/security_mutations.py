"""Check security regressions in disposable copies of a committed public source tree.

Run with the project's locked development environment. No original source is edited;
all state and TCP producers belong to the tests. A matching assertion must fail, not
collection/setup, while unchanged and neutral source controls must remain green.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECURITY_TESTS = [
    "tests/integration/test_execution_context.py",
    "tests/integration/test_security_capacity.py",
    "tests/integration/test_untrusted_definitions.py",
    "tests/integration/test_oidc.py",
    "tests/unit/test_trust_boundary.py",
]
E = "tests/integration/test_execution_context.py::"
C = "tests/integration/test_security_capacity.py::"
U = "tests/integration/test_untrusted_definitions.py::"
T = "tests/unit/test_trust_boundary.py::"
# Exact mechanical fault injection; special substitutions below replace one complete block.
CASES = [
    (
        "unannotated-read",
        "security.py",
        'return "destructive", False',
        'return "read", False',
        E + "test_unannotated_tool_is_never_assumed_read_only[execute_sql]",
    ),
    (
        "stale-category",
        "gateway.py",
        "kind = category(tool)[0]",
        'kind = tool["category"]',
        E + "test_stale_catalog_cannot_turn_an_unannotated_tool_into_a_read",
    ),
    (
        "sdk-output-schema",
        "upstreams.py",
        None,
        None,
        U + "test_adapter_output_schema_is_not_executed_by_the_hub[invalid-regex]",
    ),
    (
        "approval-context",
        "gateway.py",
        "if approval and not self._same_execution(approval, execution_context):",
        "if False and approval:",
        E + "test_destructive_approval_cannot_follow_a_changed_execution_context[header]",
    ),
    (
        "replay-context",
        "gateway.py",
        "if record and not self._same_execution(record, execution_context):",
        "if False and record:",
        E + "test_cached_write_cannot_be_replayed_for_a_different_connection",
    ),
    (
        "replay-before-policy",
        "gateway.py",
        None,
        None,
        E + "test_cached_write_still_enforces_current_personal_credential_policy",
    ),
    (
        "stale-admin-email",
        "acl.py",
        None,
        None,
        E
        + "test_admin_policy_removes_the_subjects_previous_verified_email_binding[renamed@example.test]",
    ),
    (
        "single-audience-azp",
        "oauth.py",
        '"azp" in claims',
        "False",
        "tests/integration/test_oidc.py::test_invalid_idp_identity_never_provisions_or_issues_code[single_azp]",
    ),
    (
        "credential-size",
        "credentials.py",
        "if len(dumps(clean).encode()) > self.max_bytes:",
        "if False:",
        E + "test_credential_document_size_is_bounded_before_persistence",
    ),
    (
        "credential-quota",
        "credentials.py",
        "if redis.call('SISMEMBER',KEYS[2],ARGV[1])==0 and redis.call('SCARD',KEYS[2])>=tonumber(ARGV[4]) then return 0 end",
        "if false then return 0 end",
        E + "test_concurrent_credential_creation_cannot_overfill_the_principal_budget",
    ),
    (
        "credential-namespace",
        "credentials.py",
        'if service in {"_index", "modes"}:',
        "if False:",
        C + "test_service_names_cannot_overwrite_or_delete_credential_bookkeeping[_index]",
    ),
    (
        "preference-quota",
        "credentials.py",
        "if redis.call('HEXISTS',KEYS[1],ARGV[1])==0 and redis.call('HLEN',KEYS[1])>=tonumber(ARGV[3]) then return 0 end",
        "if false then return 0 end",
        E + "test_preference_budget_can_be_reclaimed_without_credential_fallback",
    ),
    (
        "registration-quota",
        "oauth.py",
        "if redis.call('ZCARD',KEYS[2])>=tonumber(ARGV[3]) then return 0 end",
        "if false then return 0 end",
        C + "test_public_client_registration_has_an_atomic_storage_budget",
    ),
    (
        "registration-expiry",
        "oauth.py",
        "redis.call('SET',KEYS[1],ARGV[1],'EX',ARGV[4])",
        "redis.call('SET',KEYS[1],ARGV[1])",
        C + "test_unused_registration_expires_but_successful_exchange_extends_it",
    ),
    (
        "expired-client-race",
        "oauth.py",
        "if ARGV[7]=='1' and not client then return -1 end",
        "if false then return -1 end",
        C + "test_expired_client_cannot_race_code_exchange_into_new_tokens",
    ),
    (
        "yaml-alias",
        "declarations.py",
        "or self.check_event(yaml.AliasEvent)",
        "or False",
        U + "test_controller_yaml_is_bounded_before_construction[alias]",
    ),
    (
        "git-preflight-count",
        "registry.py",
        "if len(records) > 100:",
        "if False:",
        U + "test_git_snapshot_limits_are_checked_before_loading_blobs[101-1]",
    ),
    (
        "audit-size",
        "observability.py",
        "if len(serialized.encode()) > self.settings.max_audit_event_bytes:",
        "if False:",
        C + "test_large_request_cannot_expand_audit_storage_without_bound[arguments]",
    ),
    (
        "catalog-validation",
        "gateway.py",
        'if not entry.get("tools_validated", False):',
        "if False:",
        C + "test_failed_catalog_validation_does_not_keep_old_tools_callable",
    ),
    (
        "ambient-ca",
        "tls.py",
        "ssl.create_default_context(cafile=certifi.where())",
        "ssl.create_default_context()",
        T + "test_explicit_ca_extends_curated_trust_without_ambient_roots",
    ),
    (
        "deployment-deadline",
        "gateway.py",
        None,
        None,
        C + "test_legacy_server_timeout_cannot_escape_the_global_deadline",
    ),
    (
        "revocation-lifetime",
        "config.py",
        "if self.access_token_ttl > self.refresh_token_ttl:",
        "if False:",
        T + "test_revocation_index_cannot_expire_before_access_tokens",
    ),
    (
        "unknown-environment",
        "config.py",
        'if self.environment not in {"production", "development"}:',
        "if False:",
        T + "test_misspelled_environment_cannot_skip_production_checks[prod]",
    ),
]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def replace_block(source: str, start: str, end: str, replacement: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[:begin] + replacement + source[finish:]


def mutate(name: str, source: str, old: str | None, new: str | None) -> str:
    if name == "sdk-output-schema":
        return replace_block(
            source,
            "            result = await self.client.send_request(",
            "\n        except McpError",
            '            result = await self.client.call_tool(name, arguments, read_timeout_seconds=timedelta(seconds=budget), meta={"hub/request_id": request_id})',
        )
    if name == "replay-before-policy":
        marker = "                resolved = await self.credentials.resolve("
        assert source.count(marker) == 1
        return source.replace(
            marker,
            "                premature = await self.store.get('idem:' + fingerprint)\n                if premature and premature.get('state') == 'done':\n                    raise Completed(premature['result'], 'idempotent_replay')\n"
            + marker,
            1,
        )
    if name == "stale-admin-email":
        return replace_block(
            source,
            "                local bindings=",
            "                for _,email in ipairs(allowed)",
            "",
        )
    if name == "deployment-deadline":
        return replace_block(
            source,
            "                ceiling = min(",
            "                budget = min(",
            "                ceiling = definition.get('call_timeout') or self.settings.upstream_call_tool_timeout\n",
        )
    assert old is not None and new is not None
    expected = 2 if name in {"credential-size", "audit-size"} else 1
    assert source.count(old) == expected, (name, source.count(old))
    return source.replace(old, new, 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    subprocess.run([sys.executable, "scripts/check_private_boundaries.py"], cwd=ROOT, check=True)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    archive = subprocess.check_output(["git", "archive", "--format=tar", head], cwd=ROOT)
    report: dict = {"source_commit": head, "source_archive_sha256": digest(archive), "cases": []}
    cases = [
        ("unchanged-control", "security.py", None, None, None),
        *CASES,
        (
            "neutral-control",
            "security.py",
            'MASK = "[REDACTED]"',
            'MASK = "[REDACTED]"  # neutral qualification',
            None,
        ),
    ]
    for name, filename, old, new, target in cases:
        with tempfile.TemporaryDirectory(prefix="mcp-hub-security-mutant-") as temporary:
            checkout = Path(temporary)
            with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
                bundle.extractall(checkout, filter="data")
            path = checkout / "src/mcp_hub" / filename
            before = path.read_bytes()
            if name != "unchanged-control":
                path.write_text(mutate(name, before.decode(), old, new))
            after = path.read_bytes()
            if name != "unchanged-control":
                assert digest(before) != digest(after)
            receipt = output / (name + ".xml")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    *([target] if target else SECURITY_TESTS),
                    "-q",
                    "--tb=short",
                    "--show-capture=no",
                    "--junitxml=" + str(receipt),
                ],
                cwd=checkout,
                env={
                    **os.environ,
                    "PYTHONPATH": str(checkout / "src"),
                    "MCP_HUB_RUN_LIVE": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                capture_output=True,
                timeout=120,
            )
            (output / (name + ".log")).write_bytes(result.stdout + result.stderr)
            suites = ET.parse(receipt)
            errors = sum(int(s.get("errors", "0")) for s in suites.findall(".//testsuite"))
            failed = [
                c.get("name", "")
                for c in suites.findall(".//testcase")
                if c.find("failure") is not None
            ]
            accepted = (
                (result.returncode == 0 and not failed and not errors)
                if target is None
                else (
                    result.returncode == 1
                    and not errors
                    and any(n.startswith(target.split("::")[-1]) for n in failed)
                )
            )
            entry = {
                "name": name,
                "expected": "detected" if target else "survived",
                "accepted": accepted,
                "exit_code": result.returncode,
                "setup_errors": errors,
                "failed_tests": failed,
                "source_before": digest(before),
                "source_after": digest(after),
                "junit_sha256": digest(receipt.read_bytes()),
                "output_sha256": digest(result.stdout + result.stderr),
            }
            report["cases"].append(entry)
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            print(
                json.dumps({"case": name, "accepted": accepted, "expected": entry["expected"]}),
                flush=True,
            )
            if not accepted:
                raise SystemExit(
                    "Unexpected mutation result; inspect its receipt before continuing"
                )
    report["state"] = "passed"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
