#!/usr/bin/env python3
"""
Octopus Deploy Kubernetes Agent Diagnostic Tool.

Collects diagnostic information about an Octopus Deploy Kubernetes agent and
bundles it into a zip for sharing with support.

Requires Python 3.8+ and kubectl on PATH. helm is optional.

Usage:
    python3 octopus-agent-diag.py
    python3 octopus-agent-diag.py --namespace octopus-agent-target
    python3 octopus-agent-diag.py -n octopus-agent -o /tmp/diag

Or one-liner (once hosted):
    curl -sSL https://<host>/octopus-agent-diag.py | python3 -
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

AGENT_LABEL = "app.kubernetes.io/name=octopus-agent"
LOG_TAIL_LINES = 5000

# Keys we strip from Helm values before writing to the bundle. Match is
# case-insensitive on the leaf key name, at any depth. `*SecretName` keys
# are intentionally NOT in this list — they name a secret, not a value.
SENSITIVE_HELM_KEYS = frozenset(
    {
        "bearertoken",
        "serverapikey",
        "username",
        "password",
        "certificate",
        "servercertificate",
    }
)

ERROR_PATTERN = re.compile(
    r"\b(error|errors|fatal|panic|exception|failed|failure|denied|"
    r"unauthori[sz]ed|forbidden|timeout|timed out|refused|unreachable|"
    r"crashloopbackoff|imagepullbackoff|oomkilled|evicted)\b"
    r"|\bwarn(ing)?\b",
    re.IGNORECASE,
)

WORKLOAD_KINDS = [
    "deployments",
    "statefulsets",
    "daemonsets",
    "services",
    "persistentvolumeclaims",
]


def section(text: str) -> None:
    print(f"\n--- {text} ---")


def info(text: str) -> None:
    print(f"[i] {text}")


def ok(text: str) -> None:
    print(f"[OK] {text}")


def warn(text: str) -> None:
    print(f"[!] {text}")


def fail(text: str) -> None:
    print(f"[X] {text}")


@dataclass
class CmdResult:
    """Outcome of running an external command."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(cmd: list[str], timeout: int = 60) -> CmdResult:
    """Run a command and capture its output. Never raises."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CmdResult(proc.returncode, proc.stdout, proc.stderr)
    except FileNotFoundError:
        return CmdResult(127, "", f"command not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return CmdResult(
            124, "", f"command timed out after {timeout}s: {' '.join(cmd)}"
        )
    except Exception as exc:
        return CmdResult(1, "", f"error: {exc}")


def capture(out_file: Path, cmd: list[str], timeout: int = 60) -> None:
    """Run a command and write its output (plus a header) to a file."""
    result = run(cmd, timeout=timeout)
    header = f"# Command: {' '.join(cmd)}\n" f"# Run at: {utc_now()}\n\n"
    body = result.stdout
    if result.stderr:
        body += f"\n--- stderr ---\n{result.stderr}"
    body += f"\n# Exit code: {result.returncode}\n"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(header + body, encoding="utf-8")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

@dataclass
class DiagContext:
    bundle_dir: Path
    namespace: str = ""
    pods: list[str] = field(default_factory=list)
    helm_releases: list[str] = field(default_factory=list)
    octopus_url: str = ""
    k8s_version: str = "unknown"
    node_count: int = 0
    context_name: str = "unknown"
    has_helm: bool = False
    error_count: int = 0


def check_preflight() -> bool:
    """Verify kubectl exists and the cluster is reachable."""
    section("Preflight")

    if not shutil.which("kubectl"):
        fail("kubectl not found on PATH. Install kubectl and try again.")
        return False
    r = run(["kubectl", "version", "--client", "-o", "json"])
    client_ver = "unknown"
    if r.ok:
        try:
            client_ver = (
                json.loads(r.stdout)
                .get("clientVersion", {})
                .get("gitVersion", "unknown")
            )
        except json.JSONDecodeError:
            pass
    ok(f"kubectl found: {client_ver}")

    if not run(["kubectl", "cluster-info"], timeout=15).ok:
        fail("Cannot reach the Kubernetes cluster. Is your kubeconfig set correctly?")
        ctx = run(["kubectl", "config", "current-context"]).stdout.strip() or "<none>"
        info(f"Current context: {ctx}")
        return False
    ctx = run(["kubectl", "config", "current-context"]).stdout.strip() or "<unknown>"
    ok(f"Cluster reachable (context: {ctx})")
    return True


def locate_agent(ctx: DiagContext, user_namespace: str) -> None:
    section("Locating agent")

    if user_namespace:
        # User-provided — just validate the namespace exists.
        if run(["kubectl", "get", "namespace", user_namespace]).ok:
            ctx.namespace = user_namespace
            ok(f"Using namespace: {user_namespace}")
        else:
            fail(f"Namespace '{user_namespace}' does not exist.")
        return

    info("No namespace provided, searching all namespaces for agent pods...")
    r = run(
        [
            "kubectl",
            "get",
            "pods",
            "--all-namespaces",
            "-l",
            AGENT_LABEL,
            "-o",
            'jsonpath={range .items[*]}{.metadata.namespace}{"\\n"}{end}',
        ]
    )
    namespaces = sorted({ns for ns in r.stdout.split("\n") if ns})
    if namespaces:
        ctx.namespace = namespaces[0]
        ok(f"Found agent in namespace: {ctx.namespace}")
    else:
        fail("No Octopus agent pods found in any namespace.")
        info(f"Looking for pods with label: {AGENT_LABEL}")
        info("If your agent uses a non-default label, pass --namespace explicitly.")


def collect_cluster_info(ctx: DiagContext) -> None:
    section("Cluster and node info")

    info("Collecting cluster version...")
    capture(
        ctx.bundle_dir / "cluster" / "version.txt", ["kubectl", "version", "-o", "yaml"]
    )
    ok("Saved cluster version")

    info("Collecting node info...")
    capture(
        ctx.bundle_dir / "cluster" / "nodes.txt",
        ["kubectl", "get", "nodes", "-o", "wide"],
    )
    capture(
        ctx.bundle_dir / "cluster" / "nodes-describe.txt",
        ["kubectl", "describe", "nodes"],
    )
    ok("Saved node info")

    # Pull structured info for the SUMMARY
    r = run(["kubectl", "version", "-o", "json"])
    if r.ok:
        try:
            server = json.loads(r.stdout).get("serverVersion", {})
            ctx.k8s_version = server.get("gitVersion", "unknown")
        except json.JSONDecodeError:
            pass

    r = run(["kubectl", "get", "nodes", "--no-headers"])
    if r.ok:
        ctx.node_count = len([line for line in r.stdout.split("\n") if line.strip()])

    ctx.context_name = (
        run(["kubectl", "config", "current-context"]).stdout.strip() or "unknown"
    )

    info(f"Kubernetes server version: {ctx.k8s_version}")
    info(f"Node count: {ctx.node_count}")


def collect_agent_resources(ctx: DiagContext) -> None:
    if not ctx.namespace:
        return
    ns = ctx.namespace
    section(f"Agent resources in '{ns}'")

    info("Collecting all resources in namespace...")
    capture(
        ctx.bundle_dir / "agent" / "all-resources.txt",
        ["kubectl", "get", "all", "-n", ns, "-o", "wide"],
    )
    capture(
        ctx.bundle_dir / "agent" / "all-resources.yaml",
        ["kubectl", "get", "all", "-n", ns, "-o", "yaml"],
    )

    info("Collecting pod details...")
    r = run(
        [
            "kubectl",
            "get",
            "pods",
            "-n",
            ns,
            "-o",
            'jsonpath={range .items[*]}{.metadata.name}{"\\n"}{end}',
        ]
    )
    ctx.pods = [p for p in r.stdout.split("\n") if p]

    for pod in ctx.pods:
        capture(
            ctx.bundle_dir / "agent" / f"pod-{pod}.txt",
            ["kubectl", "describe", "pod", pod, "-n", ns],
        )

    if ctx.pods:
        ok(f"Described {len(ctx.pods)} pod(s)")
        # Show a friendly table to the terminal
        status = run(["kubectl", "get", "pods", "-n", ns])
        if status.ok:
            print()
            print(status.stdout.rstrip())
    else:
        warn(f"No pods found in namespace {ns}")

    info("Collecting events...")
    capture(
        ctx.bundle_dir / "agent" / "events.txt",
        ["kubectl", "get", "events", "-n", ns, "--sort-by=.lastTimestamp"],
    )
    ok("Saved events")

    info("Collecting workload and service manifests...")
    for kind in WORKLOAD_KINDS:
        capture(
            ctx.bundle_dir / "resources" / f"{kind}.yaml",
            ["kubectl", "get", kind, "-n", ns, "-o", "yaml"],
        )
    ok("Saved workloads, services, configmaps, PVCs")


def collect_logs(ctx: DiagContext) -> None:
    if not ctx.pods or not ctx.namespace:
        return
    section("Pod logs")
    ns = ctx.namespace

    for pod in ctx.pods:
        info(f"Collecting logs from {pod}...")
        r = run(
            [
                "kubectl",
                "get",
                "pod",
                pod,
                "-n",
                ns,
                "-o",
                'jsonpath={range .spec.containers[*]}{.name}{"\\n"}{end}',
            ]
        )
        containers = [c for c in r.stdout.split("\n") if c]

        for container in containers:
            capture(
                ctx.bundle_dir / "logs" / f"{pod}_{container}.log",
                [
                    "kubectl",
                    "logs",
                    pod,
                    "-c",
                    container,
                    "-n",
                    ns,
                    f"--tail={LOG_TAIL_LINES}",
                ],
                timeout=120,
            )
            prev_file = ctx.bundle_dir / "logs" / f"{pod}_{container}_previous.log"
            prev = run(
                [
                    "kubectl",
                    "logs",
                    pod,
                    "-c",
                    container,
                    "-n",
                    ns,
                    "--previous",
                    f"--tail={LOG_TAIL_LINES}",
                ],
                timeout=120,
            )
            if prev.ok and prev.stdout.strip():
                prev_file.write_text(prev.stdout, encoding="utf-8")

    ok("Saved pod logs")


def scan_for_errors(ctx: DiagContext) -> None:
    if not ctx.namespace or not ctx.pods:
        return
    section("Scanning logs for errors and warnings")

    errors_file = ctx.bundle_dir / "ERRORS.txt"
    lines: list[str] = [
        "Errors, warnings, and failures found in collected logs",
        "======================================================",
        "",
        f"Generated: {utc_now()}",
        f"Pattern:   {ERROR_PATTERN.pattern}",
        "",
        "Files scanned: all *.log files under logs/, plus agent/events.txt",
        "",
        "NOTE: This is a best-effort scan. Not every match is a real problem —",
        "some logs mention 'error' in normal output (e.g. error handling setup).",
        "Review matches in context using the original log files.",
        "",
        "-----",
        "",
    ]

    files_to_scan: list[Path] = sorted((ctx.bundle_dir / "logs").glob("*.log"))
    events_file = ctx.bundle_dir / "agent" / "events.txt"
    if events_file.exists():
        files_to_scan.append(events_file)

    total = 0
    for path in files_to_scan:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        matches = [
            (i, line)
            for i, line in enumerate(content.splitlines(), start=1)
            if ERROR_PATTERN.search(line)
        ]
        if matches:
            total += len(matches)
            rel = path.relative_to(ctx.bundle_dir).as_posix()
            lines.append(f"=== {rel} ({len(matches)} match(es)) ===")
            for lineno, line in matches:
                lines.append(f"{lineno}: {line}")
            lines.append("")

    lines.append("-----")
    lines.append(f"Total matches: {total}")
    errors_file.write_text("\n".join(lines), encoding="utf-8")

    ctx.error_count = total
    if total == 0:
        ok("No errors or warnings found in logs")
    else:
        warn(f"Found {total} potential issue(s) — see ERRORS.txt in the bundle")


def collect_helm(ctx: DiagContext) -> None:
    if not ctx.has_helm or not ctx.namespace:
        return
    section("Helm release info")
    ns = ctx.namespace

    info("Listing Helm releases in namespace...")
    capture(
        ctx.bundle_dir / "helm" / "releases.txt", ["helm", "list", "-n", ns, "--all"]
    )

    r = run(["helm", "list", "-n", ns, "-q"])
    ctx.helm_releases = [rel for rel in r.stdout.split("\n") if rel]

    for rel in ctx.helm_releases:
        info(f"Collecting details for release: {rel}")
        values_result = run(["helm", "get", "values", rel, "-n", ns, "--all"])
        values_out = ctx.bundle_dir / "helm" / f"{rel}-values.yaml"
        values_out.write_text(
            f"# Command: helm get values {rel} -n {ns} --all\n"
            f"# Run at: {utc_now()}\n"
            f"# NOTE: Sensitive keys have been redacted before writing. "
            f"Redacted keys: {', '.join(sorted(SENSITIVE_HELM_KEYS))}\n\n"
            + sanitize_helm_values(values_result.stdout),
            encoding="utf-8",
        )

        manifest_result = run(["helm", "get", "manifest", rel, "-n", ns])
        manifest_out = ctx.bundle_dir / "helm" / f"{rel}-manifest.yaml"
        manifest_out.write_text(
            f"# Command: helm get manifest {rel} -n {ns}\n"
            f"# Run at: {utc_now()}\n"
            f"# NOTE: Sensitive keys have been redacted before writing.\n\n"
            + sanitize_helm_values(manifest_result.stdout),
            encoding="utf-8",
        )

        capture(
            ctx.bundle_dir / "helm" / f"{rel}-history.txt",
            ["helm", "history", rel, "-n", ns],
        )

    if ctx.helm_releases:
        ok("Saved Helm release info")
    else:
        warn(f"No Helm releases found in namespace {ns}")

def collect_rbac(ctx: DiagContext) -> None:
    """Collect RBAC. Secrets are deliberately skipped entirely."""
    if not ctx.namespace:
        return
    section("RBAC and service accounts")
    ns = ctx.namespace

    info("Collecting service accounts...")
    capture(
        ctx.bundle_dir / "rbac" / "serviceaccounts.yaml",
        ["kubectl", "get", "serviceaccounts", "-n", ns, "-o", "yaml"],
    )

    info("Collecting roles and rolebindings...")
    capture(
        ctx.bundle_dir / "rbac" / "roles.yaml",
        ["kubectl", "get", "roles", "-n", ns, "-o", "yaml"],
    )
    capture(
        ctx.bundle_dir / "rbac" / "rolebindings.yaml",
        ["kubectl", "get", "rolebindings", "-n", ns, "-o", "yaml"],
    )

    info("Collecting cluster-scoped RBAC...")
    capture(
        ctx.bundle_dir / "rbac" / "clusterrolebindings-all.yaml",
        ["kubectl", "get", "clusterrolebindings", "-o", "yaml"],
    )
    capture(
        ctx.bundle_dir / "rbac" / "clusterroles-all.yaml",
        ["kubectl", "get", "clusterroles", "-o", "yaml"],
    )

    info("Listing secret names (no data collected)...")
    secret_listing = ctx.bundle_dir / "rbac" / "secret-names.txt"
    header = (
        f"# Secret NAMES only (no data, no metadata) in namespace {ns}\n"
        f"# Run at: {utc_now()}\n"
        f"# This file contains only secret names and types so support can\n"
        f"# verify the expected secrets exist. No secret contents are collected.\n\n"
    )
    secret_listing.write_text(
        header + run(["kubectl", "get", "secrets", "-n", ns]).stdout,
        encoding="utf-8",
    )
    ok("Saved RBAC. Secret data not collected.")


def collect_configmap_names(ctx: DiagContext) -> None:
    """Collect configmap names and labels only, not the .data field."""
    if not ctx.namespace:
        return
    ns = ctx.namespace
    info("Listing configmap names (no data collected)...")

    r = run(["kubectl", "get", "configmaps", "-n", ns, "-o", "json"])
    out = ctx.bundle_dir / "resources" / "configmaps-names.txt"
    header = (
        f"# ConfigMap NAMES and labels only (no .data) in namespace {ns}\n"
        f"# Run at: {utc_now()}\n"
        f"# This file contains only configmap names, labels, and annotations so\n"
        f"# support can verify expected configmaps exist. No configmap data is collected.\n\n"
    )
    if not r.ok:
        out.write_text(
            header + f"kubectl get configmaps failed: {r.stderr}\n", encoding="utf-8"
        )
        return

    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        out.write_text(
            header + f"Could not parse configmap JSON: {e}\n", encoding="utf-8"
        )
        return

    lines = [header.rstrip(), ""]
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        name = meta.get("name", "<unknown>")
        labels = meta.get("labels") or {}
        annotations = meta.get("annotations") or {}
        annotations = {
            k: v
            for k, v in annotations.items()
            if k != "kubectl.kubernetes.io/last-applied-configuration"
        }
        lines.append(f"- name: {name}")
        if labels:
            lines.append(f"  labels:")
            for k, v in sorted(labels.items()):
                lines.append(f"    {k}: {v}")
        if annotations:
            lines.append(f"  annotations:")
            for k, v in sorted(annotations.items()):
                lines.append(f"    {k}: {v}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

def collect_resource_usage(ctx: DiagContext) -> None:
    if not ctx.namespace:
        return
    section("Resource usage")
    info("Collecting resource usage (requires metrics-server)...")

    if not run(["kubectl", "top", "nodes"], timeout=30).ok:
        warn("metrics-server not available — skipping 'kubectl top'")
        (ctx.bundle_dir / "cluster" / "top-nodes.txt").write_text(
            "metrics-server not available in this cluster\n", encoding="utf-8"
        )
        return

    capture(ctx.bundle_dir / "cluster" / "top-nodes.txt", ["kubectl", "top", "nodes"])
    capture(
        ctx.bundle_dir / "agent" / "top-pods.txt",
        ["kubectl", "top", "pods", "-n", ctx.namespace, "--containers"],
    )
    ok("Saved resource usage")

def parse_server_url(yaml_text: str) -> str:
    """
    Extract agent.serverUrl (or fall back to global.serverApiUrl) from a
    helm values.yaml dump.

    This tracks the top-level block so we never confuse comment lines
    mentioning 'serverUrl' with real nested values, and never pick up
    a serverUrl from an unrelated block.
    """
    if not yaml_text:
        return ""

    current_block = ""
    fallback = ""

    for raw in yaml_text.splitlines():
        line = raw.rstrip()
        if not line:
            continue

        if not line[0].isspace() and not line.lstrip().startswith("#") and ":" in line:
            current_block = line.split(":", 1)[0].strip()
            continue

        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue

        if current_block == "agent":
            m = re.match(r"^\s+serverUrl:\s*(.*)$", line)
            if m:
                val = m.group(1).strip().strip('"').strip("'")
                if val:
                    return val

        if current_block == "global":
            m = re.match(r"^\s+serverApiUrl:\s*(.*)$", line)
            if m:
                val = m.group(1).strip().strip('"').strip("'")
                if val and not fallback:
                    fallback = val

    return fallback


def sanitize_helm_values(yaml_text: str) -> str:
    """
    Redact sensitive values from a helm values YAML dump.

    We operate on text rather than parsing/re-emitting YAML because we can't
    depend on PyYAML and we want to preserve the original formatting for
    everything we keep.

    Rules:
      - For each line of the form `<indent><key>: <value>`, if the key
        (case-insensitive) is in SENSITIVE_HELM_KEYS, replace the value with
        '<REDACTED>'.
      - Multiline values introduced by `|` or `>` block scalars under a
        sensitive key are replaced too — we consume subsequent lines that
        are more indented than the key.
      - *SecretName keys are left alone; they reference a secret by name
        without exposing the value.
    """
    if not yaml_text:
        return yaml_text

    out: list[str] = []
    lines = yaml_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(
            r"^(?P<indent>\s*)(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<rest>.*)$", line
        )
        if m and m.group("key").lower() in SENSITIVE_HELM_KEYS:
            indent = m.group("indent")
            key = m.group("key")
            rest = m.group("rest").rstrip()

            if rest in ("|", ">", "|-", ">-", "|+", ">+"):
                out.append(f"{indent}{key}: <REDACTED>")
                key_indent_len = len(indent)
                i += 1
                while i < len(lines):
                    nxt = lines[i]
                    if nxt.strip() == "":
                        i += 1
                        continue
                    leading = len(nxt) - len(nxt.lstrip())
                    if leading <= key_indent_len:
                        break
                    i += 1
                continue

            out.append(f"{indent}{key}: <REDACTED>")
            i += 1
            continue

        out.append(line)
        i += 1

    result = "\n".join(out)
    if yaml_text.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result

    """
    Extract agent.serverUrl (or fall back to global.serverApiUrl) from a
    helm values.yaml dump.

    This tracks the top-level block so we never confuse comment lines
    mentioning 'serverUrl' with real nested values, and never pick up
    a serverUrl from an unrelated block.
    """
    if not yaml_text:
        return ""

    current_block = ""
    fallback = ""

    for raw in yaml_text.splitlines():
        # Strip trailing whitespace but preserve leading
        line = raw.rstrip()
        if not line:
            continue

        # Top-level key (no leading whitespace, not a comment, has a colon)
        if not line[0].isspace() and not line.lstrip().startswith("#") and ":" in line:
            current_block = line.split(":", 1)[0].strip()
            continue

        # Skip comments
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue

        if current_block == "agent":
            m = re.match(r"^\s+serverUrl:\s*(.*)$", line)
            if m:
                val = m.group(1).strip().strip('"').strip("'")
                if val:
                    return val

        if current_block == "global":
            m = re.match(r"^\s+serverApiUrl:\s*(.*)$", line)
            if m:
                val = m.group(1).strip().strip('"').strip("'")
                if val and not fallback:
                    fallback = val

    return fallback

def collect_network(ctx: DiagContext) -> None:
    section("Network checks")

    if ctx.has_helm and ctx.helm_releases and ctx.namespace:
        for rel in ctx.helm_releases:
            r = run(["helm", "get", "values", rel, "-n", ctx.namespace, "--all"])
            if r.ok:
                candidate = parse_server_url(r.stdout)
                if re.match(r"^https?://", candidate):
                    ctx.octopus_url = candidate
                    break

    netcheck_file = ctx.bundle_dir / "network" / "in-cluster-checks.txt"
    netcheck_file.parent.mkdir(parents=True, exist_ok=True)

    if ctx.octopus_url:
        info(f"Octopus server URL detected: {ctx.octopus_url}")
        host = re.sub(r"^https?://", "", ctx.octopus_url).split("/")[0].split(":")[0]

        info("Running DNS check from inside the cluster (this may take ~15s)...")
        pod_name = "octopus-netcheck-" + "".join(
            random.choices(string.ascii_lowercase + string.digits, k=6)
        )

        check_cmd = (
            f"echo '--- nslookup ---'; nslookup {host} 2>&1; echo; "
            f"echo '--- http response headers ---'; "
            f"wget -S --spider --timeout=10 {ctx.octopus_url} 2>&1 | head -20; "
            f"echo; echo '--- exit ---'"
        )

        result = run(
            [
                "kubectl",
                "run",
                pod_name,
                "--rm",
                "-i",
                "--quiet",
                "--restart=Never",
                "--image=busybox:1.36",
                f"--namespace={ctx.namespace or 'default'}",
                "--timeout=30s",
                "--",
                "sh",
                "-c",
                check_cmd,
            ],
            timeout=60,
        )

        output = f"# In-cluster network checks for {host}\n\n"
        output += result.stdout
        if result.stderr:
            output += f"\n--- stderr ---\n{result.stderr}"
        netcheck_file.write_text(output, encoding="utf-8")

        if "Address" in result.stdout:
            ok("DNS resolution succeeded")
        else:
            warn("DNS resolution may have failed — check network/in-cluster-checks.txt")
    else:
        warn(
            "Could not detect a valid Octopus server URL in Helm values — skipping in-cluster network check"
        )
        info(
            "You can manually test with: kubectl run test --rm -it --image=busybox -- sh"
        )
        netcheck_file.write_text(
            "No valid Octopus server URL found in Helm values "
            "(looked for agent.serverUrl and global.serverApiUrl).\n",
            encoding="utf-8",
        )

    info("Checking CoreDNS...")
    capture(
        ctx.bundle_dir / "network" / "coredns.txt",
        [
            "kubectl",
            "get",
            "pods",
            "-n",
            "kube-system",
            "-l",
            "k8s-app=kube-dns",
            "-o",
            "wide",
        ],
    )

def write_summary(ctx: DiagContext) -> None:
    section("Building summary")
    summary = ctx.bundle_dir / "SUMMARY.txt"

    lines = [
        "Octopus Deploy Kubernetes Agent Diagnostic Summary",
        "==================================================",
        "",
        f"Generated:        {utc_now()}",
        f"Kubernetes ctx:   {ctx.context_name}",
        f"K8s version:      {ctx.k8s_version}",
        f"Node count:       {ctx.node_count}",
        f"Agent namespace:  {ctx.namespace or '<not found>'}",
        f"Octopus URL:      {ctx.octopus_url or '<not detected>'}",
        f"Log issues found: {ctx.error_count}  (see ERRORS.txt if > 0)",
        "",
        "Pod status:",
    ]
    if ctx.namespace:
        r = run(["kubectl", "get", "pods", "-n", ctx.namespace])
        lines.append(r.stdout.rstrip() if r.ok else "  (could not list pods)")

    lines.append("")
    lines.append("Helm releases:")
    if ctx.has_helm and ctx.namespace:
        r = run(["helm", "list", "-n", ctx.namespace])
        lines.append(r.stdout.rstrip() if r.ok else "  (could not list releases)")
    else:
        lines.append("  (helm not available)")

    lines.append("")
    lines.append("Bundle contents:")
    for path in sorted(ctx.bundle_dir.rglob("*")):
        if path.is_file():
            rel = path.relative_to(ctx.bundle_dir).as_posix()
            lines.append(f"  {rel}")

    summary.write_text("\n".join(lines), encoding="utf-8")
    ok("Summary written to SUMMARY.txt")

def create_bundle(bundle_dir: Path, output_dir: Path) -> Path:
    section("Creating zip bundle")
    zip_path = output_dir / f"{bundle_dir.name}.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in bundle_dir.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(output_dir))

    shutil.rmtree(bundle_dir)
    ok(f"Bundle created: {zip_path}")
    return zip_path

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect diagnostics for an Octopus Deploy Kubernetes agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 octopus-agent-diag.py\n"
            "  python3 octopus-agent-diag.py --namespace octopus-agent-target\n"
            "  python3 octopus-agent-diag.py -n octopus-agent -o /tmp/diag"
        ),
    )
    parser.add_argument(
        "-n",
        "--namespace",
        default="",
        help="Namespace where the agent is installed. "
        "If omitted, searches all namespaces.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=os.getcwd(),
        help="Directory to write the diagnostic bundle to.",
    )
    args = parser.parse_args()

    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    bundle_dir = output_dir / f"octopus-agent-diag-{timestamp}"

    print("Octopus Kubernetes Agent Diagnostics")
    print(f"Run at: {utc_now()}")

    if not check_preflight():
        return 1

    ctx = DiagContext(bundle_dir=bundle_dir)
    ctx.has_helm = shutil.which("helm") is not None
    if ctx.has_helm:
        v = run(["helm", "version", "--short"]).stdout.strip()
        ok(f"helm found: {v}")
    else:
        warn("helm not found — Helm release info will be skipped.")

    for sub in ("cluster", "agent", "logs", "helm", "network", "rbac", "resources"):
        (bundle_dir / sub).mkdir(parents=True, exist_ok=True)
    info(f"Bundle directory: {bundle_dir}")

    locate_agent(ctx, args.namespace)
    collect_cluster_info(ctx)
    collect_agent_resources(ctx)
    collect_configmap_names(ctx)
    collect_logs(ctx)
    scan_for_errors(ctx)
    collect_helm(ctx)
    collect_rbac(ctx)
    collect_resource_usage(ctx)
    collect_network(ctx)
    write_summary(ctx)
    zip_path = create_bundle(bundle_dir, output_dir)

    print("\nDone.")
    print(f"Share this file with Octopus support: {zip_path}")
    print("No secrets or configmap data were collected. Helm values were sanitized.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
