# Octopus Kubernetes agent diagnostics

A single-file Python tool that gathers everything you need to troubleshoot an
Octopus Deploy Kubernetes agent. Runs in any environment where you have
`kubectl` configured — local, AKS, EKS, GKE, on-premises, anywhere.

## When to use this tool

Use this whenever an Octopus Deploy Kubernetes agent isn't behaving - it won't connect or register, its pods are unhealthy (CrashLoopBackOff, ImagePullBackOff, Pending, or constant restarts), or deployments are failing in a way that points at the agent itself. Run it as the first step in troubleshooting, or whenever support asks for diagnostics: one command collects the logs, events, connectivity checks, and config into a single zip, so whoever looks at the problem has everything they need up front. It's scoped to the Kubernetes agent, so it won't help with Tentacle targets, the Octopus Server itself, or a point-in-time issue that needs live monitoring rather than a snapshot.

This tool is read-only - it inspects your cluster and writes a local zip. It never modifies, deletes, or reconfigures anything, and the collected data stays on your machine until you choose to share it.

## What it collects

- Pod status, events, and last 5,000 lines of logs (including previous logs if a pod has restarted)
- An `ERRORS.txt` that greps all collected logs for common failure keywords (error, fatal, panic, denied, timeout, CrashLoopBackOff, etc.) — the fastest way to find where something went wrong
- Helm release info: values and manifest (redacted, best-effort — see below), plus history
- Cluster version and node info
- Resource usage (if metrics-server is available)
- RBAC: service accounts, roles, rolebindings, cluster-scoped RBAC
- Secret and ConfigMap **names** only (no data, no metadata)
- Network checks from inside the cluster: DNS resolution, plus HTTP response headers only (no response body)
- A `SUMMARY.txt` at the top of the bundle so support can get oriented in seconds

Output is a single `.zip` that you can attach to a support ticket.

## What it does NOT collect

The tool minimizes sensitive data in the bundle, but redaction is best-effort — **review the bundle before sharing** if your environment may hold secrets in unusual places. What it deliberately leaves out:

- **Secret data** — not collected. We list secret names only, so support can confirm expected secrets exist.
- **ConfigMap data** — not collected. We list configmap names and labels only.
- **Secret manifests** — for any `Secret` object in the rendered manifest, the whole `data:`/`stringData:` block is redacted regardless of key name, so arbitrary or chart-defined secret keys can't leak.
- **Sensitive Helm values** — these keys are replaced with `<REDACTED>` before the values file is written: `bearerToken`, `serverApiKey`, `serverAccessToken`, `username`, `password`, `certificate`, `serverCertificate`. This applies to nested occurrences (like `agent.upgrade.dockerAuth.password`) and multi-line certificate blocks.
- **Inline env-var secrets** — an env var whose name looks sensitive (contains `token`, `password`, `key`, `secret`, `cert`, etc.) has its `value:` redacted in both the values file and the manifest, including multi-line cert/key blocks. `valueFrom:` secret references are preserved (they name a secret without exposing it).
- **HTTP response bodies** — the network check uses `wget --spider` to capture response headers only, so if your Octopus server returns anything sensitive in an error response, it won't end up in the bundle.

Helm values containing `*SecretName` keys (e.g. `bearerTokenSecretName: my-agent-auth`) are preserved because they reference a secret by name without exposing the value.

> **Note:** pod logs are collected as-is and are not sanitized. If an application logs a token or connection string, it will be in the bundle. The review step matters most for `logs/` and the per-pod `describe` output.

## Prerequisites

- **kubectl**, configured for the cluster where the agent is installed
- **helm** (optional, but recommended — the tool falls back gracefully without it)
- For the pre-built binaries: nothing else. For running from source: Python 3.8+.

## Running it

### Option 1: Download the binary (recommended)

Grab the latest release from the [Releases page](../../releases/latest) and run it. No Python install required.

```bash
# Linux x86_64
curl -sSLO https://github.com/OctopusDeploy/kubernetes-agent-diagnostics/releases/latest/download/octopus-agent-diag-linux-amd64
chmod +x octopus-agent-diag-linux-amd64
./octopus-agent-diag-linux-amd64
```

```bash
# macOS (Apple Silicon)
curl -sSLO https://github.com/OctopusDeploy/kubernetes-agent-diagnostics/releases/latest/download/octopus-agent-diag-macos-arm64
chmod +x octopus-agent-diag-macos-arm64
xattr -d com.apple.quarantine ./octopus-agent-diag-macos-arm64
./octopus-agent-diag-macos-arm64
```

```powershell
# Windows
Invoke-WebRequest -Uri https://github.com/OctopusDeploy/kubernetes-agent-diagnostics/releases/latest/download/octopus-agent-diag-windows-amd64.exe -OutFile octopus-agent-diag.exe
.\octopus-agent-diag.exe
```

Available platforms: `linux-amd64`, `linux-arm64`, `macos-arm64`, `windows-amd64`.

Each release includes a `SHA256SUMS.txt` to verify integrity:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

### Option 2: Run from source (Python 3.8+)

If you have Python installed, you can run the script directly without a binary:

```bash
curl -sSL https://raw.githubusercontent.com/OctopusDeploy/kubernetes-agent-diagnostics/main/octopus-agent-diag.py | python3 -
```

Or download and run:

```bash
curl -sSLO https://raw.githubusercontent.com/OctopusDeploy/kubernetes-agent-diagnostics/main/octopus-agent-diag.py
python3 octopus-agent-diag.py
```

### Command-line options

```
Options:
  -n, --namespace NS   Namespace where the agent is installed.
                       If omitted, searches all namespaces.
  -o, --output DIR     Directory to write the diagnostic bundle to.
                       Default: current directory.
```

With a specific namespace:

```bash
./octopus-agent-diag-linux-amd64 --namespace octopus-agent-target
```

## What you get

A zip named `octopus-agent-diag-<timestamp>.zip` with this structure:

```
octopus-agent-diag-20260420-143022/
├── SUMMARY.txt                       # Quick orientation for support
├── ERRORS.txt                        # Grep of logs + events for errors/warnings
├── agent/
│   ├── all-resources.txt
│   ├── all-resources.yaml
│   ├── events.txt
│   ├── pod-<n>.txt                # describe output per pod
│   └── top-pods.txt
├── cluster/
│   ├── nodes.txt
│   ├── nodes-describe.txt
│   ├── top-nodes.txt
│   └── version.txt
├── helm/
│   ├── releases.txt
│   ├── <release>-values.yaml         # sensitive values redacted (best-effort)
│   ├── <release>-manifest.yaml       # Secret data + inline env secrets redacted
│   └── <release>-history.txt
├── logs/
│   ├── <pod>_<container>.log
│   └── <pod>_<container>_previous.log  # only if the container has restarted
├── network/
│   ├── in-cluster-checks.txt         # nslookup + response headers only
│   └── coredns.txt
├── rbac/
│   ├── serviceaccounts.yaml
│   ├── roles.yaml
│   ├── rolebindings.yaml
│   ├── clusterroles-all.yaml
│   ├── clusterrolebindings-all.yaml
│   └── secret-names.txt              # names only, no data
└── resources/
    ├── deployments.yaml
    ├── statefulsets.yaml
    ├── daemonsets.yaml
    ├── services.yaml
    ├── persistentvolumeclaims.yaml
    └── configmaps-names.txt          # names and labels only, no data
```

## Troubleshooting the tool itself

- **"No Octopus agent pods found"** — the tool looks for pods with the label `app.kubernetes.io/name=octopus-agent`. If your agent uses a different label or has been customized, pass `--namespace` explicitly.
- **"Cannot reach the Kubernetes cluster"** — check your kubeconfig. Run `kubectl cluster-info` and confirm you're pointed at the right cluster.
- **"metrics-server not available"** — that's fine, it's optional. `kubectl top` data will be skipped and the rest of the bundle is unaffected.
- **"Could not detect a valid Octopus server URL"** — this happens when Helm values don't have `agent.serverUrl` set (for example, when auth uses a referenced secret instead). The rest of the bundle is unaffected; you can run a manual DNS check with `kubectl run test --rm -it --image=busybox -- sh`.

## Development

### Running the tests

```bash
python3 test_octopus_agent_diag.py
```

The test suite covers the Helm values parser, both sanitizers (values and
manifest) including inline env-var and block-scalar redaction, and the
error-scanning regex. Secret-redaction tests plant a known string and assert
it's absent from the output. No external dependencies — runs on stock
Python 3.8+.

### Building a binary locally

```bash
./build.sh
```

This creates a single-file executable in `./dist/` for your current platform.
PyInstaller can't cross-compile, so for multi-platform releases use the
GitHub Actions workflow.

### Releasing

Push a version tag to trigger the release workflow:

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions will:

1. Run the test suite.
2. Build a binary for each of the four platforms (Linux amd64/arm64, macOS arm64, Windows amd64).
3. Generate SHA256 checksums.
4. Create a GitHub Release with all binaries attached.

### Project layout

- `octopus-agent-diag.py` — the tool (single file, stdlib only)
- `test_octopus_agent_diag.py` — unit tests
- `build.sh` — local PyInstaller build script
- `.github/workflows/release.yml` — CI pipeline that builds binaries on version tags
- `README.md` — you are here

Happy deployments!