#!/usr/bin/env python3
"""
Unit tests for octopus-agent-diag.py.

Run with:
    python3 test_octopus_agent_diag.py
    python3 -m unittest test_octopus_agent_diag
"""

import importlib.util
import sys
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "octopus_agent_diag",
    Path(__file__).parent / "octopus-agent-diag.py",
)
_module = importlib.util.module_from_spec(_spec)
sys.modules["octopus_agent_diag"] = _module
_spec.loader.exec_module(_module)

parse_server_url = _module.parse_server_url
sanitize_helm_values = _module.sanitize_helm_values
ERROR_PATTERN = _module.ERROR_PATTERN
SENSITIVE_HELM_KEYS = _module.SENSITIVE_HELM_KEYS


class TestSanitizeHelmValues(unittest.TestCase):
    """Tests for Helm values sanitization.

    The critical property: no sensitive value from the input should appear
    anywhere in the output. We both check that specific values are gone
    AND that <REDACTED> appears where expected.
    """

    def assertNotInOutput(self, needle: str, output: str) -> None:
        self.assertNotIn(
            needle,
            output,
            f"Sensitive value {needle!r} leaked into sanitized output:\n{output}",
        )

    def test_redacts_bearer_token(self):
        yaml = """
agent:
  name: my-agent
  bearerToken: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret.signature
  serverUrl: https://octopus.example.com
"""
        out = sanitize_helm_values(yaml)
        self.assertNotInOutput(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret.signature", out
        )
        self.assertIn("bearerToken: <REDACTED>", out)
        self.assertIn("serverUrl: https://octopus.example.com", out)
        self.assertIn("name: my-agent", out)

    def test_redacts_server_api_key(self):
        yaml = """
agent:
  serverApiKey: API-ABCDEF123456GHIJKL
"""
        out = sanitize_helm_values(yaml)
        self.assertNotInOutput("API-ABCDEF123456GHIJKL", out)
        self.assertIn("serverApiKey: <REDACTED>", out)

    def test_redacts_password(self):
        yaml = """
agent:
  username: admin
  password: hunter2-is-a-bad-password
"""
        out = sanitize_helm_values(yaml)
        self.assertNotInOutput("hunter2-is-a-bad-password", out)
        self.assertNotInOutput("admin", out)
        self.assertIn("password: <REDACTED>", out)
        self.assertIn("username: <REDACTED>", out)

    def test_redacts_certificate(self):
        yaml = """
agent:
  certificate: MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBase64Blob
  serverCertificate: MIIDanotherBase64Blob
"""
        out = sanitize_helm_values(yaml)
        self.assertNotInOutput(
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBase64Blob", out
        )
        self.assertNotInOutput("MIIDanotherBase64Blob", out)
        self.assertIn("certificate: <REDACTED>", out)
        self.assertIn("serverCertificate: <REDACTED>", out)

    def test_redacts_block_scalar_certificate(self):
        """Certificates are often written as multi-line block scalars with |."""
        yaml = """agent:
  certificate: |
    -----BEGIN CERTIFICATE-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBLEAKY
    VERYSECRETCERTCONTENTMUSTBEREDACTED
    -----END CERTIFICATE-----
  serverUrl: https://octopus.example.com
"""
        out = sanitize_helm_values(yaml)
        self.assertNotInOutput(
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBLEAKY", out
        )
        self.assertNotInOutput("VERYSECRETCERTCONTENTMUSTBEREDACTED", out)
        self.assertNotInOutput("BEGIN CERTIFICATE", out)
        self.assertIn("certificate: <REDACTED>", out)
        self.assertIn("serverUrl: https://octopus.example.com", out)

    def test_preserves_secret_name_references(self):
        """*SecretName keys are pointers — they reveal nothing sensitive."""
        yaml = """
agent:
  bearerTokenSecretName: my-agent-auth
  serverApiKeySecretName: my-api-key-secret
  serverCertificateSecretName: my-cert-secret
"""
        out = sanitize_helm_values(yaml)
        self.assertIn("bearerTokenSecretName: my-agent-auth", out)
        self.assertIn("serverApiKeySecretName: my-api-key-secret", out)
        self.assertIn("serverCertificateSecretName: my-cert-secret", out)

    def test_redacts_nested_docker_auth_password(self):
        """Nested sensitive keys (dockerAuth.password) are still leaf keys."""
        yaml = """
agent:
  upgrade:
    dockerAuth:
      username: registry-user
      password: registry-password-do-not-leak
      registry: docker.io
"""
        out = sanitize_helm_values(yaml)
        self.assertNotInOutput("registry-password-do-not-leak", out)
        self.assertNotInOutput("registry-user", out)
        self.assertIn("password: <REDACTED>", out)
        self.assertIn("username: <REDACTED>", out)
        self.assertIn("registry: docker.io", out)

    def test_redacts_polling_proxy_password(self):
        yaml = """
agent:
  pollingProxy:
    host: proxy.example.com
    port: 8080
    username: proxy-user
    password: proxy-secret-password
"""
        out = sanitize_helm_values(yaml)
        self.assertNotInOutput("proxy-secret-password", out)
        self.assertNotInOutput("proxy-user", out)
        self.assertIn("host: proxy.example.com", out)
        self.assertIn("port: 8080", out)

    def test_empty_input(self):
        self.assertEqual(sanitize_helm_values(""), "")

    def test_no_sensitive_keys_passes_through(self):
        yaml = """
agent:
  name: my-agent
  serverUrl: https://octopus.example.com
  acceptEula: Y
  logLevel: Info
"""
        out = sanitize_helm_values(yaml)
        self.assertEqual(yaml, out)

    def test_case_insensitive_key_matching(self):
        """YAML keys are usually camelCase, but we shouldn't be fooled by case."""
        yaml = """
agent:
  BearerToken: case-variant-token
  PASSWORD: upper-case-password
"""
        out = sanitize_helm_values(yaml)
        self.assertNotInOutput("case-variant-token", out)
        self.assertNotInOutput("upper-case-password", out)

    def test_preserves_comments(self):
        yaml = """# This is a comment
agent:
  # -- The bearer token
  bearerToken: secret
  # -- The server URL
  serverUrl: https://octopus.example.com
"""
        out = sanitize_helm_values(yaml)
        self.assertIn("# This is a comment", out)
        self.assertIn("# -- The bearer token", out)
        self.assertIn("# -- The server URL", out)
        self.assertNotInOutput("bearerToken: secret", out)

    def test_realistic_full_values_dump(self):
        """End-to-end: a realistic helm get values output."""
        yaml = """USER-SUPPLIED VALUES:
agent:
  acceptEula: Y
  name: prod-agent
  serverUrl: https://octopus.example.com
  serverApiKey: API-REDACTMEPLZ1234567890
  bearerToken: ""
  certificate: |
    -----BEGIN CERTIFICATE-----
    ABCDEFGHIJKLMNOPQRSTUVWXYZ
    -----END CERTIFICATE-----
  space: Default
  upgrade:
    dockerAuth:
      username: docker-user
      password: docker-secret-pw
image:
  tag: "9.1.3703"
"""
        out = sanitize_helm_values(yaml)
        self.assertNotInOutput("API-REDACTMEPLZ1234567890", out)
        self.assertNotInOutput("ABCDEFGHIJKLMNOPQRSTUVWXYZ", out)
        self.assertNotInOutput("BEGIN CERTIFICATE", out)
        self.assertNotInOutput("docker-user", out)
        self.assertNotInOutput("docker-secret-pw", out)
        self.assertIn("name: prod-agent", out)
        self.assertIn("serverUrl: https://octopus.example.com", out)
        self.assertIn("acceptEula: Y", out)
        self.assertIn("space: Default", out)
        self.assertIn('tag: "9.1.3703"', out)


class TestParseServerUrl(unittest.TestCase):
    """Tests for the Helm values parser.

    This is the logic that the bash version got wrong. These cases all come
    from real-world scenarios or the original bug report.
    """

    def test_populated_agent_server_url(self):
        yaml = """
agent:
  name: my-agent
  acceptEula: Y
  serverUrl: https://octopus.example.com
  serverCommsAddress: https://octopus.example.com:10943
image:
  tag: "9.1.3703"
"""
        self.assertEqual(parse_server_url(yaml), "https://octopus.example.com")

    def test_empty_server_url_returns_empty(self):
        yaml = """
agent:
  name: ""
  serverUrl: ""
  serverCommsAddress: ""
"""
        self.assertEqual(parse_server_url(yaml), "")

    def test_comment_lines_mentioning_server_url_are_ignored(self):
        """Reproduces the production bug — comment lines mentioning serverUrl."""
        yaml = """
# Default values for kubernetes-agent.
# -- Override the name of the app
nameOverride: ""
agent:
  name: ""
  # -- The URL of the target Octopus Server to register this agent with
  # @section -- Agent values
  serverUrl: ""
"""
        self.assertEqual(parse_server_url(yaml), "")

    def test_falls_back_to_global_server_api_url(self):
        yaml = """
agent:
  name: ""
  serverUrl: ""
global:
  serverApiUrl: https://octopus-global.example.com
"""
        self.assertEqual(parse_server_url(yaml), "https://octopus-global.example.com")

    def test_quoted_url(self):
        yaml = """
agent:
  serverUrl: "https://octopus.example.com"
"""
        self.assertEqual(parse_server_url(yaml), "https://octopus.example.com")

    def test_single_quoted_url(self):
        yaml = """
agent:
  serverUrl: 'https://octopus.example.com'
"""
        self.assertEqual(parse_server_url(yaml), "https://octopus.example.com")

    def test_agent_takes_precedence_over_unrelated_blocks(self):
        """If some other block has a serverUrl key, we must not pick it up."""
        yaml = """
scriptPods:
  serverUrl: "https://should-not-match.com"
agent:
  serverUrl: "https://correct.com"
"""
        self.assertEqual(parse_server_url(yaml), "https://correct.com")

    def test_empty_input(self):
        self.assertEqual(parse_server_url(""), "")

    def test_whitespace_only_input(self):
        self.assertEqual(parse_server_url("   \n  \n"), "")

    def test_agent_takes_precedence_over_global_when_both_set(self):
        yaml = """
agent:
  serverUrl: https://agent-wins.example.com
global:
  serverApiUrl: https://global-loses.example.com
"""
        self.assertEqual(parse_server_url(yaml), "https://agent-wins.example.com")


class TestErrorPattern(unittest.TestCase):
    """Spot-check the error-scanning regex so we don't silently regress it."""

    def assert_matches(self, line: str, should_match: bool = True) -> None:
        actual = bool(ERROR_PATTERN.search(line))
        self.assertEqual(
            actual,
            should_match,
            f"Expected match={should_match} for: {line!r}",
        )

    def test_matches_error(self):
        self.assert_matches("2026-04-20T12:00:02Z ERROR connection refused")

    def test_matches_fatal(self):
        self.assert_matches("FATAL authentication failed: token expired")

    def test_matches_panic(self):
        self.assert_matches("runtime panic: segmentation violation")

    def test_matches_warning(self):
        self.assert_matches("WARN  retry attempt 1/5")

    def test_matches_crashloopbackoff(self):
        self.assert_matches("Pod is in CrashLoopBackOff state")

    def test_matches_imagepullbackoff(self):
        self.assert_matches("ImagePullBackOff: cannot pull image")

    def test_matches_oomkilled(self):
        self.assert_matches("Container was OOMKilled")

    def test_matches_forbidden(self):
        self.assert_matches('serviceaccount "x" is forbidden')

    def test_matches_unauthorized(self):
        self.assert_matches("401 Unauthorized")

    def test_matches_unauthorised_british(self):
        self.assert_matches("Request was unauthorised")

    def test_matches_connection_refused(self):
        self.assert_matches("dial tcp: connection refused")

    def test_ignores_terror_substring(self):
        self.assert_matches("The terror of legacy code", should_match=False)

    def test_ignores_word_warning_in_url(self):
        self.assert_matches(
            "Visit https://example.com/notawarnbutsimilar", should_match=False
        )

    def test_normal_info_line_does_not_match(self):
        self.assert_matches(
            "2026-04-20T12:00:00Z INFO Agent started", should_match=False
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
