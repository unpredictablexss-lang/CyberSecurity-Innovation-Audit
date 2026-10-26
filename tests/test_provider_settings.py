import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from src.workbench import agent
from src.workbench.api import create_app
from src.workbench.provider_settings import read_settings, record_provider_check, write_settings
from src.workbench.settings import Settings

HEADERS = {"x-ohscanner-client": "workbench-v1"}


class ProviderSettingsStoreTests(unittest.TestCase):
    def test_atomic_store_is_private_and_provider_config_reads_it(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            data_dir = Path(temp) / "data"
            settings = {"base_url": "https://api.example.invalid/v1", "model": "test-model",
                        "proxy_url": "", "api_key": "private-test-key"}
            write_settings(settings, data_dir)
            path = data_dir / "agent-provider.json"
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(data_dir.stat().st_mode), 0o700)
            loaded = read_settings(data_dir)
            self.assertEqual({key: loaded[key] for key in settings}, settings)
            self.assertTrue(loaded["config_revision"])
            self.assertIsNone(loaded["last_provider_check"])
            config = agent.ProviderConfig.from_env(data_dir)
            self.assertTrue(config.configured)
            self.assertEqual(config.api_key, "private-test-key")
            self.assertNotIn("private-test-key", json.dumps(config.public))

    def test_chat_protocol_round_trips_and_legacy_config_defaults_to_responses(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            data_dir = Path(temp) / "data"
            write_settings({"api_protocol": "openai-chat-completions",
                            "base_url": "https://api.example.invalid", "model": "chat-model",
                            "proxy_url": "", "api_key": "test-key"}, data_dir)
            loaded = read_settings(data_dir)
            self.assertEqual(loaded["api_protocol"], "openai-chat-completions")
            self.assertEqual(agent.ProviderConfig.from_env(data_dir).provider,
                             "openai-chat-completions")

            legacy_dir = Path(temp) / "legacy"
            legacy_dir.mkdir()
            (legacy_dir / "agent-provider.json").write_text(json.dumps({
                "base_url": "https://api.example.invalid/v1", "model": "legacy-model",
                "proxy_url": "", "api_key": "legacy-key",
            }), encoding="utf-8")
            if os.name == "posix":
                os.chmod(legacy_dir / "agent-provider.json", 0o600)
            self.assertEqual(read_settings(legacy_dir)["api_protocol"], "openai-responses")
            self.assertEqual(agent.ProviderConfig.from_env(legacy_dir).provider, "openai-responses")

    def test_environment_provider_is_authoritative_over_local_file(self):
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp) / "data"
            write_settings({"base_url": "https://file.example.invalid/v1", "model": "file-model",
                            "proxy_url": "", "api_key": "file-secret"}, data_dir)
            os.chmod(data_dir / "agent-provider.json", 0o644)
            with patch.dict(os.environ, {
                    "OHSCANNER_LLM_API_PROTOCOL": "openai-chat-completions",
                    "OHSCANNER_LLM_BASE_URL": "https://env.example.invalid/v1",
                    "OHSCANNER_LLM_MODEL": "env-model",
                    "OHSCANNER_LLM_API_KEY": "env-secret"}, clear=True):
                config = agent.ProviderConfig.from_env(data_dir)
            self.assertTrue(config.configured)
            self.assertEqual(config.provider, "openai-chat-completions")
            self.assertEqual(config.model, "env-model")
            self.assertEqual(config.endpoint_host, "env.example.invalid")
            self.assertEqual(config.api_key, "env-secret")

    def test_insecure_file_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp) / "data"
            write_settings({"base_url": "https://api.example.invalid/v1", "model": "m",
                            "proxy_url": "", "api_key": "secret"}, data_dir)
            os.chmod(data_dir / "agent-provider.json", 0o644)
            with self.assertRaisesRegex(ValueError, "权限不安全"):
                read_settings(data_dir)

    def test_probe_record_is_bound_to_the_exact_local_configuration(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            data_dir = Path(temp) / "data"
            first = {"base_url": "https://api.example.invalid/v1", "model": "model-a",
                     "proxy_url": "", "api_key": "secret-a"}
            write_settings(first, data_dir)
            provider = agent.ProviderConfig.from_env(data_dir)
            write_settings({**first, "model": "model-b", "api_key": "secret-b"}, data_dir)
            recorded = record_provider_check(data_dir, provider, {
                "model": "model-a", "endpoint_host": "api.example.invalid", "duration_ms": 1,
                "usage": {"input_tokens": 2, "output_tokens": 3},
                "response_sha256": "a" * 64,
            })
            self.assertIsNone(recorded)
            current = read_settings(data_dir)
            self.assertEqual(current["model"], "model-b")
            self.assertEqual(current["api_key"], "secret-b")
            self.assertIsNone(current["last_provider_check"])


class ProviderSettingsApiTests(unittest.TestCase):
    def test_mimo_token_plan_endpoint_is_rejected_without_saving_credentials(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            app = create_app(Settings(root / "data", (root / "targets",)))
            with TestClient(app) as client:
                response = client.post("/api/v1/agent/provider-settings", headers=HEADERS, json={
                    "base_url": "https://token-plan-cn.xiaomimimo.com/v1",
                    "model": "mimo-v2.6-pro", "proxy_url": "", "api_key": "tp-test-secret"})
            self.assertEqual(response.status_code, 409, response.text)
            self.assertIn("not permitted", response.json()["detail"])
            self.assertNotIn("tp-test-secret", response.text)
            self.assertFalse((root / "data" / "agent-provider.json").exists())

    def test_save_status_probe_and_clear_never_return_the_key(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            app = create_app(Settings(root / "data", (root / "targets",)))
            with TestClient(app) as client:
                headers = HEADERS
                status = client.get("/api/v1/agent/provider-settings")
                self.assertFalse(status.json()["configured"])
                self.assertNotIn("api_key", status.json())
                self.assertIsNone(status.json()["last_provider_check"])
                saved = client.post("/api/v1/agent/provider-settings", headers=headers, json={
                    "api_protocol": "openai-chat-completions",
                    "base_url": "https://api.example.invalid/v1", "model": "test-model",
                    "proxy_url": "", "api_key": "private-test-key"})
                self.assertEqual(saved.status_code, 200, saved.text)
                self.assertTrue(saved.json()["configured"])
                self.assertTrue(saved.json()["api_key_configured"])
                self.assertEqual(saved.json()["api_protocol"], "openai-chat-completions")
                self.assertNotIn("private-test-key", saved.text)
                self.assertNotIn("api_key", saved.json())
                with patch("src.workbench.agent.provider_connectivity_check", return_value={
                        "ok": True, "provider": "openai-responses", "model": "test-model",
                        "endpoint_host": "api.example.invalid", "duration_ms": 2,
                        "usage": {"input_tokens": 3, "output_tokens": 4},
                        "response_sha256": "a" * 64, "source_sent": False,
                        "operation_created": False, "disclaimer": "connectivity only"}) as probe:
                    checked = client.post("/api/v1/agent/provider-check", headers=headers,
                                          json={"confirm_no_source_request": True})
                self.assertEqual(checked.status_code, 200, checked.text)
                self.assertFalse(checked.json()["source_sent"])
                self.assertTrue(checked.json()["probe_persisted"])
                self.assertTrue(checked.json()["checked_at"])
                self.assertEqual(probe.call_args.kwargs["config"].api_key, "private-test-key")
                refreshed = client.get("/api/v1/agent/provider-settings").json()
                investigation_status = client.get("/api/v1/agent/status").json()
                self.assertEqual(investigation_status["last_provider_check"]["model"], "test-model")
                self.assertEqual(investigation_status["last_provider_check"]["endpoint_host"], "api.example.invalid")
                self.assertNotIn("private-test-key", json.dumps(investigation_status))
                self.assertEqual(refreshed["last_provider_check"]["model"], "test-model")
                self.assertEqual(refreshed["api_protocol"], "openai-chat-completions")
                self.assertEqual(refreshed["last_provider_check"]["endpoint_host"], "api.example.invalid")
                self.assertNotIn("api_key", refreshed["last_provider_check"])
                check_file = root / "data" / "agent-provider-check.json"
                self.assertEqual(stat.S_IMODE(check_file.stat().st_mode), 0o600)
                serialized_check = check_file.read_text(encoding="utf-8")
                self.assertNotIn("private-test-key", serialized_check)
                self.assertNotIn("response_sha256", serialized_check)
                resaved = client.post("/api/v1/agent/provider-settings", headers=headers, json={
                    "base_url": "https://api.example.invalid/v1", "model": "test-model-v2",
                    "proxy_url": "", "api_key": ""})
                self.assertEqual(resaved.status_code, 200, resaved.text)
                self.assertIsNone(resaved.json()["last_provider_check"])
                cleared = client.post("/api/v1/agent/provider-settings/clear", headers=headers, json={})
                self.assertEqual(cleared.status_code, 200, cleared.text)
                self.assertFalse(cleared.json()["configured"])
                self.assertFalse(cleared.json()["api_key_configured"])
                self.assertIsNone(cleared.json()["last_provider_check"])
                self.assertNotIn("private-test-key", cleared.text)

    def test_environment_managed_provider_cannot_be_overwritten_from_panel(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
                "OHSCANNER_LLM_MODEL": "env-model", "OHSCANNER_LLM_API_KEY": "env-secret"}, clear=True):
            root = Path(temp)
            app = create_app(Settings(root / "data", (root / "targets",)))
            with TestClient(app) as client:
                view = client.get("/api/v1/agent/provider-settings").json()
                self.assertFalse(view["editable"])
                response = client.post("/api/v1/agent/provider-settings", headers=HEADERS, json={
                    "base_url": "https://api.example.invalid/v1", "model": "other-model",
                    "api_key": "new-secret"})
                self.assertEqual(response.status_code, 409)
                self.assertFalse((root / "data" / "agent-provider.json").exists())

    def test_environment_probe_is_not_attached_to_local_settings(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
                "OHSCANNER_LLM_BASE_URL": "https://env.example.invalid/v1",
                "OHSCANNER_LLM_MODEL": "env-model", "OHSCANNER_LLM_API_KEY": "env-secret"}, clear=True):
            root = Path(temp)
            app = create_app(Settings(root / "data", (root / "targets",)))
            with TestClient(app) as client, patch("src.workbench.agent.provider_connectivity_check", return_value={
                    "ok": True, "provider": "openai-responses", "model": "env-model",
                    "endpoint_host": "env.example.invalid", "duration_ms": 1,
                    "usage": {"input_tokens": 2, "output_tokens": 3}, "source_sent": False,
                    "operation_created": False}):
                checked = client.post("/api/v1/agent/provider-check", headers=HEADERS,
                                      json={"confirm_no_source_request": True})
                self.assertEqual(checked.status_code, 200, checked.text)
                self.assertFalse(checked.json()["probe_persisted"])
                self.assertIsNone(client.get("/api/v1/agent/provider-settings").json()["last_provider_check"])
                self.assertFalse((root / "data" / "agent-provider-check.json").exists())


if __name__ == "__main__":
    unittest.main()
