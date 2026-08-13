#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("ai_help_provider.py")
spec = importlib.util.spec_from_file_location("ai_help_provider", MODULE)
ai = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(ai)


class FakeResponse:
    def __init__(self, payload: dict): self._raw = json.dumps(payload).encode()
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
    def read(self, size=-1): return self._raw if size < 0 else self._raw[:size]


class Clock:
    def __init__(self): self.value = 100.0
    def __call__(self): return self.value


class AIHelpProviderTests(unittest.TestCase):
    def make_private(self, name: str, value: str, mode=0o600):
        td = tempfile.TemporaryDirectory()
        path = Path(td.name) / name
        path.write_text(value + "\n", encoding="utf-8")
        path.chmod(mode)
        self.addCleanup(td.cleanup)
        return str(path)

    def make_key(self, mode=0o600):
        return self.make_private("openai.key", "sk-test-abcdefghijklmnopqrstuvwxyz0123456789", mode)

    def make_model(self, value="test-model", mode=0o600):
        return self.make_private("openai-model", value, mode)

    def test_responses_request_is_server_side_bounded_redacted_and_not_stored(self):
        seen = {}
        def opener(request, timeout):
            seen["url"] = request.full_url; seen["authorization"] = request.get_header("Authorization")
            seen["timeout"] = timeout; seen["body"] = json.loads(request.data.decode())
            return FakeResponse({"output":[{"type":"message","content":[{"type":"output_text","text":"Use selected-node proof."}]}]})
        provider = ai.AIHelpProvider(model="test-model", key_file=self.make_key(), opener=opener)
        result = provider.ask("Why did connect fail?", context={"api_token":"SECRET","phase":"failed"}, client_id="192.168.50.2")
        self.assertEqual(result["answer"], "Use selected-node proof.")
        self.assertEqual(seen["url"], ai.OPENAI_RESPONSES_URL)
        self.assertTrue(seen["authorization"].startswith("Bearer sk-test-"))
        self.assertIs(seen["body"]["store"], False)
        self.assertNotIn("SECRET", seen["body"]["input"])
        self.assertNotIn("sk-test-", json.dumps(result))

    def test_model_can_come_from_private_file_without_compose_env(self):
        provider = ai.AIHelpProvider(model=None, model_file=self.make_model("gpt-test.1"), key_file=self.make_key(), opener=lambda *_a, **_k: FakeResponse({"output_text":"ok"}))
        self.assertEqual(provider.model, "gpt-test.1")
        self.assertTrue(provider.status()["available"])
        self.assertEqual(provider.ask("help")["answer"], "ok")

    def test_key_and_model_files_must_be_private(self):
        provider = ai.AIHelpProvider(model="test-model", key_file=self.make_key(0o644), opener=lambda *_a, **_k: None)
        with self.assertRaisesRegex(ai.AIHelpError, "permissions are too broad"): provider.ask("help")
        with self.assertRaisesRegex(ai.AIHelpError, "permissions are too broad"):
            ai.AIHelpProvider(model=None, model_file=self.make_model(mode=0o644), key_file=self.make_key())

    def test_symlink_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td)/"target"; target.write_text("sk-test-abcdefghijklmnopqrstuvwxyz0123456789"); target.chmod(0o600)
            link = Path(td)/"link"; link.symlink_to(target)
            provider = ai.AIHelpProvider(model="test-model", key_file=str(link), opener=lambda *_a, **_k: None)
            with self.assertRaisesRegex(ai.AIHelpError, "must not be a symlink"): provider.ask("help")

    def test_disabled_without_model(self):
        provider = ai.AIHelpProvider(model="", key_file=self.make_key())
        self.assertFalse(provider.status()["available"])
        with self.assertRaisesRegex(ai.AIHelpError, "not configured"): provider.ask("help")

    def test_invalid_model_name_fails_closed(self):
        with self.assertRaisesRegex(ai.AIHelpError, "unsupported characters"):
            ai.AIHelpProvider(model="bad model; rm -rf /", key_file=self.make_key())
        with self.assertRaisesRegex(ai.AIHelpError, "unsupported characters"):
            ai.AIHelpProvider(model=None, model_file=self.make_model("bad model"), key_file=self.make_key())

    def test_question_context_bounds_and_rate_limit(self):
        safe = ai.sanitize_context({"password":"pw","private_key":"key","nested":{"authorization":"Bearer abc","ok":"x"*9000}})
        self.assertNotIn("Bearer abc", safe)
        provider = ai.AIHelpProvider(model="m", key_file=self.make_key(), opener=lambda *_a, **_k: FakeResponse({"output_text":"ok"}), now=Clock())
        with self.assertRaisesRegex(ai.AIHelpError, "exceeds"): provider.ask("x" * (ai.MAX_QUESTION_CHARS + 1))
        for _ in range(ai.MAX_REQUESTS_PER_MINUTE): provider.ask("help", client_id="client")
        with self.assertRaisesRegex(ai.AIHelpError, "rate limit"): provider.ask("help", client_id="client")

    def test_empty_provider_output_rejected(self):
        with self.assertRaisesRegex(ai.AIHelpError, "no text answer"): ai._extract_output_text({"output":[]})


if __name__ == "__main__": unittest.main()
