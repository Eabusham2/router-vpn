#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("ai_help_provider.py")
spec = importlib.util.spec_from_file_location("ai_help_provider", MODULE)
ai = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(ai)


class FakeResponse:
    def __init__(self, payload: dict):
        self._raw = json.dumps(payload).encode()
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
    def read(self, size=-1): return self._raw if size < 0 else self._raw[:size]


class Clock:
    def __init__(self): self.value = 100.0
    def __call__(self): return self.value


class AIHelpProviderTests(unittest.TestCase):
    def make_key(self, mode=0o600):
        td = tempfile.TemporaryDirectory()
        path = Path(td.name) / "openai.key"
        path.write_text("sk-test-abcdefghijklmnopqrstuvwxyz0123456789\n", encoding="utf-8")
        path.chmod(mode)
        self.addCleanup(td.cleanup)
        return str(path)

    def test_real_openai_responses_request_is_server_side_bounded_and_not_stored(self):
        seen = {}
        def opener(request, timeout):
            seen["url"] = request.full_url
            seen["authorization"] = request.get_header("Authorization")
            seen["timeout"] = timeout
            seen["body"] = json.loads(request.data.decode())
            return FakeResponse({"output":[{"type":"message","content":[{"type":"output_text","text":"Use selected-node proof."}]}]})
        provider = ai.AIHelpProvider(model="test-model", key_file=self.make_key(), opener=opener)
        result = provider.ask("Why did connect fail?", context={"api_token":"SECRET","phase":"failed"}, client_id="192.168.50.2")
        self.assertEqual(result["answer"], "Use selected-node proof.")
        self.assertEqual(seen["url"], ai.OPENAI_RESPONSES_URL)
        self.assertTrue(seen["authorization"].startswith("Bearer sk-test-"))
        self.assertEqual(seen["body"]["model"], "test-model")
        self.assertIs(seen["body"]["store"], False)
        self.assertLessEqual(seen["body"]["max_output_tokens"], ai.MAX_OUTPUT_TOKENS)
        self.assertNotIn("SECRET", seen["body"]["input"])
        self.assertIn("[redacted]", seen["body"]["input"])
        self.assertNotIn("sk-test-", json.dumps(result))

    def test_key_file_must_be_private_regular_non_symlink(self):
        path = self.make_key(0o644)
        provider = ai.AIHelpProvider(model="test-model", key_file=path, opener=lambda *_a, **_k: None)
        with self.assertRaisesRegex(ai.AIHelpError, "permissions are too broad"):
            provider.ask("help")
        with tempfile.TemporaryDirectory() as td:
            target = Path(td)/"target"; target.write_text("sk-test-abcdefghijklmnopqrstuvwxyz0123456789") ; target.chmod(0o600)
            link = Path(td)/"link"; link.symlink_to(target)
            provider = ai.AIHelpProvider(model="test-model", key_file=str(link), opener=lambda *_a, **_k: None)
            with self.assertRaisesRegex(ai.AIHelpError, "must not be a symlink"):
                provider.ask("help")

    def test_provider_disabled_without_explicit_model(self):
        provider = ai.AIHelpProvider(model="", key_file=self.make_key())
        self.assertFalse(provider.status()["available"])
        with self.assertRaisesRegex(ai.AIHelpError, "AI_MODEL"):
            provider.ask("help")

    def test_question_and_context_are_bounded_and_secret_redacted(self):
        safe = ai.sanitize_context({"password":"pw","private_key":"key","nested":{"authorization":"Bearer abc","ok":"x"*9000}})
        self.assertNotIn("pw", safe)
        self.assertNotIn("Bearer abc", safe)
        self.assertLessEqual(len(safe), ai.MAX_CONTEXT_CHARS + len("…[context truncated]"))
        provider = ai.AIHelpProvider(model="m", key_file=self.make_key(), opener=lambda *_a, **_k: None)
        with self.assertRaisesRegex(ai.AIHelpError, "exceeds"):
            provider.ask("x" * (ai.MAX_QUESTION_CHARS + 1))

    def test_per_client_rate_limit(self):
        clock = Clock()
        def opener(*_args, **_kwargs): return FakeResponse({"output_text":"ok"})
        provider = ai.AIHelpProvider(model="m", key_file=self.make_key(), opener=opener, now=clock)
        for _ in range(ai.MAX_REQUESTS_PER_MINUTE):
            self.assertEqual(provider.ask("help", client_id="client")["answer"], "ok")
        with self.assertRaisesRegex(ai.AIHelpError, "rate limit"):
            provider.ask("help", client_id="client")
        clock.value += 61
        self.assertEqual(provider.ask("help", client_id="client")["answer"], "ok")

    def test_output_extraction_rejects_empty_payload(self):
        with self.assertRaisesRegex(ai.AIHelpError, "no text answer"):
            ai._extract_output_text({"output":[]})


if __name__ == "__main__":
    unittest.main()
