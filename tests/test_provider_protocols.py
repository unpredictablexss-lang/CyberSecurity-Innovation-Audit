import hashlib
import json
import unittest

from src.workbench.agent import ResponsesClient, ProviderConfig


class _Response:
    status = 200

    def __init__(self, body):
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size):
        return self.body


class _Opener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        return _Response(self.responses.pop(0))


class ChatCompletionsAdapterTests(unittest.TestCase):
    def test_protocol_is_bound_into_provider_consent_fingerprint(self):
        responses = ProviderConfig("https://api.example.invalid/v1", "test-model", "test-key",
                                   provider="openai-responses")
        chat = ProviderConfig("https://api.example.invalid/v1", "test-model", "test-key",
                              provider="openai-chat-completions")
        self.assertNotEqual(responses.fingerprint, chat.fingerprint)

    def test_tool_call_round_trip_uses_compatible_chat_messages(self):
        config = ProviderConfig("https://api.example.invalid/v1", "test-model", "test-key",
                                provider="openai-chat-completions")
        client = ResponsesClient(config)
        opener = _Opener([
            {"id": "chat-1", "choices": [{"message": {"role": "assistant", "content": None,
                "tool_calls": [{"id": "call-1", "type": "function", "function": {
                    "name": "read_fixed_source_range",
                    "arguments": '{"file":"src/a.cpp","start_line":4,"line_count":2}'}}]},
                "finish_reason": "tool_calls"}],
             "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}},
            {"id": "chat-2", "choices": [{"message": {"role": "assistant",
                "content": '{"status":"ok"}', "tool_calls": None}, "finish_reason": "stop"}],
             "usage": {"prompt_tokens": 22, "completion_tokens": 3, "total_tokens": 25}},
        ])
        client.opener = opener
        tools = [{"type": "function", "name": "read_fixed_source_range",
                  "description": "Read fixed source", "parameters": {
                      "type": "object", "properties": {"file": {"type": "string"}},
                      "required": ["file"], "additionalProperties": False}}]
        first = client.create({"model": "test-model", "instructions": "Read only.",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "Inspect this."}]}],
            "store": False, "max_output_tokens": 128, "tools": tools,
            "tool_choice": "auto", "parallel_tool_calls": False})
        self.assertEqual(first["status"], "completed")
        self.assertEqual(first["output"][0]["type"], "function_call")
        self.assertEqual(first["output"][0]["call_id"], "call-1")
        self.assertEqual(first["usage"]["input_tokens"], 10)

        second = client.create({"model": "test-model", "instructions": "Read only.",
            "input": [
                {"role": "user", "content": [{"type": "input_text", "text": "Inspect this."}]},
                *first["output"],
                {"type": "function_call_output", "call_id": "call-1", "output": '{"evidence_id":"ev-1"}'},
            ], "tools": tools, "tool_choice": "auto"})
        self.assertEqual(second["status"], "completed")
        self.assertEqual(second["output"][0]["content"][0]["text"], '{"status":"ok"}')

        request, _ = opener.requests[0]
        self.assertEqual(request.full_url, "https://api.example.invalid/v1/chat/completions")
        first_body = json.loads(request.data)
        self.assertEqual(first_body["max_tokens"], 128)
        self.assertEqual(first_body["messages"][0]["role"], "system")
        self.assertEqual(first_body["tools"][0]["function"]["name"], "read_fixed_source_range")
        self.assertNotIn("strict", first_body["tools"][0]["function"])
        self.assertIs(first_body["parallel_tool_calls"], False)
        self.assertEqual(first["_ohscanner_wire_request_sha256"], hashlib.sha256(request.data).hexdigest())
        second_body = json.loads(opener.requests[1][0].data)
        self.assertEqual(second_body["messages"][-2]["tool_calls"][0]["id"], "call-1")
        self.assertEqual(second_body["messages"][-1]["tool_call_id"], "call-1")
        self.assertEqual(second_body["messages"][-1]["role"], "tool")

    def test_schema_output_maps_to_json_mode_and_keeps_schema_in_system_instruction(self):
        config = ProviderConfig("https://api.example.invalid", "test-model", "test-key",
                                provider="openai-chat-completions")
        client = ResponsesClient(config)
        opener = _Opener([{"choices": [{"message": {"role": "assistant", "content": '{"ok":true}'},
                                         "finish_reason": "stop"}]}])
        client.opener = opener
        schema = {"type": "object", "properties": {"ok": {"type": "boolean"}},
                  "required": ["ok"], "additionalProperties": False}
        result = client.create({"model": "test-model", "instructions": "Return JSON.",
            "input": "Check only.", "store": False,
            "text": {"format": {"type": "json_schema", "name": "probe", "strict": True,
                                 "schema": schema}}})
        body = json.loads(opener.requests[0][0].data)
        self.assertEqual(opener.requests[0][0].full_url, "https://api.example.invalid/chat/completions")
        self.assertEqual(body["response_format"], {"type": "json_object"})
        self.assertIn(json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                      body["messages"][0]["content"])
        self.assertEqual(result["status"], "completed")

    def test_malformed_tool_call_and_missing_chat_choices_fail_closed(self):
        config = ProviderConfig("https://api.example.invalid", "test-model", "test-key",
                                provider="openai-chat-completions")
        client = ResponsesClient(config)
        client.opener = _Opener([{"choices": [{"message": {"role": "assistant", "content": None,
            "tool_calls": [{"id": "", "function": {"name": "x", "arguments": "{}"}}]},
            "finish_reason": "tool_calls"}] }])
        with self.assertRaisesRegex(ValueError, "invalid function call"):
            client.create({"model": "test-model", "input": "probe"})

        client.opener = _Opener([{"choices": []}])
        with self.assertRaisesRegex(ValueError, "Chat Completions shape"):
            client.create({"model": "test-model", "input": "probe"})

        client.opener = _Opener([{"choices": [{"message": {"role": "assistant", "content": None},
                                                  "finish_reason": "stop"}]}])
        with self.assertRaisesRegex(ValueError, "did not include assistant content"):
            client.create({"model": "test-model", "input": "probe"})

    def test_invalid_parallel_setting_and_non_function_tool_response_fail_closed(self):
        config = ProviderConfig("https://api.example.invalid", "test-model", "test-key",
                                provider="openai-chat-completions")
        client = ResponsesClient(config)
        opener = _Opener([])
        client.opener = opener
        with self.assertRaisesRegex(ValueError, "parallel tool setting"):
            client.create({"model": "test-model", "input": "probe", "tools": [],
                           "parallel_tool_calls": "false"})
        self.assertEqual(opener.requests, [])

        client.opener = _Opener([{"choices": [{"message": {"role": "assistant", "content": None,
            "tool_calls": [{"id": "call-1", "type": "custom", "function": {
                "name": "read_fixed_source_range", "arguments": "{}"}}]},
            "finish_reason": "tool_calls"}]}])
        with self.assertRaisesRegex(ValueError, "invalid function call"):
            client.create({"model": "test-model", "input": "probe"})


if __name__ == "__main__":
    unittest.main()
