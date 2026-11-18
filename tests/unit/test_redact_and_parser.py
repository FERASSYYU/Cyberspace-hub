import unittest

from pbh.core.redact import redact
from pbh.parsers.json_parser import JsonSafetyError, parse_json, strip_jsonc_comments


class RedactTests(unittest.TestCase):
    def test_aws_style_key_is_removed(self):
        out = redact("id AKIA" + "A" * 16)
        self.assertNotIn("AKIA" + "A" * 16, out)
        self.assertIn("[REDACTED]", out)

    def test_password_assignment_value_is_removed(self):
        out = redact('{"password": "hunter2-lab"}')
        self.assertNotIn("hunter2-lab", out)

    def test_plain_text_is_unchanged(self):
        self.assertEqual(redact("nothing sensitive here"), "nothing sensitive here")


class JsonParserTests(unittest.TestCase):
    def test_duplicate_keys_are_rejected(self):
        with self.assertRaises(JsonSafetyError):
            parse_json('{"a": 1, "a": 2}')

    def test_depth_limit_is_enforced(self):
        deep = "[" * 80 + "]" * 80
        with self.assertRaises(JsonSafetyError):
            parse_json(deep)

    def test_jsonc_comments_are_removed_outside_strings(self):
        text = '{"url": "http://x//y", // note\n "b": 1 /* block */}'
        self.assertEqual(parse_json(strip_jsonc_comments(text)), {"url": "http://x//y", "b": 1})

    def test_unterminated_block_comment_fails(self):
        with self.assertRaises(JsonSafetyError):
            strip_jsonc_comments('{"a": 1 /* open')


if __name__ == "__main__":
    unittest.main()
