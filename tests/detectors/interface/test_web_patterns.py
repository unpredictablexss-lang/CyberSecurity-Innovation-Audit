import unittest
from src.ohscanner.detectors.interface.web_patterns import review_patterns

class WebPatternTests(unittest.TestCase):
    def test_bridge_nonliteral(self):
        self.assertEqual(review_patterns('controller.runJavaScript("alert(" + input + ")");', 'bridge'), [(1, 'bridge.nonliteral-script')])
    def test_bridge_constant_control(self):
        self.assertEqual(review_patterns('controller.runJavaScript("document.title");', 'bridge'), [])
    def test_comments_and_quoted_code(self):
        text = '// x.runJavaScript(input)\nconst s = "x.runJavaScript(input)"; /* x.fileAccess(true) */'
        self.assertEqual(review_patterns(text, 'bridge'), [])
        self.assertEqual(review_patterns(text, 'disclosure'), [])
    def test_url_prefix(self):
        self.assertEqual(review_patterns('url.startsWith("https://trusted.example")', 'url'), [(1, 'url.raw-string-allowlist-review')])
    def test_url_parsed_control(self):
        self.assertEqual(review_patterns('u.hostname === "trusted.example" && u.protocol === "https:"', 'url'), [])
    def test_non_url_prefix(self):
        self.assertEqual(review_patterns('name.startsWith("prefix")', 'url'), [])
    def test_file_access_and_fixed_control(self):
        self.assertEqual(review_patterns('Web({}).fileAccess(true)', 'disclosure'), [(1, 'disclosure.local-file-access-enabled')])
        self.assertEqual(review_patterns('Web({}).fileAccess(false)', 'disclosure'), [])
    def test_mixed_mode(self):
        self.assertEqual(review_patterns('Web({}).mixedMode(MixedMode.All)', 'disclosure'), [(1, 'disclosure.mixed-content-enabled')])
        self.assertEqual(review_patterns('Web({}).mixedMode(MixedMode.None)', 'disclosure'), [])
    def test_multiline_and_nested_args(self):
        self.assertEqual(review_patterns('x.\nrunJavaScript(build(a, b), callback)', 'bridge'), [(2, 'bridge.nonliteral-script')])
    def test_incomplete_call_withheld(self):
        self.assertEqual(review_patterns('x.runJavaScript(', 'bridge'), [])
