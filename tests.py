import unittest

from headershield import evaluate


class HeaderShieldTests(unittest.TestCase):
    def test_baseline_headers_score_higher_than_empty_response(self):
        empty_score, _ = evaluate("https://example.test", {})
        secure_score, findings = evaluate("https://example.test", {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        })
        self.assertGreater(secure_score, empty_score)
        self.assertEqual(secure_score, 100)
        self.assertTrue(any(f.level == "pass" for f in findings))

    def test_http_loses_https_points(self):
        score, findings = evaluate("http://example.test", {})
        self.assertEqual(score, 0)
        self.assertTrue(any("HTTPS is not in use" in f.title for f in findings))


if __name__ == "__main__":
    unittest.main()
