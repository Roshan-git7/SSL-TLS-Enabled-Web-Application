import os
import sys
import tempfile
import unittest
import threading
import http.client
from http.server import HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, init_db, get_db, _RedirectHandler, HTTPS_PORT

TEST_CFG = {
    "TESTING": True,
    "WTF_CSRF_ENABLED": False,
    "SESSION_COOKIE_SECURE": False,
    "SECRET_KEY": "test-secret-key-not-for-production-only-abcdef123",
}


class BaseTC(unittest.TestCase):

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.db_fd)
        cfg = dict(TEST_CFG, DATABASE=self.db_path)
        self.app = create_app(cfg)
        with self.app.app_context():
            init_db()
        self.client = self.app.test_client()

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except FileNotFoundError:
            pass

    def register(self, username="testuser", password="Password1!", confirm=None):
        return self.client.post(
            "/register",
            data={
                "username": username,
                "password": password,
                "confirm_password": confirm if confirm is not None else password,
            },
            follow_redirects=True,
        )

    def login(self, username="testuser", password="Password1!"):
        return self.client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=True,
        )

    def logout(self):
        return self.client.post("/logout", follow_redirects=True)


class TestRegistration(BaseTC):

    def test_register_success(self):
        resp = self.register("alice", "SecurePass9!")
        self.assertIn(b"Account created", resp.data)
        self.assertEqual(resp.status_code, 200)

    def test_register_duplicate_username(self):
        self.register("alice", "SecurePass9!")
        resp = self.register("alice", "DiffPass99!")
        self.assertIn(b"already taken", resp.data)

    def test_register_duplicate_username_case_insensitive(self):
        self.register("Alice", "SecurePass9!")
        resp = self.register("alice", "DiffPass99!")
        self.assertIn(b"already taken", resp.data)

    def test_register_username_too_short(self):
        resp = self.register("ab", "SecurePass9!")
        self.assertIn(b"at least 3", resp.data)

    def test_register_password_too_short(self):
        resp = self.register("validuser", "short")
        self.assertIn(b"at least 8", resp.data)

    def test_register_password_mismatch(self):
        resp = self.register("validuser", "Password1!", confirm="Different1!")
        self.assertIn(b"do not match", resp.data)

    def test_password_stored_as_hash_not_plaintext(self):
        self.register("bob", "MyPlainText9!")
        with self.app.app_context():
            db = get_db()
            row = db.execute(
                "SELECT password_hash FROM users WHERE username = 'bob'"
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertNotIn("MyPlainText9!", row["password_hash"])
        self.assertTrue(
            row["password_hash"].startswith("pbkdf2:") or
            row["password_hash"].startswith("scrypt:")
        )


class TestLogin(BaseTC):

    def setUp(self):
        super().setUp()
        self.register("charlie", "ValidPass9!")

    def test_login_success_redirects_to_dashboard(self):
        resp = self.login("charlie", "ValidPass9!")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Dashboard", resp.data)

    def test_login_wrong_password_shows_generic_error(self):
        resp = self.login("charlie", "WrongPass99!")
        self.assertIn(b"Invalid username or password", resp.data)

    def test_login_nonexistent_user_shows_generic_error(self):
        resp = self.login("doesnotexist", "SomePass9!")
        self.assertIn(b"Invalid username or password", resp.data)

    def test_login_sets_user_id_in_session(self):
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)
        self.login("charlie", "ValidPass9!")
        with self.client.session_transaction() as sess:
            self.assertIn("user_id", sess)


class TestDashboard(BaseTC):

    def test_dashboard_redirects_when_not_logged_in(self):
        resp = self.client.get("/dashboard", follow_redirects=True)
        self.assertIn(b"log in", resp.data.lower())

    def test_dashboard_accessible_after_login(self):
        self.register("dave", "SecurePass9!")
        self.login("dave", "SecurePass9!")
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Dashboard", resp.data)


class TestLogout(BaseTC):

    def test_logout_clears_session_and_redirects(self):
        self.register("eve", "SecurePass9!")
        self.login("eve", "SecurePass9!")
        with self.client.session_transaction() as sess:
            self.assertIn("user_id", sess)
        resp = self.logout()
        self.assertEqual(resp.status_code, 200)
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

    def test_dashboard_inaccessible_after_logout(self):
        self.register("frank", "SecurePass9!")
        self.login("frank", "SecurePass9!")
        self.logout()
        resp = self.client.get("/dashboard", follow_redirects=True)
        self.assertIn(b"log in", resp.data.lower())


class TestSecurityHeaders(BaseTC):

    def test_x_content_type_options(self):
        resp = self.client.get("/")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")

    def test_x_frame_options(self):
        resp = self.client.get("/")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

    def test_referrer_policy(self):
        resp = self.client.get("/")
        self.assertEqual(
            resp.headers.get("Referrer-Policy"),
            "strict-origin-when-cross-origin",
        )

    def test_content_security_policy_present(self):
        resp = self.client.get("/")
        csp = resp.headers.get("Content-Security-Policy", "")
        self.assertIn("default-src", csp)

    def test_hsts_absent_on_http(self):
        resp = self.client.get("/")
        self.assertNotIn("Strict-Transport-Security", resp.headers)


class TestCSRFProtection(BaseTC):

    def test_post_without_csrf_token_is_rejected_when_csrf_enabled(self):
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)
        try:
            csrf_app = create_app({
                "TESTING": True,
                "WTF_CSRF_ENABLED": True,
                "SESSION_COOKIE_SECURE": False,
                "SECRET_KEY": "csrf-test-secret-key-abcdefghijklmnop",
                "DATABASE": db_path,
            })
            with csrf_app.app_context():
                init_db()
            c = csrf_app.test_client()
            resp = c.post("/register", data={
                "username": "hacker",
                "password": "Password1!",
                "confirm_password": "Password1!",
            })
            self.assertNotIn(b"Account created", resp.data)
        finally:
            os.unlink(db_path)


class TestHTTPRedirectHandler(unittest.TestCase):

    def _make_server(self):
        server = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
        return server, server.server_address[1]

    def test_get_returns_302_to_https_origin(self):
        server, port = self._make_server()
        t = threading.Thread(target=server.handle_request, daemon=True)
        t.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/test-path?q=1")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 302)
            loc = resp.getheader("Location", "")
            self.assertTrue(loc.startswith(f"https://127.0.0.1:{HTTPS_PORT}"))
            self.assertIn("/test-path", loc)
        finally:
            conn.close()
            server.server_close()
        t.join(timeout=2)

    def test_redirect_does_not_include_external_host(self):
        server, port = self._make_server()
        t = threading.Thread(target=server.handle_request, daemon=True)
        t.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/page", headers={"Host": "evil.example.com"})
            resp = conn.getresponse()
            loc = resp.getheader("Location", "")
            self.assertNotIn("evil.example.com", loc)
            self.assertIn("127.0.0.1", loc)
        finally:
            conn.close()
            server.server_close()
        t.join(timeout=2)


class TestErrorPages(BaseTC):

    def test_404_for_unknown_route(self):
        resp = self.client.get("/this-route-does-not-exist-xyz")
        self.assertEqual(resp.status_code, 404)
        self.assertIn(b"404", resp.data)

    def test_security_page_loads(self):
        resp = self.client.get("/security")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security", resp.data)

    def test_home_page_loads(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
