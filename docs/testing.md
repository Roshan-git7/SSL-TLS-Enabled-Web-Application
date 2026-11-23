# Testing Guide — SSL/TLS Secure Web Application

**Project:** SSL/TLS-Enabled Secure Web Application  
**Student:** Roshan — B.Tech CSE, 5th Semester  
**Target Environment:** Windows 10/11 (PowerShell / Command Prompt)

---

## 1. Automated Test Suite

The project includes a comprehensive automated test suite written using Python's standard `unittest` framework. The test suite uses an in-memory/temporary file SQLite database (`tempfile.mkstemp`) so that running tests never overwrites your real `users.db` file or requires a live TLS certificate.

### Running the Tests

Open Windows PowerShell in the project directory and run:

```powershell
py -m unittest discover -s tests -v
```

*(If using standard python: `python -m unittest discover -s tests -v`)*

### Test Suite Structure

The tests are defined in `tests/test_app.py`:

| Test Class | Test Method | Description |
|---|---|---|
| **TestRegistration** | `test_register_success` | Valid credentials redirect to login with confirmation |
| | `test_register_duplicate_username` | Prevents duplicate username creation with friendly message |
| | `test_register_duplicate_username_case_insensitive` | Ensures 'Alice' and 'alice' collide via SQLite NOCASE collation |
| | `test_register_username_too_short` | Rejects usernames shorter than 3 characters |
| | `test_register_password_too_short` | Rejects passwords shorter than 8 characters |
| | `test_register_password_mismatch` | Rejects non-matching password confirmation |
| | `test_password_stored_as_hash_not_plaintext` | Verifies SQLite stores Werkzeug pbkdf2/scrypt hash, never plaintext |
| **TestLogin** | `test_login_success_redirects_to_dashboard` | Valid credentials set session and redirect to dashboard |
| | `test_login_wrong_password_shows_generic_error` | Generic error on invalid password (prevents username enumeration) |
| | `test_login_nonexistent_user_shows_generic_error` | Generic error on unknown user |
| | `test_login_sets_user_id_in_session` | Confirms user ID stored in server-side session |
| **TestDashboard** | `test_dashboard_redirects_when_not_logged_in` | Unauthenticated GET /dashboard redirects to /login |
| | `test_dashboard_accessible_after_login` | Logged-in session can view dashboard contents |
| **TestLogout** | `test_logout_clears_session_and_redirects` | POST /logout clears user_id from session and redirects home |
| | `test_dashboard_inaccessible_after_logout` | After logout, access to /dashboard is denied |
| **TestSecurityHeaders** | `test_x_content_type_options` | Confirms `X-Content-Type-Options: nosniff` header |
| | `test_x_frame_options` | Confirms `X-Frame-Options: DENY` header |
| | `test_referrer_policy` | Confirms `Referrer-Policy: strict-origin-when-cross-origin` |
| | `test_content_security_policy_present` | Confirms `Content-Security-Policy` header exists |
| | `test_hsts_absent_on_http` | Confirms `Strict-Transport-Security` is NOT sent on HTTP |
| **TestCSRFProtection** | `test_post_without_csrf_token_is_rejected_when_csrf_enabled` | Submitting forms without CSRF token is rejected |
| **TestHTTPRedirectHandler** | `test_get_returns_302_to_https_origin` | Port 5001 returns 302 redirect to `https://127.0.0.1:5000` |
| | `test_redirect_does_not_include_external_host` | Host header injection cannot force redirect to external malicious domain |
| **TestErrorPages** | `test_404_for_unknown_route` | Custom 404 template returned for non-existent routes |
| | `test_security_page_loads` | Security documentation page responds with 200 OK |
| | `test_home_page_loads` | Landing page responds with 200 OK |

---

## 2. Manual Verification & Demonstration Steps

### Step A: Verify HTTP-to-HTTPS Redirection

1. Start the application:
   ```powershell
   py app.py
   ```
2. Open PowerShell in a second terminal and query the HTTP port using `curl`:
   ```powershell
   curl -I http://127.0.0.1:5001/dashboard?test=1
   ```
3. Observe the response:
   ```http
   HTTP/1.0 302 Found
   Location: https://127.0.0.1:5000/dashboard?test=1
   Connection: close
   ```
4. **Key Viva Point:** Notice the location is hardcoded to `https://127.0.0.1:5000`. Even if an attacker supplies `Host: evil.com`, the redirect safely goes to the local HTTPS listener.

---

### Step B: Inspect SSL/TLS Certificate in Browser

1. Open your browser (Google Chrome, Microsoft Edge, or Mozilla Firefox).
2. Navigate to: `https://127.0.0.1:5000/`
3. Because the certificate is self-signed, the browser will display a warning:
   - *Chrome/Edge:* "Your connection isn't private" / `NET::ERR_CERT_AUTHORITY_INVALID`
4. Click **Advanced** -> **Proceed to 127.0.0.1 (unsafe)**.
5. In the address bar, click the crossed-out padlock icon or the "Not secure" badge -> **Certificate details**.
6. View certificate properties:
   - **Issued To (CN):** 127.0.0.1
   - **Organization (O):** SSL Secure Web App Dev
   - **SAN (Subject Alternative Name):** IP:127.0.0.1, DNS:localhost
   - **Signature Algorithm:** SHA-256 with RSA (2048 bits)
   - **Validity:** 365 days

---

### Step C: Inspect Security Headers & Cookies in DevTools

1. In the browser, press `F12` to open Developer Tools.
2. Switch to the **Network** tab.
3. Refresh the page (`Ctrl + F5`) and select the request for `127.0.0.1`.
4. Inspect **Response Headers**:
   - `Content-Security-Policy: default-src 'self'; ...`
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains` (sent over HTTPS)
5. Switch to **Application** (or **Storage** in Firefox) -> **Cookies** -> `https://127.0.0.1:5000`:
   - Inspect the `session` cookie:
     - `HttpOnly`: Checked (prevents JavaScript access via `document.cookie`)
     - `Secure`: Checked (cookie is only transmitted over HTTPS connections)
     - `SameSite`: `Lax` (protects against Cross-Site Request Forgery)

---

### Step D: Inspect Password Hashes in SQLite

1. In PowerShell, query the SQLite database using Python:
   ```powershell
   py -c "import sqlite3; conn = sqlite3.connect('users.db'); print(conn.execute('SELECT id, username, password_hash, created_at FROM users').fetchall())"
   ```
2. Observe that:
   - The password is stored as an irreversible cryptographic hash:
     e.g., `scrypt:32768:8:1$...` or `pbkdf2:sha256:1000000$...`
   - Plaintext passwords never appear anywhere in the database or logs.

---

### Step E: Wireshark Packet Capture Demonstration (Optional Viva Demo)

1. Open Wireshark and listen on the **Adapter for loopback traffic capture** (`Npcap Loopback Adapter`).
2. Set the display filter to:
   ```wireshark
   tcp.port == 5000 || tcp.port == 5001
   ```
3. Test HTTP traffic on port 5001:
   - You can read the plaintext HTTP GET and 302 Found headers.
4. Test HTTPS traffic on port 5000:
   - Notice the initial TLS handshake packets: **Client Hello**, **Server Hello**, **Certificate**, **Key Exchange**.
   - Notice subsequent communication is labeled **Application Data** and encrypted; payloads cannot be read in plaintext.
