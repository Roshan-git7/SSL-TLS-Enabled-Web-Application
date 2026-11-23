# Viva & Oral Exam Guide — SSL/TLS Secure Web Application

**Project:** SSL/TLS-Enabled Secure Web Application  
**Student:** Roshan — B.Tech CSE, 5th Semester  
**Subject:** Cyber Security / Information Security Lab

---

## Quick Reference / Cheat Sheet

| Question | Short Answer |
|---|---|
| **Primary Goal of Project** | Demonstrate end-to-end transport encryption (TLS), secure session cookies, CSRF protection, salted password hashing, and HTTP redirection in a lightweight Flask web application. |
| **Backend Framework** | Python Flask 3.x with standard library `ssl`, `sqlite3`, and `http.server`. |
| **Ports Used** | `5000` (HTTPS encrypted) and `5001` (HTTP redirect listener). |
| **Hashing Algorithm** | Werkzeug's implementation of Scrypt / PBKDF2-HMAC-SHA256 with cryptographic salting. |
| **Database** | SQLite3 using parameterized SQL queries (`?` placeholders). |
| **Authentication** | Flask server-side session signed with cryptographic `SECRET_KEY`. |

---

## Top 15 Viva Questions & In-Depth Answers

### 1. What is SSL/TLS, and where does it sit in the OSI / TCP/IP model?
**Answer:**  
TLS (Transport Layer Security) is the modern cryptographic successor to SSL (Secure Sockets Layer). It operates between the **Transport layer (TCP)** and the **Application layer (HTTP, SMTP, etc.)**. In the OSI model, it is often considered at the Session / Presentation boundary. It provides three foundational security objectives:
1. **Confidentiality:** Symmetric encryption (e.g., AES-GCM, ChaCha20) ensures eavesdroppers cannot read traffic.
2. **Integrity:** Message Authentication Codes (MAC / AEAD) ensure data is not tampered with in transit.
3. **Authentication:** Digital certificates ensure the client is communicating with the legitimate server, preventing Man-in-the-Middle (MitM) attacks.

---

### 2. What happens during a TLS handshake?
**Answer:**  
1. **Client Hello:** The browser sends supported TLS versions, cipher suites, and a random number (`Client Random`).
2. **Server Hello:** The server chooses the cipher suite, sends its random number (`Server Random`), and transmits its **X.509 Digital Certificate** containing its public key.
3. **Authentication & Key Exchange:** The client validates the server's certificate. Using Diffie-Hellman (ECDHE) or RSA, the client and server derive a shared secret (`Pre-Master Secret`).
4. **Session Key Derivation:** Both parties independently calculate the symmetric session keys using the client random, server random, and pre-master secret.
5. **Finished:** Both send encrypted verification messages. All subsequent HTTP messages are symmetrically encrypted for fast data transmission.

---

### 3. Why does the browser show a red "Not Secure" warning on our project?
**Answer:**  
Our project uses a **self-signed certificate** generated for local development (`127.0.0.1`). In commercial environments, certificates are signed by a trusted **Certificate Authority (CA)** (e.g., Let's Encrypt, DigiCert) whose root certificates are pre-installed in the operating system's trust store.  
Because our self-signed certificate's issuer is not in the browser's root trust store, the browser displays `NET::ERR_CERT_AUTHORITY_INVALID`. The encryption itself is mathematically valid and full-strength (RSA-2048, SHA-256), but identity verification by a trusted third party is absent.

---

### 4. Why did we need a separate HTTP listener on port 5001?
**Answer:**  
Flask's built-in WSGI development server (`werkzeug.serving`) binds a single socket per process. When configured with an SSL context, that socket accepts only TLS handshakes. An incoming plaintext HTTP request to port 5000 results in an immediate TLS handshake error (`ssl.SSLError: http request to https port`).  
To demonstrate an actual HTTP-to-HTTPS redirect, our project runs a lightweight background HTTP server on port `5001` using Python's standard `http.server.HTTPServer`. It intercepts HTTP traffic and sends back an HTTP `302 Found` response pointing to `https://127.0.0.1:5000`.

---

### 5. What is an Open Redirect vulnerability, and how does our HTTP listener prevent it?
**Answer:**  
An open redirect happens when a server takes an untrusted input (such as the `Host:` HTTP header or a query parameter like `?next=http://attacker.com`) and reflects it into the `Location:` header of a redirect response. Attackers use this for phishing campaigns.  
In our implementation, the redirect listener ignores the `Host:` header completely and hardcodes the destination origin to `https://127.0.0.1:5000`, appending only the sanitized request path.

---

### 6. What do the cookie flags `HttpOnly`, `Secure`, and `SameSite` do?
**Answer:**  
- **`HttpOnly`:** Instructs the browser that the cookie must not be accessible via client-side JavaScript (`document.cookie`). This protects session IDs against theft via Cross-Site Scripting (XSS).
- **`Secure`:** Instructs the browser to only transmit the cookie over encrypted HTTPS connections, preventing transmission over plaintext HTTP.
- **`SameSite=Lax`:** Restricts cross-site request behavior. The cookie is not sent on cross-site subrequests (e.g., images, AJAX), but is sent when a user navigates directly (top-level GET). This mitigates Cross-Site Request Forgery (CSRF).

---

### 7. What is HSTS (HTTP Strict Transport Security)? Why is it sent only on HTTPS?
**Answer:**  
HSTS is delivered via the `Strict-Transport-Security` header. It tells the browser that for a given time period (`max-age=31536000`), it must automatically upgrade all future requests to HTTPS before even contacting the network, defeating SSL-stripping attacks.  
**Critical rule:** RFC 6797 mandates that browsers must ignore HSTS headers received over plaintext HTTP because an attacker could inject or strip them. Therefore, our application only attaches HSTS when `request.is_secure` is true.

---

### 8. Why use Werkzeug's `generate_password_hash` instead of simple SHA-256?
**Answer:**  
General-purpose hash functions like SHA-256 or MD5 were designed for speed (e.g., verifying file integrity). A modern GPU can compute billions of SHA-256 hashes per second, making them vulnerable to rainbow table attacks and brute force.  
Werkzeug uses **Scrypt** or **PBKDF2-HMAC-SHA256**:
1. **Cryptographic Salt:** Every password receives a unique random salt, preventing precomputed rainbow table attacks.
2. **Key Stretching (Work Factor):** Thousands of iterations force the algorithm to be computationally expensive and memory-hard, making offline cracking infeasible.

---

### 9. How does our project prevent SQL Injection?
**Answer:**  
We use SQLite with **parameterized queries** (prepared statements with `?` placeholders):
```python
db.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
```
The database engine compiles the SQL command structure first, and treats the user input strictly as literal data. Characters like `'`, `--`, or `OR 1=1` are never interpreted as SQL syntax.

---

### 10. What is Session Fixation, and how did we prevent it?
**Answer:**  
Session Fixation occurs when an attacker forces a known session ID onto a victim (e.g., via a malicious link). If the application retains the same session ID after the user logs in, the attacker can hijack the authenticated session.  
In our `login` route, we explicitly execute `session.clear()` immediately before storing `session["user_id"] = user["id"]`, ensuring a fresh session token is issued upon privilege elevation.

---

### 11. What is Cross-Site Request Forgery (CSRF) and how is it mitigated here?
**Answer:**  
CSRF tricks an authenticated user's browser into executing an unwanted action on a trusted website (e.g., submitting an unauthorized form).  
We use **Flask-WTF (CSRFProtect)**. Every form includes a hidden `<input type="hidden" name="csrf_token" value="...">`. The server verifies that the token matches the user's session token. Since an external attacker site cannot read the token under the Same-Origin Policy, forged requests fail with HTTP 400.

---

### 12. What is Content Security Policy (CSP)?
**Answer:**  
CSP is an HTTP response header (`Content-Security-Policy`) that specifies which dynamic resources the browser is allowed to load and execute.  
Our policy: `default-src 'self'; script-src 'self'; style-src 'self' ...; frame-ancestors 'none'`.  
This prevents attackers from injecting external malicious scripts or loading the site within malicious `<iframe>` tags (clickjacking).

---

### 13. Why does the login route return a generic error on failure?
**Answer:**  
If a server returns "Username not found" versus "Incorrect password", an attacker can automate queries to enumerate valid usernames.  
Our project returns the identical message: `"Invalid username or password"` for both cases, preventing user enumeration.

---

### 14. What does Wireshark show when capturing HTTPS traffic versus HTTP?
**Answer:**  
- **Plaintext HTTP (port 5001):** The entire payload is readable, including headers, request path, parameters, and form fields.
- **HTTPS (port 5000):** After the initial plaintext TLS handshake (`Client Hello` / `Server Hello` / `Certificate`), all subsequent packets are labeled `Application Data` and are encrypted. The attacker cannot see the URL path, headers, cookies, or credentials.

---

### 15. What are the production limitations of this student project?
**Answer:**  
1. **Development Server:** Flask's built-in server is designed for development and testing, not high-concurrency production (a production deployment would use Gunicorn or uWSGI behind Nginx).
2. **Self-Signed Certificate:** Needs replacement with a CA-signed certificate (e.g., Let's Encrypt).
3. **Local Database:** SQLite is a local file-based database suitable for single-node deployments; enterprise systems use PostgreSQL or MySQL.
