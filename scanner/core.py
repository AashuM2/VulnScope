
import requests
import ssl
import socket
from urllib.parse import urlsplit


class Scanner:
    def __init__(self, url):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        self.url = url.rstrip("/")
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnScope Security Scanner"
        })
        self._login_if_dvwa()

    def _login_if_dvwa(self):
        if "127.0.0.1:8080" in self.url or "localhost:8080" in self.url:
            try:
                login_page = self.session.get(
                    self.url.split("/")[0] + "//" +
                    urlsplit(self.url).netloc + "/login.php",
                    timeout=5
                )

                token = login_page.text.split(
                    "user_token' value='"
                )[1].split("'")[0]

                self.session.post(
                    self.url.split("/")[0] + "//" +
                    urlsplit(self.url).netloc + "/login.php",
                    data={
                        "username": "admin",
                        "password": "password",
                        "Login": "Login",
                        "user_token": token
                    },
                    timeout=5
                )
            except Exception:
                pass

    def scan(self):
        self.check_ssl()
        self.check_headers()
        self.check_sql_injection()
        self.check_xss()
        self.check_open_redirect()
        self.check_dir_traversal()
        self.check_auth()
        return self.results

    def add_result(self, vuln_type, severity, detected_by, description, fix):
        self.results.append({
            "vuln_type": vuln_type,
            "severity": severity,
            "detected_by": detected_by,
            "description": description,
            "fix_suggestion": fix
        })

    def check_ssl(self):
        parsed = urlsplit(self.url)

        if parsed.scheme != "https":
            self.add_result(
                "SSL Certificate Invalid",
                "Critical",
                "Static",
                "The target URL uses HTTP instead of HTTPS.",
                "Enable HTTPS with a valid SSL/TLS certificate."
            )
            return

        try:
            hostname = parsed.hostname
            port = parsed.port or 443

            ctx = ssl.create_default_context()

            with ctx.wrap_socket(
                socket.socket(),
                server_hostname=hostname
            ) as s:
                s.settimeout(5)
                s.connect((hostname, port))
                version = s.version()

                if version in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
                    self.add_result(
                        "Weak SSL/TLS Version",
                        "High",
                        "Active",
                        f"Server is using outdated {version} protocol.",
                        "Upgrade to TLS 1.2 or TLS 1.3."
                    )

        except Exception:
            self.add_result(
                "SSL Certificate Invalid",
                "Critical",
                "Static",
                "The SSL/TLS connection or certificate validation failed.",
                "Install and configure a valid SSL certificate."
            )

    def check_headers(self):
        try:
            res = self.session.get(self.url, timeout=5)
            headers = res.headers

            if "X-Frame-Options" not in headers:
                self.add_result(
                    "Missing X-Frame-Options Header",
                    "Medium",
                    "Static",
                    "The website does not define an X-Frame-Options header.",
                    "Add X-Frame-Options: DENY or SAMEORIGIN."
                )

            if "Content-Security-Policy" not in headers:
                self.add_result(
                    "Missing Content Security Policy",
                    "High",
                    "Static",
                    "No Content Security Policy header was found.",
                    "Configure a suitable Content-Security-Policy header."
                )

            if "Strict-Transport-Security" not in headers:
                self.add_result(
                    "Missing HSTS Header",
                    "Medium",
                    "Static",
                    "The website does not define an HSTS header.",
                    "Add Strict-Transport-Security after enabling HTTPS."
                )

            if "X-Content-Type-Options" not in headers:
                self.add_result(
                    "Missing X-Content-Type-Options Header",
                    "Low",
                    "Static",
                    "The website does not define the nosniff protection header.",
                    "Add X-Content-Type-Options: nosniff."
                )

            try:
                options_res = self.session.options(self.url, timeout=5)
                allowed = options_res.headers.get("Allow", "").upper()

                if any(method in allowed.split(",") for method in
                       ["DELETE", "PUT", "TRACE"]):
                    self.add_result(
                        "Potentially Dangerous HTTP Methods Enabled",
                        "High",
                        "Active",
                        f"Server advertises these methods: {allowed}.",
                        "Disable unnecessary HTTP methods."
                    )

            except requests.RequestException:
                pass

        except requests.RequestException:
            pass

    def check_sql_injection(self):
        error_patterns = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "mysql_fetch",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "ora-00933",
            "odbc driver",
            "sqlite error",
            "postgresql error"
        ]

        try:
            baseline = self.session.get(self.url, timeout=5)
            baseline_text = baseline.text.lower()

            for error in error_patterns:
                if error in baseline_text:
                    self.add_result(
                        "SQL Error Disclosure",
                        "High",
                        "Static",
                        "The response contains a possible database error message.",
                        "Disable database error display and use custom error pages."
                    )
                    break

            # Non-destructive quote-based probes only
            payloads = ["'", '"']

            for payload in payloads:
                res = self.session.get(
                    self.url,
                    params={"id": payload},
                    timeout=5
                )

                response_text = res.text.lower()

                for error in error_patterns:
                    if error in response_text and error not in baseline_text:
                        self.add_result(
                            "Potential SQL Injection",
                            "High",
                            "Active",
                            "A database error appeared after a quote-based input test. Manual verification is required.",
                            "Use prepared statements and parameterized queries."
                        )
                        return

        except requests.RequestException:
            pass

    def check_xss(self):
        try:
            res = self.session.get(self.url, timeout=5)

            if "document.write(" in res.text or "innerHTML" in res.text:
                self.add_result(
                    "Potential XSS Sink (Static)",
                    "Medium",
                    "Static",
                    "The page contains JavaScript functions that may create XSS risks.",
                    "Avoid unsafe DOM insertion. Prefer textContent and safe output encoding."
                )

            payload = "<vulnscope-test>"
            param_names = ["q", "name", "search", "input"]

            for param in param_names:
                res = self.session.get(
                    self.url,
                    params={param: payload},
                    timeout=5
                )

                if payload in res.text:
                    self.add_result(
                        "Potential Reflected XSS",
                        "Medium",
                        "Active",
                        "Test input was reflected in the response. Browser execution has not been confirmed.",
                        "Apply context-aware output encoding and validate user input."
                    )
                    return

        except requests.RequestException:
            pass

    def check_open_redirect(self):
        try:
            res = self.session.get(self.url, timeout=5)
            page = res.text.lower()

            redirect_params = [
                "redirect", "url", "next", "return", "goto"
            ]

            for param in redirect_params:
                if "?" + param + "=" in page or "&" + param + "=" in page:
                    self.add_result(
                        "Potential Open Redirect Parameter",
                        "Low",
                        "Static",
                        f"The page contains a possible {param} redirect parameter.",
                        "Validate redirect destinations against an allowed-domain list."
                    )
                    break

            res = self.session.get(
                self.url,
                params={"redirect": "https://example.com"},
                timeout=5,
                allow_redirects=False
            )

            location = res.headers.get("Location", "")

            if res.status_code in [301, 302, 303, 307, 308]:
                if "example.com" in location:
                    self.add_result(
                        "Potential Open Redirect",
                        "Medium",
                        "Active",
                        "The target redirected to an external test destination.",
                        "Validate redirect URLs against a whitelist of allowed domains."
                    )

        except requests.RequestException:
            pass

    def check_dir_traversal(self):
        try:
            res = self.session.get(self.url, timeout=5)
            page = res.text.lower()

            if any(param in page for param in
                   ["?file=", "?path=", "?page="]):
                self.add_result(
                    "Potential Directory Traversal Parameter",
                    "Low",
                    "Static",
                    "The page contains possible file path parameters.",
                    "Validate file paths and use a whitelist of allowed files."
                )

            # Read-only test probes. Use only on authorized targets.
            payloads = [
                {"file": "../../etc/passwd"},
                {"path": "../../../etc/passwd"},
                {"page": "....//....//etc/passwd"}
            ]

            for params in payloads:
                res = self.session.get(
                    self.url,
                    params=params,
                    timeout=5
                )

                if "root:" in res.text and "/bin/" in res.text:
                    self.add_result(
                        "Potential Directory Traversal",
                        "Critical",
                        "Active",
                        "The response contains content resembling a system password file.",
                        "Validate file path inputs and restrict access to the intended directory."
                    )
                    return

        except requests.RequestException:
            pass

    def check_auth(self):
        try:
            res = self.session.get(self.url, timeout=5)

            for cookie in res.cookies:
                rest = str(cookie).lower()

                if not cookie.has_nonstandard_attr("HttpOnly"):
                    self.add_result(
                        "Cookie Missing HttpOnly Flag",
                        "Medium",
                        "Static",
                        "A cookie may be accessible through JavaScript.",
                        "Set the HttpOnly flag on session cookies."
                    )

                if not cookie.secure:
                    self.add_result(
                        "Cookie Missing Secure Flag",
                        "Medium",
                        "Static",
                        "A cookie does not have the Secure flag.",
                        "Set the Secure flag when using HTTPS."
                    )

                if "samesite" not in rest:
                    self.add_result(
                        "Cookie Missing SameSite Flag",
                        "Low",
                        "Static",
                        "A cookie may lack SameSite protection.",
                        "Configure an appropriate SameSite policy."
                    )

        except requests.RequestException:
            pass

        try:
            parsed = urlsplit(self.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            login_urls = [
                base_url + "/admin",
                base_url + "/login",
                base_url + "/administrator"
            ]

            for login_url in login_urls:
                res = self.session.get(login_url, timeout=5)

                if res.status_code == 200 and (
                    "login" in res.text.lower()
                    or "password" in res.text.lower()
                ):
                    self.add_result(
                        "Potential Admin Panel Exposure",
                        "High",
                        "Active",
                        f"A possible login or admin page was found at {login_url}.",
                        "Restrict administrative access and enable rate limiting and multi-factor authentication."
                    )
                    break

        except requests.RequestException:
            pass
