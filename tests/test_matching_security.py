"""Red-team table for autofill matching: a page must never be offered another site's password.

Every row was a real failure or a classic phishing trick. `page -> domains offered`."""

import pytest

from icp.vault.host import Credential, CredentialStore, _normalize_host


def cred(domain, title=""):
    return Credential(domain=domain, username="me", password="secret", title=title or domain)


STORE = CredentialStore([
    cred("example.com"), cred("paypal.com"), cred("amazon", "Amazon"), cred("localhost"),
    cred("cloudflare", "Cloudflare"), cred("192.168.1.1"), cred("xn--bcher-kva.example"),
    cred("bücher.example", "Bücher Shop"), cred("", "Cloudflare Dashboard"),
])


def offered(page):
    return sorted(c.domain for c in STORE.match(page))


@pytest.mark.parametrize("page", [
    "example.com.evil.com", "evil-example.com", "evilexample.com", "example.com@evil.com",
    "paypal.com.evil.com", "paypa1.com", "xn--pypal-4ve.com", "рaypal.com",     # Cyrillic p
    "amazon.evil.com", "amazon-login.com", "myamazon.com", "amazonaws.com",
    "cloudflare.evil.com", "cloudflare.example.org", "evil.localhost", "shop.evil.com",
    "buecher.example", "bücher.example",
    "192.168.1.10", "1.192.168.1.1", "evil.com.192.168.1.1",
    # parser confusion: a browser sends these to evil.com
    "https://evil.com\\@example.com/", "https://evil.com#@example.com/",
    "https://evil.com?@example.com", "https://user:pw@evil.com/example.com",
    "https://evil.com/https://example.com", "https://evil.com/?u=example.com",
    "//evil.com/@example.com", "https://example.com\x00.evil.com", "https://exa mple.com",
    "javascript:alert(1)", "", "   ", ".", "..", "[",
])
def test_phishing_pages_are_offered_nothing(page):
    assert offered(page) == [], page


@pytest.mark.parametrize("page,domains", [
    ("example.com", ["example.com"]),
    ("EXAMPLE.COM", ["example.com"]),
    ("www.example.com", ["example.com"]),
    ("login.deep.example.com", ["example.com"]),
    ("example.com.", ["example.com"]),                         # fully-qualified form
    ("https://example.com:8443/a?b=c#d", ["example.com"]),
    ("https://user:pw@example.com/", ["example.com"]),
    ("amazon.com", ["amazon"]), ("www.amazon.co.uk", ["amazon"]),
    ("dash.cloudflare.com", ["", "cloudflare"]),            # a label-only entry has no domain
    ("localhost", ["localhost"]), ("192.168.1.1", ["192.168.1.1"]),
    ("xn--bcher-kva.example", ["xn--bcher-kva.example"]),     # punycode stored by the browser
])
def test_legitimate_pages_still_match(page, domains):
    assert offered(page) == domains


@pytest.mark.parametrize("raw,host", [
    ("https://evil.com\\@example.com/", "evil.com"),
    ("https://evil.com#@example.com/", "evil.com"),
    ("http://[::1]:8080/", "[::1]"),
    ("https://EXAMPLE.com:443/x", "example.com"),
    ("example.com\x00", ""), ("exa mple.com", ""), ("", ""),
])
def test_normalize_host_reads_urls_like_a_browser(raw, host):
    assert _normalize_host(raw) == host
