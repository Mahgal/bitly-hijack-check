#!/usr/bin/env python3
"""bitly-hijack-check: follow a short link's redirect chain and flag anything
suspicious about where it actually lands.

Why this exists: on 2026-11-15/16 it emerged that old, inactive Bitly links
could be re-registered by someone else, so a link posted years ago can now
point somewhere its author never intended (see README "Why now").

This tool only follows redirects and applies simple, explainable heuristics.
A SUSPICIOUS or MISMATCH verdict is *not* proof a link was hijacked -- it
means "check this by hand before you trust it". Only an --expect mismatch
states a hard fact: the final host is not the host you expected.

Stdlib only. Python 3.8+.
"""

import argparse
import ipaddress
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional, Tuple

VERSION = "1.0.0"
MAX_HOPS = 10
DEFAULT_TIMEOUT = 10.0

# Well-known shortener hosts. A second shortener hop mid-chain means the
# link bounces through another shortening service -- a common cloak.
SHORTENER_HOSTS = {
    "bit.ly", "bitly.com", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rb.gy", "cutt.ly", "shorturl.at", "rebrand.ly",
    "s.id", "tiny.cc", "j.mp", "t.ly", "shorte.st", "adf.ly",
}

REDIRECT_CODES = {301, 302, 303, 307, 308}


class Hop:
    """One step of a redirect chain.

    ``status`` is the HTTP status actually observed, or 0 when the hop's
    URL is known (it appeared as a Location header) but could not be
    fetched at all -- e.g. the host does not resolve. ``note`` explains
    a 0 status.
    """

    def __init__(self, status: int, url: str, note: str = ""):
        self.status = status
        self.url = url
        self.host = urllib.parse.urlparse(url).hostname or ""
        self.note = note

    def __repr__(self):  # pragma: no cover - debugging aid
        return "Hop(%d %s)" % (self.status, self.url)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stop urllib following redirects so we can record every hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch_once(url: str, timeout: float) -> Tuple[int, Optional[str]]:
    """One request, no redirect following.

    Returns (status, location-header-or-None). Raises URLError / OSError /
    ValueError on network failure or a bad URL.
    """
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "bitly-hijack-check/%s" % VERSION})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Location")
    except urllib.error.HTTPError as exc:
        # 3xx arrives here because _NoRedirect refuses to follow it.
        return exc.code, exc.headers.get("Location")


def follow_redirects(url: str, timeout: float = DEFAULT_TIMEOUT,
                     max_hops: int = MAX_HOPS) -> Tuple[List[Hop], Optional[str]]:
    """Follow a URL's redirect chain manually.

    Returns (hops, error). ``error`` is None on success; otherwise a
    human-readable reason and ``hops`` holds whatever was recorded first.
    If a redirect target is known from a Location header but cannot be
    fetched, it is still recorded as a final hop with status 0 (and a
    note) -- the destination host is known even when the server cannot
    be reached, and the heuristics can still be applied to it.
    """
    hops: List[Hop] = []
    current = url
    for _ in range(max_hops + 1):
        try:
            status, location = _fetch_once(current, timeout)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            if hops:
                # We got here via a redirect: the target URL is known.
                hops.append(Hop(0, current,
                                note="could not fetch: %s" % reason))
                return hops, None
            return hops, "request failed for %s: %s" % (current, reason)
        hops.append(Hop(status, current))
        if status in REDIRECT_CODES and location:
            nxt = urllib.parse.urljoin(current, location)
            if nxt == current:
                return hops, "redirect loop at %s" % current
            current = nxt
            continue
        return hops, None
    return hops, "too many redirects (over %d hops)" % max_hops


def _normalize_host(host: str) -> str:
    host = (host or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def classify(hops: List[Hop], expect: Optional[str] = None) -> Tuple[str, List[str]]:
    """Apply the documented heuristics to a finished chain.

    Returns (verdict, reasons). Verdict is one of CLEAN, SUSPICIOUS,
    MISMATCH. Rules, in order:
      1. --expect given and final host differs -> MISMATCH.
      2. Final host is an IP literal -> SUSPICIOUS.
      3. Final host contains punycode (xn--) -> SUSPICIOUS.
      4. A second shortener hop appears mid-chain -> SUSPICIOUS.
      5. Otherwise -> CLEAN.
    """
    if not hops:
        return "SUSPICIOUS", ["no hops recorded"]
    final_host = hops[-1].host
    reasons: List[str] = []
    if expect:
        if _normalize_host(final_host) != _normalize_host(expect):
            return "MISMATCH", [
                "final host %r does not match expected host %r"
                % (final_host, expect)]
    if _is_ip_literal(final_host):
        reasons.append("final host %r is a bare IP address, not a domain name"
                       % final_host)
    if "xn--" in final_host.lower():
        reasons.append("final host %r contains punycode (xn--) -- possible "
                       "look-alike domain" % final_host)
    mid_hosts = [_normalize_host(h.host) for h in hops[1:-1]] or []
    # Also count the first hop's host only as the entry shortener; a
    # *different* shortener later in the chain is the suspicious part.
    first_host = _normalize_host(hops[0].host)
    for host in mid_hosts:
        if host in SHORTENER_HOSTS and host != first_host:
            reasons.append("redirect chain passes through a second shortener "
                           "(%s) after %s" % (host, first_host))
            break
    if reasons:
        return "SUSPICIOUS", reasons
    return "CLEAN", ["final host %r, no heuristic triggered" % final_host]


def check_url(url: str, expect: Optional[str] = None,
              timeout: float = DEFAULT_TIMEOUT) -> Tuple[List[Hop], str, List[str], Optional[str]]:
    """Full check: follow + classify. Returns (hops, verdict, reasons, error)."""
    hops, error = follow_redirects(url, timeout=timeout)
    if error is not None:
        return hops, "", [], error
    verdict, reasons = classify(hops, expect=expect)
    return hops, verdict, reasons, None


def _print_hops(hops: List[Hop]) -> None:
    for i, hop in enumerate(hops, 1):
        if hop.status == 0:
            print("[hop %d] ??? %s  (host: %s) -- %s"
                  % (i, hop.url, hop.host, hop.note))
        else:
            print("[hop %d] %d %s  (host: %s)"
                  % (i, hop.status, hop.url, hop.host))


def _print_result(url: str, hops: List[Hop], verdict: str, reasons: List[str]) -> None:
    _print_hops(hops)
    print("Final URL: %s" % hops[-1].url)
    print("Final host: %s" % hops[-1].host)
    print("Verdict: %s" % verdict)
    for reason in reasons:
        print("  - %s" % reason)
    if verdict in ("SUSPICIOUS", "MISMATCH"):
        print("Note: this is a heuristic flag, not proof of hijacking. "
              "Verify the destination by hand before trusting the link.")
    else:
        print("Note: CLEAN means no heuristic fired; it is not a guarantee "
              "the destination is safe.")


def _run_mock(fail_on=None) -> int:
    """Run the built-in offline mock demo: /clean and /hijacked fixtures."""
    from mock_redirect_server import run_server

    # Fixed port so demo output is reproducible; fall back to an ephemeral
    # port only if 18081 is already in use.
    try:
        server, port = run_server(18081)
    except OSError:
        server, port = run_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    worst = 0
    try:
        base = "http://127.0.0.1:%d" % port
        # /clean: a link that lands where it should.
        # /hijacked: the same link's *expected* destination is example.com,
        # but it actually lands on a look-alike host -- the exact shape of
        # a re-registered short link.
        for path, expect in (("/clean", "example.com"),
                             ("/hijacked", "example.com")):
            url = base + path
            print("== mock check: %s (expect %s) ==" % (url, expect))
            hops, verdict, reasons, error = check_url(url, expect=expect)
            if error is not None:
                print("Error: %s" % error)
                worst = 1
                continue
            _print_result(url, hops, verdict, reasons)
            print()
            if verdict != "CLEAN":
                worst = 1
        if fail_on == "suspicious":
            return worst
        return 0
    finally:
        server.shutdown()
        server.server_close()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bitly-hijack-check",
        description="Follow a short link's redirect chain and flag where it "
                    "really lands. Heuristic verdicts only -- verify by hand.")
    parser.add_argument("--url", help="short link (or any URL) to check")
    parser.add_argument("--expect", default=None,
                        help="expected final hostname, e.g. example.com")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="per-request timeout in seconds (default 10)")
    parser.add_argument("--fail-on", choices=["suspicious"], default=None,
                        help="exit 1 when the verdict is not CLEAN "
                             "(MISMATCH or SUSPICIOUS)")
    parser.add_argument("--mock", action="store_true",
                        help="run the offline mock demo (clean + hijacked "
                             "fixtures on a local server) instead of a live URL")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)

    if args.mock:
        return _run_mock(fail_on=args.fail_on)
    if not args.url:
        parser.error("--url is required unless --mock is given")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    hops, verdict, reasons, error = check_url(args.url, expect=args.expect,
                                              timeout=args.timeout)
    if error is not None:
        _print_hops(hops)
        print("Error: %s" % error)
        print("The link could not be checked (network error, bad URL, or "
              "redirect loop). This is not a verdict about the link.")
        return 1
    _print_result(args.url, hops, verdict, reasons)
    if args.fail_on == "suspicious" and verdict != "CLEAN":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
