"""HTTP/web interaction tools using httpx."""
import html
import os
import re

import httpx

from config import ARTIFACTS_DIR
from scope import check_scope


def _safe_save_path(save_to: str) -> str:
    """
    Resolve a user-supplied save_to path to a location inside an allowlisted
    directory (the artifacts dir, /tmp, or /var/tmp). A bare/relative name is
    placed inside the artifacts dir; an absolute path is accepted only if it
    resolves inside one of the allowed roots. This blocks writes to sensitive
    locations (home dir, /etc, SSH keys, cron, etc.) and '..' traversal.
    Raises ValueError if the resolved path is outside all allowed roots.
    """
    artifacts = os.path.realpath(ARTIFACTS_DIR)
    if os.path.isabs(save_to):
        candidate = os.path.realpath(save_to)
    else:
        candidate = os.path.realpath(os.path.join(artifacts, save_to))

    allowed_roots = [artifacts, os.path.realpath("/tmp"), os.path.realpath("/var/tmp")]
    for root in allowed_roots:
        try:
            if os.path.commonpath([root, candidate]) == root:
                return candidate
        except ValueError:
            continue
    raise ValueError(
        f"save_to must resolve inside {artifacts}, /tmp, or /var/tmp; "
        f"'{save_to}' resolves outside all of them."
    )


def _strip_html(html_str: str) -> str:
    """Remove HTML tags and extract visible text."""
    # Remove scripts and styles
    text = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html_str, flags=re.DOTALL | re.IGNORECASE)
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    # Decode HTML entities
    text = html.unescape(text)
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def _register(mcp, job_mgr):

    @mcp.tool()
    async def http_request(
        url: str,
        method: str = "GET",
        headers: dict = {},
        cookies: dict = {},
        data: str = "",
        follow_redirects: bool = True,
        timeout: int = 30,
        save_to: str = "",
        extract_text: bool = False,
    ) -> dict:
        """
        Make an HTTP request and inspect the full response.
        url: target URL
        method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
        headers: dict of HTTP headers e.g. {"Authorization": "Bearer token"}
        cookies: dict of cookies e.g. {"session": "abc123"}
        data: request body for POST/PUT (string or JSON)
        follow_redirects: follow 3xx redirects (default True)
        timeout: request timeout in seconds
        save_to: if set, save response body to this file path (for binaries/large files)
        extract_text: if True and HTML, strip tags and return visible text only
        Returns: status, headers, body (or file path if save_to), redirect chain, timing
        """
        check_scope(url)
        async with httpx.AsyncClient(follow_redirects=follow_redirects, timeout=timeout) as client:
            try:
                resp = await client.request(method, url, headers=headers, cookies=cookies, content=data)

                result = {
                    "status_code": resp.status_code,
                    "reason": resp.reason_phrase,
                    "headers": dict(resp.headers),
                    "cookies": dict(resp.cookies),
                    "body_length": len(resp.content),
                    "redirect_chain": [str(r.url) for r in resp.history],
                    "final_url": str(resp.url),
                    "elapsed_ms": resp.elapsed.total_seconds() * 1000,
                }

                if save_to:
                    # Save to disk — confined to the artifacts directory
                    try:
                        path = _safe_save_path(save_to)
                    except ValueError as e:
                        return {"error": str(e), "status_code": resp.status_code}
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as f:
                        f.write(resp.content)
                    result["saved_to"] = path
                    result["body_preview"] = resp.text[:200] if resp.text else f"<binary, {len(resp.content)} bytes>"
                elif extract_text and "text/html" in resp.headers.get("content-type", ""):
                    result["body"] = _strip_html(resp.text)
                    result["note"] = "HTML stripped to visible text only"
                else:
                    result["body"] = resp.text[:10000]  # truncate large responses

                return result
            except httpx.TimeoutException:
                return {"error": f"Request timed out after {timeout}s", "status_code": None}
            except httpx.ConnectError as e:
                hint = ""
                if "Name or service not known" in str(e) or "Errno -2" in str(e):
                    # Extract hostname from URL for hint
                    from urllib.parse import urlparse
                    host = urlparse(url).hostname or url
                    hint = f"DNS resolution failed for '{host}'. Add to /etc/hosts: echo '10.x.x.x {host}' | sudo tee -a /etc/hosts"
                return {"error": str(e), "hint": hint or "Connection failed", "status_code": None}
            except Exception as e:
                return {"error": str(e), "status_code": None}

    @mcp.tool()
    async def html_to_text(html: str) -> dict:
        """
        Strip HTML tags and extract visible text.
        Removes scripts, styles, tags. Returns clean readable text.
        html: HTML string
        """
        return {"text": _strip_html(html), "original_length": len(html)}

    @mcp.tool()
    async def extract_links(
        html: str,
        base_url: str = "",
        only_same_origin: bool = False,
    ) -> dict:
        """
        Extract all links (anchors, forms, scripts, images) from HTML.
        Useful for building a crawl tree without manually grep'ing the response body.
        html: HTML string
        base_url: optional base URL for resolving relative links
        only_same_origin: if True and base_url given, only return links to same host
        Returns: lists of links by category (anchors, forms, scripts, images, css)
        """
        from urllib.parse import urljoin, urlparse

        def _abs(url: str) -> str:
            return urljoin(base_url, url) if base_url else url

        # Extract by tag
        anchors = re.findall(r'<a\s+[^>]*href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        forms = re.findall(r'<form\s+[^>]*action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        scripts = re.findall(r'<script\s+[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        images = re.findall(r'<img\s+[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        css = re.findall(r'<link\s+[^>]*href=["\']([^"\']+)["\']', html, re.IGNORECASE)

        result = {
            "anchors": [_abs(u) for u in dict.fromkeys(anchors)],
            "forms": [_abs(u) for u in dict.fromkeys(forms)],
            "scripts": [_abs(u) for u in dict.fromkeys(scripts)],
            "images": [_abs(u) for u in dict.fromkeys(images)],
            "css": [_abs(u) for u in dict.fromkeys(css)],
        }

        if only_same_origin and base_url:
            base_host = urlparse(base_url).netloc
            for k, urls in result.items():
                result[k] = [u for u in urls if urlparse(u).netloc == base_host]

        result["total"] = sum(len(v) for v in result.values() if isinstance(v, list))
        return result

    @mcp.tool()
    async def http_form_submit(
        url: str,
        form_data: dict,
        method: str = "POST",
        headers: dict = {},
        cookies: dict = {},
        follow_redirects: bool = True,
    ) -> dict:
        """
        Submit an HTML form (simulates browser form POST).
        url: form action URL
        form_data: dict of form fields e.g. {"username": "admin", "password": "test"}
        method: POST (default) or GET
        headers: additional HTTP headers
        cookies: session cookies to include
        follow_redirects: follow redirects after submit (default True)
        Returns: response status, headers, body, redirect chain
        """
        check_scope(url)
        async with httpx.AsyncClient(follow_redirects=follow_redirects, timeout=30) as client:
            try:
                if method.upper() == "GET":
                    resp = await client.get(url, params=form_data, headers=headers, cookies=cookies)
                else:
                    resp = await client.post(url, data=form_data, headers=headers, cookies=cookies)
                return {
                    "status_code": resp.status_code,
                    "reason": resp.reason_phrase,
                    "headers": dict(resp.headers),
                    "cookies": dict(resp.cookies),
                    "body": resp.text[:10000],
                    "redirect_chain": [str(r.url) for r in resp.history],
                    "final_url": str(resp.url),
                }
            except Exception as e:
                return {"error": str(e)}
