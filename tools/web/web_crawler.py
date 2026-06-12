"""Web crawler — follows links to discover endpoints, forms, and interesting paths."""
import re
from urllib.parse import urljoin, urlparse

import httpx

from scope import check_scope


def _register(mcp, job_mgr):

    @mcp.tool()
    async def web_crawl(
        url: str,
        max_depth: int = 2,
        max_pages: int = 50,
        include_external: bool = False,
        timeout: int = 10,
    ) -> dict:
        """
        Crawl a web application by following links organically.
        Discovers endpoints, forms, and interesting paths that wordlist brute-force misses.
        url: starting URL (e.g. 'http://example.com/')
        max_depth: how many link levels deep to follow (default 2)
        max_pages: max pages to visit (default 50)
        include_external: also collect external links (not crawled, just listed)
        timeout: per-request timeout in seconds
        Returns: discovered URLs by category, forms, and interesting endpoints
        """
        check_scope(url)
        base = urlparse(url)
        base_origin = f"{base.scheme}://{base.netloc}"

        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(url, 0)]
        pages: list[dict] = []
        forms: list[dict] = []
        external: list[str] = []
        interesting: list[str] = []

        _INTERESTING = re.compile(
            r"(admin|login|signup|register|upload|api|config|backup|"
            r"phpinfo|\.git|\.env|\.sql|password|secret|token|key)",
            re.IGNORECASE
        )

        async with httpx.AsyncClient(
            follow_redirects=True, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"}
        ) as client:
            while queue and len(visited) < max_pages:
                current_url, depth = queue.pop(0)
                if current_url in visited:
                    continue
                visited.add(current_url)

                try:
                    resp = await client.get(current_url)
                    body = resp.text
                except Exception:
                    continue

                page_info = {
                    "url": current_url,
                    "status": resp.status_code,
                    "content_type": resp.headers.get("content-type", ""),
                    "size": len(body),
                }
                pages.append(page_info)

                if _INTERESTING.search(current_url):
                    interesting.append(current_url)

                if depth >= max_depth:
                    continue

                # Extract links
                for href in re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE):
                    abs_url = urljoin(current_url, href).split("#")[0].split("?")[0]
                    parsed = urlparse(abs_url)
                    if parsed.netloc == base.netloc:
                        if abs_url not in visited:
                            queue.append((abs_url, depth + 1))
                    elif include_external and abs_url.startswith("http"):
                        external.append(abs_url)

                # Extract forms
                for form_match in re.finditer(
                    r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                    body, re.DOTALL | re.IGNORECASE
                ):
                    action = urljoin(current_url, form_match.group(1))
                    inputs = re.findall(
                        r'<input[^>]*name=["\']([^"\']+)["\']', form_match.group(2)
                    )
                    method = re.search(r'method=["\'](\w+)["\']', form_match.group(0))
                    forms.append({
                        "action": action,
                        "method": (method.group(1).upper() if method else "GET"),
                        "inputs": inputs,
                        "found_on": current_url,
                    })

        return {
            "start_url": url,
            "pages_visited": len(visited),
            "pages": pages[:30],
            "forms": forms,
            "interesting": list(set(interesting)),
            "external_links": list(set(external))[:20],
            "all_urls": sorted(visited),
        }
