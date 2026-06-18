"""
Syntecnia Native HTTP — Zero-dependency HTTP client.

Clean, readable syntax for HTTP requests:

    let response be http("GET", "https://api.store.com/products",
        headers = {"Authorization": "Bearer sk-123"},
        query = {"page": "1", "limit": "10"}
    )

    let response be http("POST", "https://api.store.com/orders",
        headers = {"Content-Type": "application/json"},
        body = {"product": "laptop", "quantity": 1}
    )

Shorthand builtins:
    let data be http_get(url, headers?, query?)
    let data be http_post(url, body, headers?)
    let data be http_put(url, body, headers?)
    let data be http_delete(url, headers?)

Response is always a map:
    {
        "status": 200,
        "ok": true,
        "body": "...",
        "headers": {"content-type": "application/json", ...},
        "json": {...}  (auto-parsed if content-type is json)
    }

Uses only Python stdlib (urllib). No requests, no httpx, nothing external.
"""

import json as _json
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional, Any


def http_request(method: str, url: str,
                 headers: Dict[str, str] = None,
                 query: Dict[str, str] = None,
                 body: Any = None,
                 timeout: int = 30) -> Dict[str, Any]:
    """
    Make an HTTP request. Returns a structured response dict.

    This is the single function that handles all HTTP communication.
    No external dependencies.
    """
    # Build URL with query parameters
    if query:
        separator = "&" if "?" in url else "?"
        query_string = urllib.parse.urlencode(query)
        url = f"{url}{separator}{query_string}"

    # Prepare body
    body_bytes = None
    if body is not None:
        if isinstance(body, dict):
            body_bytes = _json.dumps(body).encode("utf-8")
            if headers is None:
                headers = {}
            if "Content-Type" not in headers and "content-type" not in headers:
                headers["Content-Type"] = "application/json"
        elif isinstance(body, str):
            body_bytes = body.encode("utf-8")
        elif isinstance(body, bytes):
            body_bytes = body

    # Build request
    req = urllib.request.Request(url, method=method.upper())
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)
    if body_bytes:
        req.data = body_bytes

    # Execute
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            response_body = resp.read().decode("utf-8")
            response_headers = dict(resp.headers)
            status = resp.status

            # Auto-parse JSON
            json_data = None
            content_type = response_headers.get("content-type", "")
            if "json" in content_type.lower():
                try:
                    json_data = _json.loads(response_body)
                except _json.JSONDecodeError:
                    pass

            return {
                "status": status,
                "ok": 200 <= status < 300,
                "body": response_body,
                "headers": response_headers,
                "json": json_data,
            }

    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")
        except:
            pass
        return {
            "status": e.code,
            "ok": False,
            "body": error_body,
            "headers": dict(e.headers) if e.headers else {},
            "json": None,
            "error": str(e),
        }
    except urllib.error.URLError as e:
        return {
            "status": 0,
            "ok": False,
            "body": "",
            "headers": {},
            "json": None,
            "error": str(e),
        }
    except Exception as e:
        return {
            "status": 0,
            "ok": False,
            "body": "",
            "headers": {},
            "json": None,
            "error": f"{type(e).__name__}: {e}",
        }


def register_http_builtins(env, capability_checker=None):
    """Register HTTP builtins in a Syntecnia environment."""
    from ..core.types import (
        SynValue, BuiltinTask, SynTask,
        syn_number, syn_text, syn_bool, syn_nothing, syn_list, syn_map,
        SynMap, SynText, SynList,
    )

    def _to_python_dict(syn_map_val):
        """Convert a SynValue map to a Python dict of strings."""
        if not isinstance(syn_map_val.type, SynMap):
            return {}
        return {str(k): str(v) for k, v in syn_map_val.raw.items()}

    def _to_python_any(syn_val):
        """Convert SynValue to Python-native for JSON body."""
        if isinstance(syn_val.type, SynMap):
            result = {}
            for k, v in syn_val.raw.items():
                result[str(k)] = _to_python_any(v)
            return result
        if isinstance(syn_val.type, SynList):
            return [_to_python_any(item) for item in syn_val.raw]
        if hasattr(syn_val, 'raw'):
            return syn_val.raw
        return str(syn_val)

    def _response_to_syn(response: dict) -> SynValue:
        """Convert HTTP response dict to SynValue map."""
        result = {
            "status": syn_number(response["status"]),
            "ok": syn_bool(response["ok"]),
            "body": syn_text(response.get("body", "")),
        }
        # Headers
        if response.get("headers"):
            header_map = {k: syn_text(str(v)) for k, v in response["headers"].items()}
            result["headers"] = syn_map(header_map)
        # JSON (recursive conversion)
        if response.get("json") is not None:
            result["json"] = _python_to_syn(response["json"])
        # Error
        if response.get("error"):
            result["error"] = syn_text(response["error"])
        return syn_map(result)

    def _python_to_syn(val) -> SynValue:
        """Convert Python value to SynValue recursively."""
        if val is None:
            return syn_nothing()
        if isinstance(val, bool):
            return syn_bool(val)
        if isinstance(val, (int, float)):
            return syn_number(val)
        if isinstance(val, str):
            return syn_text(val)
        if isinstance(val, list):
            return syn_list([_python_to_syn(item) for item in val])
        if isinstance(val, dict):
            return syn_map({str(k): _python_to_syn(v) for k, v in val.items()})
        return syn_text(str(val))

    # -- Builtins --

    def _http(args):
        """http(method, url, headers?, query?, body?, timeout?)"""
        method = str(args[0].raw)
        url = str(args[1].raw)
        headers = _to_python_dict(args[2]) if len(args) > 2 and isinstance(args[2].type, SynMap) else None
        query = _to_python_dict(args[3]) if len(args) > 3 and isinstance(args[3].type, SynMap) else None
        body = _to_python_any(args[4]) if len(args) > 4 else None
        timeout = int(args[5].raw) if len(args) > 5 else 30
        response = http_request(method, url, headers, query, body, timeout)
        return _response_to_syn(response)

    def _http_get(args):
        """http_get(url, headers?, query?)"""
        url = str(args[0].raw)
        headers = _to_python_dict(args[1]) if len(args) > 1 and isinstance(args[1].type, SynMap) else None
        query = _to_python_dict(args[2]) if len(args) > 2 and isinstance(args[2].type, SynMap) else None
        response = http_request("GET", url, headers, query)
        return _response_to_syn(response)

    def _http_post(args):
        """http_post(url, body, headers?)"""
        url = str(args[0].raw)
        body = _to_python_any(args[1]) if len(args) > 1 else None
        headers = _to_python_dict(args[2]) if len(args) > 2 and isinstance(args[2].type, SynMap) else None
        response = http_request("POST", url, headers, body=body)
        return _response_to_syn(response)

    def _http_put(args):
        """http_put(url, body, headers?)"""
        url = str(args[0].raw)
        body = _to_python_any(args[1]) if len(args) > 1 else None
        headers = _to_python_dict(args[2]) if len(args) > 2 and isinstance(args[2].type, SynMap) else None
        response = http_request("PUT", url, headers, body=body)
        return _response_to_syn(response)

    def _http_delete(args):
        """http_delete(url, headers?)"""
        url = str(args[0].raw)
        headers = _to_python_dict(args[1]) if len(args) > 1 and isinstance(args[1].type, SynMap) else None
        response = http_request("DELETE", url, headers)
        return _response_to_syn(response)

    builtins = {
        "http": BuiltinTask("http", _http),
        "http_get": BuiltinTask("http_get", _http_get),
        "http_post": BuiltinTask("http_post", _http_post),
        "http_put": BuiltinTask("http_put", _http_put),
        "http_delete": BuiltinTask("http_delete", _http_delete),
    }
    for name, builtin in builtins.items():
        env.set(name, SynValue(raw=builtin, type=SynTask()))
