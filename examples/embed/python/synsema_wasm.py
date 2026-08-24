"""Synsema embebido en Python vía wasmtime-py — glue de la ABI de synsema-wasm-web.

    pip install wasmtime
    python demo.py ../../../engine/target/wasm32-unknown-unknown/wasm/synsema_wasm_web.wasm

ABI (ver engine/crates/synsema-wasm-web/src/lib.rs):
  exports  synsema_alloc(len) / synsema_free(ptr, len) / synsema_call(ptr, len) -> ptr
           (buffer [u32 LE len][json]; se libera con synsema_free(ptr, 4 + len))
  imports  synsema_host.host_call / host_random_fill / host_now_ms

El host es un dict con lo que tu app le PRESTA al programa (todo opcional):
  {"http": fn(req) -> dict, "kv": obj con get/set/delete/list, "llm": fn(op, prompt),
   "log": fn(line), "sleep": fn(secs) | True}
Python es síncrono, así que no hace falta ningún bridge: urllib/requests resuelven ahí.
"""

import json
import os
import struct
import time

from wasmtime import Func, FuncType, Linker, Module, Store, ValType


def offers_of(host):
    o = {}
    if host is None:
        return o
    if callable(host.get("http")):
        o["http"] = True
    if host.get("kv") is not None:
        o["kv"] = True
    if callable(host.get("llm")):
        o["llm"] = True
    if callable(host.get("log")):
        o["log"] = True
    if host.get("sleep"):
        o["sleep"] = True
    return o


def _normalize_http(r):
    if not isinstance(r, dict):
        return {"error": "host http returned nothing"}
    out = {"status": int(r.get("status", 0)), "headers": []}
    if r.get("error"):
        out["error"] = str(r["error"])
    h = r.get("headers") or []
    out["headers"] = [[k, v] for k, v in (h.items() if isinstance(h, dict) else h)]
    body = r.get("body")
    if isinstance(body, (bytes, bytearray)):
        import base64

        out["body_base64"] = base64.b64encode(bytes(body)).decode("ascii")
    elif body is not None:
        out["body"] = str(body)
    return out


def dispatch_host(host, kind, payload):
    """Devuelve un objeto JSON-serializable, o None si el host no ofrece ese hook."""
    if host is None:
        return None
    if kind == "http":
        return _normalize_http(host["http"](payload)) if callable(host.get("http")) else None
    kv = host.get("kv")
    if kind == "kv_get":
        return {"value": kv.get(payload["ns"], payload["key"])} if kv is not None else None
    if kind == "kv_set":
        if kv is None:
            return None
        kv.set(payload["ns"], payload["key"], payload["value"])
        return {}
    if kind == "kv_delete":
        if kv is None:
            return None
        if hasattr(kv, "delete"):
            kv.delete(payload["ns"], payload["key"])
        return {}
    if kind == "kv_list":
        if kv is None:
            return None
        return {"keys": kv.list(payload["ns"]) if hasattr(kv, "list") else []}
    if kind == "llm":
        if not callable(host.get("llm")):
            return None
        r = host["llm"](payload["op"], payload["prompt"])
        return {"content": r, "tokens": 0} if isinstance(r, str) else {"content": str(r.get("content", "")), "tokens": int(r.get("tokens", 0))}
    if kind == "log":
        if not callable(host.get("log")):
            return None
        host["log"](payload["line"])
        return {}
    if kind == "sleep":
        s = host.get("sleep")
        if callable(s):
            s(payload["secs"])
            return {}
        if s is True:
            time.sleep(payload["secs"])
            return {}
        return None
    return None


class Synsema:
    def __init__(self, wasm_path):
        self.store = Store()
        self.module = Module.from_file(self.store.engine, wasm_path)
        self._host = None
        linker = Linker(self.store.engine)
        i32, f64 = ValType.i32(), ValType.f64()
        linker.define_func("synsema_host", "host_call", FuncType([i32, i32, i32, i32], [i32]), self._host_call)
        linker.define_func("synsema_host", "host_random_fill", FuncType([i32, i32], [i32]), self._random_fill)
        linker.define_func("synsema_host", "host_now_ms", FuncType([], [f64]), lambda: time.time() * 1000.0)
        self.inst = linker.instantiate(self.store, self.module)
        ex = self.inst.exports(self.store)
        self.mem = ex["memory"]
        self._alloc = ex["synsema_alloc"]
        self._free = ex["synsema_free"]
        self._call = ex["synsema_call"]

    # -- memoria lineal --
    def _read(self, ptr, n):
        return bytes(self.mem.read(self.store, ptr, ptr + n))

    def _write_buf(self, data):
        """Escribe [u32 LE len][data] en un buffer del guest y devuelve el ptr."""
        ptr = self._alloc(self.store, 4 + len(data))
        self.mem.write(self.store, struct.pack("<I", len(data)) + data, ptr)
        return ptr

    # -- imports --
    def _host_call(self, kp, kl, pp, pl):
        kind = self._read(kp, kl).decode()
        payload = json.loads(self._read(pp, pl).decode())
        try:
            result = dispatch_host(self._host, kind, payload)
        except Exception as e:  # el error del host viaja como dato, no como trap
            result = {"error": str(e)}
        if result is None:
            return 0
        return self._write_buf(json.dumps(result).encode())

    def _random_fill(self, ptr, n):
        self.mem.write(self.store, os.urandom(n), ptr)
        return 0

    # -- API --
    def call(self, request, host=None):
        self._host = host
        try:
            req = json.dumps(request).encode()
            rp = self._alloc(self.store, len(req))
            self.mem.write(self.store, req, rp)
            out = self._call(self.store, rp, len(req))
            self._free(self.store, rp, len(req))
            n = struct.unpack("<I", self._read(out, 4))[0]
            body = self._read(out + 4, n)
            self._free(self.store, out, 4 + n)
            return json.loads(body.decode())
        finally:
            self._host = None

    def _req(self, op, source, filename="<embedded>", env=None, ceiling=None, host=None):
        r = {"op": op, "source": source, "filename": filename}
        if env:
            r["env"] = env
        if ceiling:
            r["ceiling"] = ceiling
        if host:
            r["host"] = offers_of(host)
        return r

    def version(self):
        return self.call({"op": "version"})["version"]

    def run(self, source, **kw):
        return self.call(self._req("run", source, **kw), kw.get("host"))

    def test(self, source, **kw):
        return self.call(self._req("test", source, **kw), kw.get("host"))

    def check(self, source, filename="<embedded>"):
        return self.call({"op": "check", "source": source, "filename": filename})

    def handle(self, source, request, **kw):
        r = self._req("handle", source, **kw)
        body = request.get("body", "")
        rq = {
            "method": request.get("method", "GET"),
            "path": request.get("path", "/"),
            "headers": [[k, v] for k, v in (request.get("headers") or {}).items()] if isinstance(request.get("headers"), dict) else (request.get("headers") or []),
            "ip": request.get("ip", ""),
        }
        if isinstance(body, (bytes, bytearray)):
            import base64

            rq["body_base64"] = base64.b64encode(bytes(body)).decode("ascii")
        else:
            rq["body"] = "" if body is None else str(body)
        r["request"] = rq
        return self.call(r, kw.get("host"))
