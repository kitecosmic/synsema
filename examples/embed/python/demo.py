"""Demo: un agente Synsema dentro de una app Python — sin backend Synsema.

    pip install wasmtime
    python demo.py [ruta/al/synsema_wasm_web.wasm]

La app le presta al programa: `http` (urllib), `kv` (un dict → archivo JSON), `llm`
(mock; conectá tu SDK) y `log`. El programa sigue declarando `require net/memory/llm`
y el `ceiling` de la app sigue mandando. Termina con exit 1 si algo no da lo esperado.
"""

import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from synsema_wasm import Synsema  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WASM = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    HERE, "..", "..", "..", "engine", "target", "wasm32-unknown-unknown", "wasm", "synsema_wasm_web.wasm"
)


class FileKv:
    """KV durable de juguete: un JSON en disco (en producción: Redis, SQLite, lo que uses)."""

    def __init__(self, path):
        self.path = path
        self.data = json.load(open(path)) if os.path.exists(path) else {}

    def get(self, ns, key):
        return self.data.get(ns, {}).get(key)

    def set(self, ns, key, value):
        self.data.setdefault(ns, {})[key] = value
        json.dump(self.data, open(self.path, "w"))

    def delete(self, ns, key):
        self.data.get(ns, {}).pop(key, None)
        json.dump(self.data, open(self.path, "w"))

    def list(self, ns):
        return list(self.data.get(ns, {}).keys())


def http(req):
    """El `http` del host: urllib síncrono. El programa ya pasó el gate `require net`."""
    data = req.get("body")
    r = urllib.request.Request(req["url"], method=req["method"], data=data.encode() if data else None)
    for k, v in req["headers"]:
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=req["timeout"]) as resp:
            return {"status": resp.status, "headers": dict(resp.headers), "body": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "headers": dict(e.headers), "body": e.read().decode("utf-8", "replace")}
    except Exception as e:  # DNS, timeout…: el programa lo ve en {error: …}
        return {"status": 0, "error": str(e)}


def llm(op, prompt):
    # Acá iría tu SDK (Anthropic/OpenAI/local). El mock devuelve algo reconocible.
    return {"content": f"[{op}] {prompt[:40]}", "tokens": 12}


host = {"http": http, "kv": FileKv(os.path.join(HERE, "agenda.kv.json")), "llm": llm, "log": lambda line: print("   [host]", line), "sleep": True}

syn = Synsema(WASM)
print("synsema", syn.version())
failed = 0


def check(name, ok, detail=None):
    global failed
    print(("  ok  " if ok else "FAIL  ") + name + ("" if ok else f" -- {detail}"))
    failed += 0 if ok else 1


# 1. Cómputo puro + secreto desde `env` (reemplaza al .env).
r = syn.run('require secret("KEY")\nprint(keccak256("hola"))\nprint(type_of(secret("KEY")))', env={"KEY": "abc"})
check("run: keccak + secret desde env", r["ok"] and r["output"][1] == "secret", r)

# 2. Memoria persistente sobre el KV de la app (dos corridas).
r = syn.run('require memory("agenda")\nremember("preference", "responder en español", ["idioma"])\nprint(memory_summary())', filename="agenda.syn", host=host)
check("memoria: remember -> kv del host", r["ok"] and "Backend: host-kv" in "\n".join(r["output"]), r)
r = syn.run('require memory("agenda")\nprint(recall(search="español")[0]["content"])', filename="agenda.syn", host=host)
check("memoria: recall en otra corrida", r["ok"] and r["output"][0] == "responder en español", r)

# 3. LLM del host + audit.
r = syn.run('require llm\nprint(reason about "el clima")\nprint(llm_usage())', host=host)
check("llm: reason va al host y llm_usage cuenta", r["ok"] and r["output"][0].startswith("[reason]") and r["output"][1] == "12", r)
check("audit: cada chequeo de capability queda registrado", any(a["capability"] == "llm" for a in r["audit"]), r["audit"])

# 4. Red del host, gateada: sin `require net` no se llama a urllib.
r = syn.run('let r be fetch("https://example.com")', host=host)
check("red: sin require net -> denegado antes del host", not r["ok"] and "Capability not granted: net" in r["errors"][0], r)
if os.environ.get("SYNSEMA_DEMO_ONLINE"):
    r = syn.run('require net("example.com")\nlet r be fetch("https://example.com")\nprint(r["status"])', host=host)
    check("red: fetch real vía urllib", r["ok"] and r["output"][0] == "200", r)

# 5. serve en modo handler: la app entrega el request, recibe la respuesta.
app = '''require serve(8080)
serve on 8080
    route "GET /saludo/:nombre"
        give {"hola": params.nombre, "visitas": state_incr("visitas")}
'''
a = syn.handle(app, {"method": "GET", "path": "/saludo/ana"}, host=host)
b = syn.handle(app, {"method": "GET", "path": "/saludo/ana"}, host=host)
check("handle: ruta + state_incr durable en el kv", a["status"] == 200 and '"visitas": 1' in a["body"] and '"visitas": 2' in b["body"], (a, b))

# 6. El techo de la app manda aunque el host ofrezca todo.
r = syn.run('require llm\nprint(reason about "x")', host=host, ceiling="stdout")
check("ceiling: la app deniega llm aunque lo ofrezca", not r["ok"] and "Capability not granted: llm" in r["errors"][0], r)

os.remove(os.path.join(HERE, "agenda.kv.json"))
print("all ok" if not failed else f"{failed} FAIL")
sys.exit(1 if failed else 0)
