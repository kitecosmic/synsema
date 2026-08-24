// Demo: un agente Synsema dentro de una app Go — sin backend Synsema (wazero, puro Go).
//
//	go run . ../../../engine/target/wasm32-unknown-unknown/wasm/synsema_wasm_web.wasm
//
// Glue de la ABI de synsema-wasm-web (ver engine/crates/synsema-wasm-web/src/lib.rs):
//
//	exports  synsema_alloc / synsema_free / synsema_call(json) -> [u32 LE len][json]
//	imports  synsema_host.{host_call, host_random_fill, host_now_ms}
//
// La app le presta al programa `http` (net/http), `kv` (un map) y `llm` (mock); el
// programa sigue declarando `require net/memory/llm` y el `ceiling` de la app manda.
// Termina con exit 1 si algo no da lo esperado.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Host es lo que la app presta. Cada campo nil = "no lo ofrezco".
type Host struct {
	HTTP func(req map[string]any) map[string]any
	KV   map[string]string // ns + "\x00" + key -> value
	LLM  func(op, prompt string) (string, int)
	Log  func(line string)
}

func (h *Host) offers() map[string]bool {
	o := map[string]bool{}
	if h.HTTP != nil {
		o["http"] = true
	}
	if h.KV != nil {
		o["kv"] = true
	}
	if h.LLM != nil {
		o["llm"] = true
	}
	if h.Log != nil {
		o["log"] = true
	}
	o["sleep"] = true
	return o
}

// dispatch devuelve (resultado, ofrecido). ofrecido=false → el guest recibe "no provisto".
func (h *Host) dispatch(kind string, payload map[string]any) (any, bool) {
	str := func(k string) string { s, _ := payload[k].(string); return s }
	switch kind {
	case "http":
		if h.HTTP == nil {
			return nil, false
		}
		return h.HTTP(payload), true
	case "kv_get":
		if h.KV == nil {
			return nil, false
		}
		v, ok := h.KV[str("ns")+"\x00"+str("key")]
		if !ok {
			return map[string]any{"value": nil}, true
		}
		return map[string]any{"value": v}, true
	case "kv_set":
		if h.KV == nil {
			return nil, false
		}
		h.KV[str("ns")+"\x00"+str("key")] = str("value")
		return map[string]any{}, true
	case "kv_delete":
		if h.KV == nil {
			return nil, false
		}
		delete(h.KV, str("ns")+"\x00"+str("key"))
		return map[string]any{}, true
	case "kv_list":
		if h.KV == nil {
			return nil, false
		}
		keys := []string{}
		for k := range h.KV {
			if strings.HasPrefix(k, str("ns")+"\x00") {
				keys = append(keys, strings.TrimPrefix(k, str("ns")+"\x00"))
			}
		}
		return map[string]any{"keys": keys}, true
	case "llm":
		if h.LLM == nil {
			return nil, false
		}
		content, tokens := h.LLM(str("op"), str("prompt"))
		return map[string]any{"content": content, "tokens": tokens}, true
	case "log":
		if h.Log == nil {
			return nil, false
		}
		h.Log(str("line"))
		return map[string]any{}, true
	case "sleep":
		secs, _ := payload["secs"].(float64)
		time.Sleep(time.Duration(secs * float64(time.Second)))
		return map[string]any{}, true
	}
	return nil, false
}

type Synsema struct {
	ctx  context.Context
	rt   wazero.Runtime
	mod  api.Module
	host *Host
}

func New(ctx context.Context, wasmPath string) (*Synsema, error) {
	bytes, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, err
	}
	rt := wazero.NewRuntime(ctx)
	s := &Synsema{ctx: ctx, rt: rt}

	// Escribe [u32 LE len][data] en el heap del guest (vía su synsema_alloc) y devuelve el ptr.
	writeBuf := func(m api.Module, data []byte) uint32 {
		res, err := m.ExportedFunction("synsema_alloc").Call(ctx, uint64(4+len(data)))
		if err != nil {
			panic(err)
		}
		ptr := uint32(res[0])
		var hdr [4]byte
		binary.LittleEndian.PutUint32(hdr[:], uint32(len(data)))
		m.Memory().Write(ptr, hdr[:])
		m.Memory().Write(ptr+4, data)
		return ptr
	}

	_, err = rt.NewHostModuleBuilder("synsema_host").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, kp, kl, pp, pl uint32) uint32 {
			kind, _ := m.Memory().Read(kp, kl)
			raw, _ := m.Memory().Read(pp, pl)
			var payload map[string]any
			_ = json.Unmarshal(raw, &payload)
			if s.host == nil {
				return 0
			}
			result, offered := s.host.dispatch(string(kind), payload)
			if !offered {
				return 0
			}
			out, _ := json.Marshal(result)
			return writeBuf(m, out)
		}).Export("host_call").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, ptr, n uint32) int32 {
			buf := make([]byte, n)
			if _, err := rand.Read(buf); err != nil {
				return 1
			}
			m.Memory().Write(ptr, buf)
			return 0
		}).Export("host_random_fill").
		NewFunctionBuilder().WithFunc(func() float64 {
			return float64(time.Now().UnixMilli())
		}).Export("host_now_ms").
		Instantiate(ctx)
	if err != nil {
		return nil, err
	}
	mod, err := rt.Instantiate(ctx, bytes)
	if err != nil {
		return nil, err
	}
	s.mod = mod
	return s, nil
}

// Call manda un request JSON al guest y devuelve la respuesta decodificada.
func (s *Synsema) Call(request map[string]any, host *Host) (map[string]any, error) {
	s.host = host
	defer func() { s.host = nil }()
	if host != nil {
		request["host"] = host.offers()
	}
	req, _ := json.Marshal(request)
	alloc := s.mod.ExportedFunction("synsema_alloc")
	free := s.mod.ExportedFunction("synsema_free")
	res, err := alloc.Call(s.ctx, uint64(len(req)))
	if err != nil {
		return nil, err
	}
	rp := uint32(res[0])
	s.mod.Memory().Write(rp, req)
	out, err := s.mod.ExportedFunction("synsema_call").Call(s.ctx, uint64(rp), uint64(len(req)))
	_, _ = free.Call(s.ctx, uint64(rp), uint64(len(req)))
	if err != nil {
		return nil, fmt.Errorf("the module trapped: %w", err)
	}
	ptr := uint32(out[0])
	hdr, _ := s.mod.Memory().Read(ptr, 4)
	n := binary.LittleEndian.Uint32(hdr)
	body, _ := s.mod.Memory().Read(ptr+4, n)
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	_, _ = free.Call(s.ctx, uint64(ptr), uint64(4+n))
	return resp, nil
}

func (s *Synsema) Run(source string, host *Host, extra map[string]any) map[string]any {
	req := map[string]any{"op": "run", "source": source, "filename": "<embedded>"}
	for k, v := range extra {
		req[k] = v
	}
	r, err := s.Call(req, host)
	if err != nil {
		panic(err)
	}
	return r
}

func (s *Synsema) Handle(source string, method, path string, host *Host) map[string]any {
	req := map[string]any{"op": "handle", "source": source, "request": map[string]any{"method": method, "path": path, "headers": [][]string{}, "body": ""}}
	r, err := s.Call(req, host)
	if err != nil {
		panic(err)
	}
	return r
}

func main() {
	wasm := "../../../engine/target/wasm32-unknown-unknown/wasm/synsema_wasm_web.wasm"
	if len(os.Args) > 1 {
		wasm = os.Args[1]
	}
	ctx := context.Background()
	syn, err := New(ctx, wasm)
	if err != nil {
		fmt.Println("load:", err)
		os.Exit(1)
	}
	defer syn.rt.Close(ctx)

	v, _ := syn.Call(map[string]any{"op": "version"}, nil)
	fmt.Println("synsema", v["version"])

	failed := 0
	check := func(name string, ok bool, detail any) {
		if ok {
			fmt.Println("  ok ", name)
		} else {
			failed++
			d, _ := json.Marshal(detail)
			fmt.Println("FAIL ", name, "--", string(d))
		}
	}
	outputs := func(r map[string]any) []string {
		var out []string
		for _, l := range r["output"].([]any) {
			out = append(out, l.(string))
		}
		return out
	}
	errs := func(r map[string]any) string {
		e, _ := r["errors"].([]any)
		if len(e) == 0 {
			return ""
		}
		return e[0].(string)
	}

	host := &Host{
		KV:  map[string]string{},
		LLM: func(op, prompt string) (string, int) { return "[" + op + "] " + prompt, 9 },
		Log: func(line string) { fmt.Println("   [host]", line) },
		HTTP: func(req map[string]any) map[string]any {
			method, _ := req["method"].(string)
			url, _ := req["url"].(string)
			body, _ := req["body"].(string)
			hr, err := http.NewRequest(method, url, strings.NewReader(body))
			if err != nil {
				return map[string]any{"status": 0, "error": err.Error()}
			}
			if hs, ok := req["headers"].([]any); ok {
				for _, kv := range hs {
					p := kv.([]any)
					hr.Header.Set(p[0].(string), p[1].(string))
				}
			}
			resp, err := http.DefaultClient.Do(hr)
			if err != nil {
				return map[string]any{"status": 0, "error": err.Error()}
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			headers := [][]string{}
			for k, vs := range resp.Header {
				headers = append(headers, []string{k, vs[0]})
			}
			return map[string]any{"status": resp.StatusCode, "headers": headers, "body": string(b)}
		},
	}

	// 1. Cómputo puro + secreto desde env.
	r := syn.Run("require secret(\"KEY\")\nprint(keccak256(\"hola\"))\nprint(type_of(secret(\"KEY\")))", nil, map[string]any{"env": map[string]string{"KEY": "abc"}})
	check("run: keccak + secret desde env", r["ok"] == true && outputs(r)[1] == "secret", r)

	// 2. Memoria persistente sobre el KV de la app (dos corridas).
	r = syn.Run("require memory(\"agenda\")\nremember(\"preference\", \"dark mode\", [\"ui\"])\nprint(memory_summary())", host, map[string]any{"filename": "agenda.syn"})
	check("memoria: remember -> kv del host", r["ok"] == true && strings.Contains(strings.Join(outputs(r), "\n"), "Backend: host-kv"), r)
	r = syn.Run("require memory(\"agenda\")\nprint(recall(search=\"dark\")[0][\"content\"])", host, map[string]any{"filename": "agenda.syn"})
	check("memoria: recall en otra corrida", r["ok"] == true && outputs(r)[0] == "dark mode", r)

	// 3. LLM del host + llm_usage.
	r = syn.Run("require llm\nprint(reason about \"el clima\")\nprint(llm_usage())", host, nil)
	check("llm: reason va al host y llm_usage cuenta", r["ok"] == true && strings.HasPrefix(outputs(r)[0], "[reason]") && outputs(r)[1] == "9", r)

	// 4. Red gateada: sin `require net` no se llama a net/http.
	r = syn.Run("let r be fetch(\"https://example.com\")", host, nil)
	check("red: sin require net -> denegado antes del host", r["ok"] == false && strings.Contains(errs(r), "Capability not granted: net"), r)
	if os.Getenv("SYNSEMA_DEMO_ONLINE") != "" {
		r = syn.Run("require net(\"example.com\")\nlet r be fetch(\"https://example.com\")\nprint(r[\"status\"])", host, nil)
		check("red: fetch real via net/http", r["ok"] == true && outputs(r)[0] == "200", r)
	}

	// 5. serve en modo handler + state_* durable en el kv.
	app := "require serve(8080)\nserve on 8080\n    route \"GET /saludo/:nombre\"\n        give {\"hola\": params.nombre, \"visitas\": state_incr(\"visitas\")}\n"
	a := syn.Handle(app, "GET", "/saludo/ana", host)
	b := syn.Handle(app, "GET", "/saludo/ana", host)
	check("handle: ruta + state_incr durable", a["status"] == float64(200) && strings.Contains(a["body"].(string), "\"visitas\": 1") && strings.Contains(b["body"].(string), "\"visitas\": 2"), []any{a, b})

	// 6. El techo de la app manda.
	r = syn.Run("require llm\nprint(reason about \"x\")", host, map[string]any{"ceiling": "stdout"})
	check("ceiling: la app deniega llm aunque lo ofrezca", r["ok"] == false && strings.Contains(errs(r), "Capability not granted: llm"), r)

	if failed > 0 {
		fmt.Printf("%d FAIL\n", failed)
		os.Exit(1)
	}
	fmt.Println("all ok")
}
