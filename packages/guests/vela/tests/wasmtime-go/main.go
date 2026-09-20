// Sonda del guest de Vela bajo wasmtime-go v1.0.0 — la MISMA versión del runtime que el Executor
// de Vela 0.2.0 (`vela/go.mod`), instanciado como él: `DefineWasi()` y nada más, sin `_start`, y
// los exports llamados con punteros a memoria lineal. Si el módulo compila, instancia y responde
// acá, compila, instancia y responde en el Executor; la sonda de Node (`tests/vela_guest.probe.mjs`)
// cubre el contrato en detalle, ésta cubre el runtime exacto.
//
//	cd packages/guests/vela/tests/wasmtime-go
//	go run . ../../../../../engine/target/wasm32-wasip1/wasm/synsema_vela_guest.wasm
//
// Además afirma lo que Vela v0.3.0 (rama `dev`, `pkg/wasm/guest_imports.go`) exige al cargar: el
// módulo sólo puede DECLARAR ocho imports de `wasi_snapshot_preview1`; cualquier otro se rechaza
// antes de instanciar. Y mide compilación e instanciación en ms: v0.3.0 acota cada operación del
// guest — la instanciación incluida — a 10 s (`EXECUTOR_GUEST_EXECUTION_TIMEOUT_MS`). La sonda
// hermana `tests/wasmtime-go-v47/` hace el mismo recorrido bajo wasmtime-go v47, el runtime de dev.
//
// Necesita Go ≥ 1.21 y un compilador C (cgo): gcc/clang en Linux y macOS, MinGW-w64 en Windows.
// Variables opcionales: DEPLOY_PARAMS (JSON de constructorParams) y PAYLOAD (el JSON del
// process_request; por defecto el transfer de la app de ejemplo).
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/bytecodealliance/wasmtime-go"
)

// La lista cerrada de Vela dev (`guest_imports.go`, v0.3.0): el import set exacto que TinyGo emite
// para un guest sin I/O. Nuestro guest (Rust/std) la cumple sólo después de `tools/wasi-stub`.
// Cambiarla es un cambio de ABI de Vela; si Horizen la amplía, se amplía acá y en wasi-stub.
var allowedGuestImports = map[string]struct{}{
	"wasi_snapshot_preview1.args_get":          {},
	"wasi_snapshot_preview1.args_sizes_get":    {},
	"wasi_snapshot_preview1.clock_time_get":    {},
	"wasi_snapshot_preview1.environ_get":       {},
	"wasi_snapshot_preview1.environ_sizes_get": {},
	"wasi_snapshot_preview1.fd_write":          {},
	"wasi_snapshot_preview1.proc_exit":         {},
	"wasi_snapshot_preview1.random_get":        {},
}

// checkGuestImportsAllowed: el mismo recorrido que Vela dev hace tras compilar y antes de
// instanciar. Devuelve los imports declarados (para el resumen) y los rechazados, ordenados.
func checkGuestImportsAllowed(module *wasmtime.Module) (declared []string, rejected []string) {
	seen := map[string]struct{}{}
	for _, imp := range module.Imports() {
		name := "<module import>"
		if n := imp.Name(); n != nil {
			name = *n
		}
		q := imp.Module() + "." + name
		declared = append(declared, strings.TrimPrefix(q, "wasi_snapshot_preview1."))
		if _, ok := allowedGuestImports[q]; ok {
			continue
		}
		if _, dup := seen[q]; dup {
			continue
		}
		seen[q] = struct{}{}
		rejected = append(rejected, q)
	}
	sort.Strings(declared)
	sort.Strings(rejected)
	return declared, rejected
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000.0)
}

type guest struct {
	store *wasmtime.Store
	inst  *wasmtime.Instance
	mem   *wasmtime.Memory
}

func (g *guest) call(name string, args ...interface{}) (int32, error) {
	f := g.inst.GetFunc(g.store, name)
	if f == nil {
		return 0, fmt.Errorf("export %s not found", name)
	}
	r, err := f.Call(g.store, args...)
	if err != nil {
		return 0, err
	}
	if r == nil { // deallocate / get_allocated_memory_stats no devuelven nada
		return 0, nil
	}
	return r.(int32), nil
}

// Como writeToMemory del Executor: allocate + copia; ptr 0 para un buffer vacío.
func (g *guest) write(data []byte) (int32, error) {
	if len(data) == 0 {
		return 0, nil
	}
	ptr, err := g.call("allocate", int32(len(data)))
	if err != nil {
		return 0, err
	}
	copy(g.mem.UnsafeData(g.store)[ptr:int(ptr)+len(data)], data)
	return ptr, nil
}

func (g *guest) free(ptr int32, n int) {
	if ptr != 0 {
		_, _ = g.call("deallocate", ptr, int32(n))
	}
}

// Como extractResultBytes del Executor: [u32 LE len][json], liberado con deallocate(ptr, 4+len).
func (g *guest) result(ptr int32) ([]byte, error) {
	if ptr == 0 {
		return nil, fmt.Errorf("null result pointer")
	}
	data := g.mem.UnsafeData(g.store)
	n := binary.LittleEndian.Uint32(data[ptr : ptr+4])
	out := make([]byte, n)
	copy(out, data[int(ptr)+4:int(ptr)+4+int(n)])
	g.free(ptr, 4+int(n))
	return out, nil
}

func hexAddr(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	b := make([]byte, 20)
	for i := 0; i < 20; i++ {
		fmt.Sscanf(s[2*i:2*i+2], "%02x", &b[i])
	}
	return b
}

func fail(what string, err error) {
	fmt.Printf("FAIL %s: %v\n", what, err)
	os.Exit(1)
}

type result struct {
	State []byte `json:"state"`
	Fuel  string `json:"fuel"`
	Error string `json:"error"`
}

func parse(out []byte, what string) result {
	var r result
	if err := json.Unmarshal(out, &r); err != nil {
		fail(what+": result is not the Executor's JSON", err)
	}
	if r.Error != "" {
		fail(what, fmt.Errorf("the app answered an error: %s", r.Error))
	}
	return r
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: go run . <synsema_vela_guest.wasm>")
		os.Exit(2)
	}
	wasmBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail("read", err)
	}
	engine := wasmtime.NewEngine()
	t0 := time.Now()
	module, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		fail("compile under wasmtime 1.0", err)
	}
	compileTime := time.Since(t0)
	fmt.Printf("ok   compiled under wasmtime-go v1.0.0 (%d bytes) in %s\n", len(wasmBytes), ms(compileTime))

	// Vela v0.3.0: imports declarados ⊆ los ocho permitidos, o el módulo no carga (firmado como
	// FAILED_LOADING_OR_GETTING_MODULE). Se lista todo lo sobrante de una vez, como hace Vela.
	declared, rejected := checkGuestImportsAllowed(module)
	if len(rejected) > 0 {
		fail("imports (Vela v0.3.0 closed set)", fmt.Errorf("the module declares %d host import(s) Vela refuses: %s — run tools/wasi-stub on it", len(rejected), strings.Join(rejected, ", ")))
	}
	fmt.Printf("ok   imports ⊆ Vela v0.3.0's allowed set (%d declared: %s)\n", len(declared), strings.Join(declared, ", "))

	store := wasmtime.NewStore(engine)
	wasi := wasmtime.NewWasiConfig()
	wasi.InheritStdout() // el Executor lo manda a su log server con prefijos INF/WRN/ERR
	wasi.InheritStderr()
	store.SetWasi(wasi)
	linker := wasmtime.NewLinker(engine)
	if err := linker.DefineWasi(); err != nil {
		fail("DefineWasi", err)
	}
	t1 := time.Now()
	inst, err := linker.Instantiate(store, module)
	if err != nil {
		fail("instantiate (only WASI imports are provided)", err)
	}
	instantiateTime := time.Since(t1)
	memExport := inst.GetExport(store, "memory")
	if memExport == nil || memExport.Memory() == nil {
		fail("memory export", fmt.Errorf("missing"))
	}
	g := &guest{store: store, inst: inst, mem: memExport.Memory()}
	for _, name := range []string{"allocate", "deallocate", "load_module", "deploy", "deposit", "process_request", "trusted_request"} {
		if inst.GetFunc(store, name) == nil {
			fail("export "+name, fmt.Errorf("missing"))
		}
	}
	fmt.Printf("ok   instantiated in %s; all exports the Executor looks up are present\n", ms(instantiateTime))

	// load_module (cache warm-up) — la primera llamada paga el arranque del intérprete
	t2 := time.Now()
	p, err := g.call("load_module", int64(1))
	if err != nil {
		fail("load_module (trap)", err)
	}
	firstCallTime := time.Since(t2)
	out, _ := g.result(p)
	parse(out, "load_module")
	fmt.Printf("ok   load_module in %s → %s\n", ms(firstCallTime), out)

	// deploy
	params := []byte(os.Getenv("DEPLOY_PARAMS"))
	pp, _ := g.write(params)
	p, err = g.call("deploy", int64(1), pp, int32(len(params)))
	g.free(pp, len(params))
	if err != nil {
		fail("deploy (trap)", err)
	}
	out, _ = g.result(p)
	state := parse(out, "deploy").State
	fmt.Printf("ok   deploy → %s\n", out)

	// deposit: 1 ETH from ALICE (sender/token = 20 bytes, value = big.Int big-endian)
	alice := hexAddr("0x1111111111111111111111111111111111111111")
	eth := make([]byte, 20)
	value, _ := new(big.Int).SetString("1000000000000000000", 10)
	vb := value.Bytes()
	sp, _ := g.write(alice)
	tp, _ := g.write(eth)
	vp, _ := g.write(vb)
	stp, _ := g.write(state)
	p, err = g.call("deposit", int64(1), sp, int32(20), tp, int32(20), vp, int32(len(vb)), stp, int32(len(state)))
	g.free(sp, 20)
	g.free(tp, 20)
	g.free(vp, len(vb))
	g.free(stp, len(state))
	if err != nil {
		fail("deposit (trap)", err)
	}
	out, _ = g.result(p)
	state = parse(out, "deposit").State
	fmt.Printf("ok   deposit → %d bytes of result, state %d bytes\n", len(out), len(state))

	// process_request PROCESS (1)
	payload := []byte(os.Getenv("PAYLOAD"))
	if len(payload) == 0 {
		payload = []byte(`{"type":"transfer","to":"0x2222222222222222222222222222222222222222","amount":"250000000000000000"}`)
	}
	sp, _ = g.write(alice)
	plp, _ := g.write(payload)
	stp, _ = g.write(state)
	p, err = g.call("process_request", int64(1), sp, int32(20), int32(1), plp, int32(len(payload)), stp, int32(len(state)))
	g.free(sp, 20)
	g.free(plp, len(payload))
	g.free(stp, len(state))
	if err != nil {
		fail("process_request (trap)", err)
	}
	out, _ = g.result(p)
	parse(out, "process_request")
	fmt.Printf("ok   process_request → %s\n", out)
	// Vela v0.3.0 acota cada operación del guest a 10 s, la instanciación incluida: el número que
	// importa es compile + instantiate + primera llamada, medido acá para dejarlo anotado.
	fmt.Printf("timing: compile %s, instantiate %s, first call %s (Vela v0.3.0 bounds one guest operation, instantiation included, to 10 s)\n",
		ms(compileTime), ms(instantiateTime), ms(firstCallTime))
	fmt.Println("ALL OK under wasmtime-go v1.0.0")
}
