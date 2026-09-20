// Sonda del guest de Vela bajo wasmtime-go v47 — el runtime de Vela `dev` / v0.3.0 (`vela/go.mod`,
// rama dev), configurado como su Executor lo configura, leído de `pkg/wasm/wasmtime_runtime.go`
// (newPinnedEngine, newModuleStore, compileAndInstantiate), `pkg/wasm/epoch_deadline.go` y
// `pkg/wasm/guest_imports.go`:
//
//   - features de wasm pineadas (bulk memory, multi-value, reference types, SIMD; todo lo demás
//     apagado, GC y concurrencia incluidos: un módulo con externref no carga);
//   - la lista cerrada de OCHO imports de `wasi_snapshot_preview1`, comprobada tras compilar y
//     antes de instanciar — cualquier otro import declarado rechaza el módulo;
//   - epoch interruption: un ticker sube la época cada 100 ms y cada operación del guest — la
//     instanciación incluida — se arma con un deadline de 10 s (`EXECUTOR_GUEST_EXECUTION_TIMEOUT_MS`
//     por defecto); pasarse es un trap `Interrupt`;
//   - límites por store: 2 GiB de memoria lineal, 1 instancia, 1 memoria, 4 tablas, 10⁶ elementos;
//   - NaN canónicos y `DefineWasi()` sin nada más.
//
// Si el módulo carga, instancia y responde acá, carga en el Executor de v0.3.0 — salvo lo que sólo el
// enclave sabe (attestation, log pipes por FIFO). La sonda hermana `../wasmtime-go/` (v1.0.0) cubre
// el runtime de v0.2.0, el del devnet público; `tests/vela_guest.probe.mjs` cubre el contrato en
// detalle. Ésta cubre el runtime exacto de v0.3.0 y anota los tiempos que ese bound de 10 s acota.
//
//	cd packages/guests/vela/tests/wasmtime-go-v47
//	go run . ../../../../../engine/target/wasm32-wasip1/wasm/synsema_vela_guest.stubbed.wasm
//
// Necesita Go ≥ 1.23 y un compilador C (cgo): gcc/clang en Linux y macOS, MinGW-w64 en Windows.
// Variables opcionales: DEPLOY_PARAMS (JSON de constructorParams) y PAYLOAD (el JSON del
// process_request; por defecto el transfer de la app de ejemplo).
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v47"
)

// --- Constantes de Vela dev (pkg/common/config.go, pkg/wasm/wasmtime_runtime.go) ---
const (
	// EXECUTOR_GUEST_EXECUTION_TIMEOUT_MS por defecto: una operación del guest, instanciación incluida.
	guestExecutionTimeout = 10 * time.Second
	// GuestExecutionEpochTick: el ticker sube la época cada 100 ms; el deadline se redondea a ticks.
	epochTickInterval = 100 * time.Millisecond
	// MaxGuestMemoryCeilingBytes: los punteros del ABI son int32; ninguna dirección llega a 2 GiB.
	maxGuestMemoryBytes      = 2 * 1024 * 1024 * 1024
	maxTableElementsPerStore = 1_000_000
	maxInstancesPerStore     = 1
	maxTablesPerStore        = 4
	maxMemoriesPerStore      = 1
)

// La lista cerrada de `guest_imports.go` (v0.3.0). Cambiarla es un cambio de ABI de Vela.
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

// epochTicksFor: ceil(timeout / tick) + 1, como Vela — el +1 es corrección, no holgura: la fase del
// ticker es independiente de cuándo se arma el store.
func epochTicksFor(timeout time.Duration) uint64 {
	ticks := (timeout + epochTickInterval - 1) / epochTickInterval
	if ticks < 1 {
		ticks = 1
	}
	return uint64(ticks) + 1
}

// newPinnedEngine: la misma configuración que `newPinnedEngine` de Vela dev, flag por flag.
func newPinnedEngine() *wasmtime.Engine {
	config := wasmtime.NewConfig()
	// Habilitadas: lo que TinyGo emite, deterministas por spec.
	config.SetWasmBulkMemory(true)
	config.SetWasmMultiValue(true)
	config.SetWasmReferenceTypes(true)
	config.SetWasmSIMD(true)
	// Apagadas: resultados dependientes del host.
	config.SetWasmRelaxedSIMD(false)
	config.SetWasmRelaxedSIMDDeterministic(true)
	// Apagadas: incompatibles con el ABI (punteros int32) o con el presupuesto de RAM.
	config.SetWasmMemory64(false)
	config.SetWasmMultiMemory(false)
	config.SetWasmThreads(false)
	// Apagadas: superficie sin uso.
	config.SetWasmTailCall(false)
	config.SetWasmFunctionReferences(false)
	config.SetWasmGC(false)
	config.SetWasmWideArithmetic(false)
	config.SetWasmExceptions(false)
	config.SetWasmComponentModel(false)
	// Subsistemas enteros apagados: sin GC (un externref declarado rechaza el módulo) ni concurrencia.
	config.SetGCSupport(false)
	config.SetConcurrencySupport(false)
	// El bound de ejecución: el compilador emite los chequeos de época; un store sin armar trapea
	// de inmediato, así que TODO camino que corra código del guest arma antes (ver arm()).
	config.SetEpochInterruption(true)
	// NaN canónicos (reproducibilidad entre hosts).
	config.SetCraneliftNanCanonicalization(true)
	return wasmtime.NewEngineWithConfig(config)
}

// checkGuestImportsAllowed: el recorrido de Vela, con los imports declarados para el resumen.
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

type guest struct {
	store *wasmtime.Store
	inst  *wasmtime.Instance
	mem   *wasmtime.Memory
	ticks uint64
}

// arm: como beginGuestExecution de Vela — el deadline es ABSOLUTO (época actual + N), así que se
// arma inmediatamente antes de CADA operación, no una vez por store.
func (g *guest) arm() {
	g.store.SetEpochDeadline(g.ticks)
}

func (g *guest) call(name string, args ...interface{}) (int32, error) {
	f := g.inst.GetFunc(g.store, name)
	if f == nil {
		return 0, fmt.Errorf("export %s not found", name)
	}
	g.arm()
	r, err := f.Call(g.store, args...)
	if err != nil {
		return 0, describe(err)
	}
	if r == nil { // deallocate / get_allocated_memory_stats no devuelven nada
		return 0, nil
	}
	return r.(int32), nil
}

// describe: un trap `Interrupt` es el bound de ejecución de Vela, no un bug del módulo: se dice.
func describe(err error) error {
	var trap *wasmtime.Trap
	if errors.As(err, &trap) {
		if code := trap.Code(); code != nil && *code == wasmtime.Interrupt {
			return fmt.Errorf("guest execution bound hit (epoch interrupt after %v): %w", guestExecutionTimeout, err)
		}
	}
	return err
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

func ms(d time.Duration) string {
	return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000.0)
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
		fmt.Println("usage: go run . <synsema_vela_guest.stubbed.wasm>")
		os.Exit(2)
	}
	wasmBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail("read", err)
	}

	engine := newPinnedEngine()
	// El ticker de época, como startEpochTicker: sin él ningún deadline expira jamás — y con
	// interruption activa sin armar, todo trapea. Se para al salir.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(epochTickInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				engine.IncrementEpoch()
			}
		}
	}()

	t0 := time.Now()
	module, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		fail("compile under wasmtime-go v47 (pinned features)", err)
	}
	compileTime := time.Since(t0)
	fmt.Printf("ok   compiled under wasmtime-go v47 with Vela dev's pinned engine (%d bytes) in %s\n", len(wasmBytes), ms(compileTime))

	// Tras compilar, antes de instanciar: la lista cerrada. Todo lo sobrante de una vez.
	declared, rejected := checkGuestImportsAllowed(module)
	if len(rejected) > 0 {
		fail("imports (Vela v0.3.0 closed set)", fmt.Errorf("module declares host import(s) that are not allowed: %s — run tools/wasi-stub on it", strings.Join(rejected, ", ")))
	}
	fmt.Printf("ok   imports ⊆ Vela v0.3.0's allowed set (%d declared: %s)\n", len(declared), strings.Join(declared, ", "))

	// newModuleStore: límites pineados + deadline base.
	ticks := epochTicksFor(guestExecutionTimeout)
	store := wasmtime.NewStore(engine)
	store.Limiter(maxGuestMemoryBytes, maxTableElementsPerStore, maxInstancesPerStore, maxTablesPerStore, maxMemoriesPerStore)
	store.SetEpochDeadline(ticks)

	wasi := wasmtime.NewWasiConfig()
	wasi.InheritStdout() // el Executor lo manda a su log server por FIFOs con prefijos INF/WRN/ERR
	wasi.InheritStderr()
	store.SetWasi(wasi)
	linker := wasmtime.NewLinker(engine)
	if err := linker.DefineWasi(); err != nil {
		fail("DefineWasi", err)
	}

	// La instanciación corre código del guest (start section) y va dentro del bound: se arma antes.
	store.SetEpochDeadline(ticks)
	t1 := time.Now()
	inst, err := linker.Instantiate(store, module)
	if err != nil {
		fail("instantiate within the 10 s guest bound (WASI only)", describe(err))
	}
	instantiateTime := time.Since(t1)

	memExport := inst.GetExport(store, "memory")
	if memExport == nil || memExport.Memory() == nil {
		fail("memory export", fmt.Errorf("missing"))
	}
	g := &guest{store: store, inst: inst, mem: memExport.Memory(), ticks: ticks}
	for _, name := range []string{"allocate", "deallocate", "load_module", "deploy", "deposit", "process_request", "trusted_request"} {
		if inst.GetFunc(store, name) == nil {
			fail("export "+name, fmt.Errorf("missing"))
		}
	}
	fmt.Printf("ok   instantiated in %s (memory %d pages); all exports the Executor looks up are present\n", ms(instantiateTime), g.mem.Size(store))

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
	t3 := time.Now()
	p, err = g.call("process_request", int64(1), sp, int32(20), int32(1), plp, int32(len(payload)), stp, int32(len(state)))
	processTime := time.Since(t3)
	g.free(sp, 20)
	g.free(plp, len(payload))
	g.free(stp, len(state))
	if err != nil {
		fail("process_request (trap)", err)
	}
	out, _ = g.result(p)
	parse(out, "process_request")
	fmt.Printf("ok   process_request in %s → %d bytes of result\n", ms(processTime), len(out))

	fmt.Printf("timing: compile %s, instantiate %s, first call %s, process %s — each guest operation is bounded to %v (instantiation included), ticker %v\n",
		ms(compileTime), ms(instantiateTime), ms(firstCallTime), ms(processTime), guestExecutionTimeout, epochTickInterval)
	fmt.Println("ALL OK under wasmtime-go v47 (Vela dev / v0.3.0 runtime: pinned engine, closed imports, epoch bound)")
}
