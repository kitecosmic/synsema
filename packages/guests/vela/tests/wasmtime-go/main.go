// Sonda del guest de Vela bajo wasmtime-go v1.0.0 — la MISMA versión del runtime que el Executor
// de Vela 0.2.0 (`vela/go.mod`), instanciado como él: `DefineWasi()` y nada más, sin `_start`, y
// los exports llamados con punteros a memoria lineal. Si el módulo compila, instancia y responde
// acá, compila, instancia y responde en el Executor; la sonda de Node (`tests/vela_guest.probe.mjs`)
// cubre el contrato en detalle, ésta cubre el runtime exacto.
//
//   cd packages/guests/vela/tests/wasmtime-go
//   go run . ../../../../../engine/target/wasm32-wasip1/wasm/synsema_vela_guest.wasm
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
	"strings"

	"github.com/bytecodealliance/wasmtime-go"
)

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
	module, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		fail("compile under wasmtime 1.0", err)
	}
	fmt.Printf("ok   compiled under wasmtime-go v1.0.0 (%d bytes)\n", len(wasmBytes))
	store := wasmtime.NewStore(engine)
	wasi := wasmtime.NewWasiConfig()
	wasi.InheritStdout() // el Executor lo manda a su log server con prefijos INF/WRN/ERR
	wasi.InheritStderr()
	store.SetWasi(wasi)
	linker := wasmtime.NewLinker(engine)
	if err := linker.DefineWasi(); err != nil {
		fail("DefineWasi", err)
	}
	inst, err := linker.Instantiate(store, module)
	if err != nil {
		fail("instantiate (only WASI imports are provided)", err)
	}
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
	fmt.Println("ok   instantiated; all exports the Executor looks up are present")

	// load_module (cache warm-up)
	p, err := g.call("load_module", int64(1))
	if err != nil {
		fail("load_module (trap)", err)
	}
	out, _ := g.result(p)
	parse(out, "load_module")
	fmt.Printf("ok   load_module → %s\n", out)

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
	fmt.Println("ALL OK under wasmtime-go v1.0.0")
}
