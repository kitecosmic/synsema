# BPE performance fixture

`tokenizador.syn` and `pruebas.syn` are a snapshot of the external tokenizer
library (`librerias-prueba/tokenizador/` in its own workspace).
The fixture makes the full training comparison reproducible in this repository;
it is not a standard-library module or part of the engine binary.

From the repository root:

```sh
synsema test engine/perf/fixtures/bpe/pruebas.syn
python engine/perf/bpe_compare.py --bin engine/target/release/synsema --repeat 3
```

The benchmark checks every learned merge against a pure Python implementation
of the same algorithm, including the first-seen tie rule. `--library` can point
at the external library to check that it still matches this snapshot. The corpus
is the first 100,000 characters of `CHANGELOG.md` by default; it is a repeatable
test corpus, not the unavailable corpus from the earlier BPE report.
