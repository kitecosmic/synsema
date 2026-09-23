# ERC-8004 desde Synsema

[ERC-8004 (Trustless Agents)](https://eips.ethereum.org/EIPS/eip-8004) es un registro on-chain de
agentes: un **Identity Registry** (ERC-721; cada agente es un token que apunta a un `agentURI`),
un **Reputation Registry** (feedback firmado por clientes) y un **Validation Registry** (pedidos de
validación a terceros). Todo lo que el registro apunta vive **off-chain**: un registration file,
una Agent Card, evidencia.

Synsema no mete ERC-8004 en el motor: es un **módulo cliente** (`erc8004.syn`) sobre primitivas
que ya existen y son puras — `abi_encode`, `keccak256`, `canonical_json`, `did_key_encode`.
Lo que sí pone el motor es la verdad que el registro apunta:

| ERC-8004 espera | Synsema publica |
|---|---|
| `services: [{name: "A2A", endpoint: …}]` | `/.well-known/agent-card.json`, **derivada** de la tabla de rutas y firmada (JWS) con el `did:key` del server (`SYNSEMA_IDENTITY_KEY`, o la clave atestada bajo `serve --attested`). |
| `services: [{name: "DID", endpoint: "did:…"}]` | el `did:key` del server (`extensions[0].params.did` de la tarjeta). |
| `feedbackURI` + `feedbackHash`, `requestURI` + `requestHash` | un **recibo** (`receipt({"sign": …})`): Verifiable Credential derivada del audit, firmada como W3C Data Integrity; `document_hash(doc)` = keccak256 del JSON canónico. |
| `supportedTrust: ["tee-attestation"]` | `/.well-known/attestation` bajo `serve --attested`. |

## Uso

```
use "./erc8004.syn" as erc

let file be erc.registration_file(agent, erc.synsema_services("https://mi.server", did), registrations, ["reputation"])
let calldata be erc.register_calldata(erc.agent_uri_data(file))
```

`synsema run examples/erc8004/demo.syn` imprime el registration file canónico y los selectores y
tamaños del calldata de `register`, `giveFeedback` y `validationRequest`.

Mandar el calldata a la cadena es tu clave y tu red (`tx_eip1559` + `eth_send` bajo
`require sign("HOT_KEY")` y `require net(...)`): el módulo no pide ningún `require`.

## Antes de usarlo contra un despliegue real

Las firmas de función son las de los contratos de referencia de ERC-8004 v1.0. Compará los
selectores (`abi_selector("register(string)")`, etc.) con la ABI del contrato desplegado en tu red
antes de mandar una transacción: si difieren, cambiá la firma en el módulo, no el motor.
