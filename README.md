![GitHub License](https://img.shields.io/github/license/dashpay/base-sdk)
![Minimum Supported Rust Version](https://img.shields.io/badge/v1.85.0-msrv?style=flat&logo=rust&label=MSRV&color=orange)

> [!WARNING]
>
> This SDK is in early stages of development and different crates may have different levels of conformance and
> testing rigour. The completeness of one crate does not imply the completeness of others.
>
> As with any alternate implementation, unintended deviations from the reference implementation (i.e.
> [Dash Core](https://github.com/dashpay/dash)) are possible and must be accounted for as a risk when building on
> this SDK. If requirements demand strict conformance guarantees, it is recommended to interface with Dash Core
> through [RPC](https://docs.dash.org/en/stable/docs/core/api/remote-procedure-calls.html),
> [REST](https://docs.dash.org/en/stable/docs/core/api/http-rest.html) or
> [ZMQ](https://docs.dash.org/en/stable/docs/core/api/zmq.html) instead.

`base-sdk` is a parsing and stateless verification SDK for Dash's layer 1 blockchain.

## Crates

| Crate | Description | CI (`develop`) | Coverage |
|-------|-------------|--------------|----------|
| [dash-num](./pkgs/num) | Hash blobs, 256-bit arithmetic, compact target encoding | [![dash-num](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_num.yml?style=flat&logo=github&logoColor=white&label=num)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_num.yml) | [![dash-num](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-num&style=flat&logo=codecov&logoColor=white&label=num)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fnum) |
| [dash-p2p-core](./pkgs/p2p_core) | P2P message types and wire format | [![dash-p2p-core](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_p2p_core.yml?style=flat&logo=github&logoColor=white&label=p2p-core)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_p2p_core.yml) | [![dash-p2p-core](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-p2p-core&style=flat&logo=codecov&logoColor=white&label=p2p-core)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fp2p_core) |
| [dash-params](./pkgs/params) | Chain parameters for `mainnet`, `testnet3`, and `regtest` | [![dash-params](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_params.yml?style=flat&logo=github&logoColor=white&label=params)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_params.yml) | [![dash-params](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-params&style=flat&logo=codecov&logoColor=white&label=params)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fparams) |
| [dash-pkc](./pkgs/pkc) | BLS (legacy + IETF) and secp256k1 operations | [![dash-pkc](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_pkc.yml?style=flat&logo=github&logoColor=white&label=pkc)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_pkc.yml) | [![dash-pkc](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-pkc&style=flat&logo=codecov&logoColor=white&label=pkc)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fpkc) |
| [dash-pow](./pkgs/pow) | Proof of work scheme | [![dash-pow](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_pow.yml?style=flat&logo=github&logoColor=white&label=pow)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_pow.yml) | [![dash-pow](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-pow&style=flat&logo=codecov&logoColor=white&label=pow)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fpow) |
| [dash-primitives](./pkgs/primitives) | Blocks, transactions, payloads, governance objects | [![dash-primitives](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_primitives.yml?style=flat&logo=github&logoColor=white&label=primitives)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_primitives.yml) | [![dash-primitives](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-primitives&style=flat&logo=codecov&logoColor=white&label=primitives)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fprimitives) |
| [dash-script](./pkgs/script) | Script opcodes, classification, and address derivation | [![dash-script](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_script.yml?style=flat&logo=github&logoColor=white&label=script)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_script.yml) | [![dash-script](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-script&style=flat&logo=codecov&logoColor=white&label=script)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fscript) |
| [dash-types](./pkgs/types) | Shared byte and integer newtypes, serde helpers | [![dash-types](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_types.yml?style=flat&logo=github&logoColor=white&label=types)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_types.yml) | [![dash-types](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-types&style=flat&logo=codecov&logoColor=white&label=types)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Ftypes) |

## Dependencies

> [!NOTE]
> Solid lines are build dependencies. Dotted lines are test dependencies.

```mermaid
graph LR
  subgraph " "
    types[dash-types]
    num[dash-num]
  end
  subgraph "  "
    script[dash-script]
    pow[dash-pow]
    pkc[dash-pkc]
  end
  subgraph "   "
    primitives[dash-primitives]
    params[dash-params]
    p2p_core[dash-p2p-core]
  end

  types --> num
  types --> script
  types --> pkc
  types --> primitives
  types --> p2p_core
  num --> pow
  num --> pkc
  num --> primitives
  num --> params
  num --> p2p_core
  script --> primitives
  script --> p2p_core
  pkc --> p2p_core
  pow --> primitives
  pow -.-> params
  primitives --> params
  primitives --> p2p_core
  params --> p2p_core
```

## Features

All crates support these standard features:

| Feature | Description | Crates |
|---------|-------------|--------|
| _(baseline)_ | `no_std` + `alloc`, always available | _All_ |
| `std` | Enable standard library support | _All_ |
| `serde` | Enable serde serialization (where applicable) | [num](./pkgs/num), [p2p-core](./pkgs/p2p_core), [pkc](./pkgs/pkc), [primitives](./pkgs/primitives), [script](./pkgs/script), [types](./pkgs/types) |
| `full` | Enables all non-conflicting features | _All_ |
| `_internal` | Access to package internals, reserved for testing and benchmarks. **Not part of API contract.** | _All_ |

Specific crates define additional features:

| Feature | Description | Crates |
|---------|-------------|--------|
| `k256` | Enable secp256k1 support | [pkc](./pkgs/pkc) |
| `bls` | Enable standard and legacy BLS support | [pkc](./pkgs/pkc) |
| `aes_hw` | Enable hardware-accelerated AES on supported platforms | [pow](./pkgs/pow) |
| `simd` | Use SIMD backends (requires nightly) | [pow](./pkgs/pow) |

## License

Copyright &copy; 2026-present, The Dash Core developers. See the accompanying file [LICENSE](./LICENSE) or
<!-- pyml disable-next-line no-bare-urls -->
https://opensource.org/license/MIT
