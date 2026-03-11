# VRF in tee-node

This document describes how verifiable randomness is implemented and used in `tee-node`.
The VRF scheme is described in "Making NSEC5 Practical for DNSSEC", Cryptology
ePrint Archive, Report 2017/099, https://eprint.iacr.org/2017/099.pdf, see
Section 2.3.

## Overview

`tee-node` supports VRF as a wallet signing algorithm:

- Algorithm id: `sha256-secp256k1-vrf` (`wallets.VRFAlgo`)
- Curve: `secp256k1`
- Core implementation: [pkg/wallets/vrf/vrf.go](pkg/wallets/vrf/vrf.go)

The node exposes VRF proof generation through a wallet instruction command:

- OP pair: `op.Wallet / op.VRF`
- Router registration: [internal/router/routers.go](internal/router/routers.go)
- Processor: [internal/processors/instructions/vrfutils/processor.go](internal/processors/instructions/vrfutils/processor.go)

## Runtime Flow

1. A client submits an instruction with:
    - `walletId` (`bytes32`)
    - `keyId` (`uint64`)
    - `nonce` (`bytes`)
2. `types.ParseVRFInstruction` decodes and validates the payload.
3. The processor loads the wallet (`walletId`, `keyId`) from storage.
4. It checks `wallet.SigningAlgo == "sha256-secp256k1-vrf"`.
5. The wallet private key is converted to an ECDSA key, and a `vrf.Key` is built:
    - `Pk = (X, Y)`
    - `Sk = D`
6. `VerifiableRandomness(vrfKey, nonce)` builds a proof including pre-computed witness points.
7. The node returns JSON containing wallet metadata, nonce, and the VRF proof.

## Request Encoding

Request ABI encoding uses `vrfstruct.ITeeVrfVrfInstructionMessage` from `go-flare-common`:

- `bytes32 walletId`
- `uint64 keyId`
- `bytes nonce`

Parser validation:

- instruction data is present
- original message is not empty
- ABI decode succeeds
- nonce is non-empty

## Response Shape

`ProveRandomnessResponse` ([pkg/types/vrf.go](pkg/types/vrf.go)), serialized as JSON:

- `walletId`
- `keyId`
- `nonce`
- `proof`

`proof` contains:

- `gamma` (curve point: `{x, y}`)
- `c` (challenge scalar)
- `s` (response scalar)
- `u` (witness point: `c·pk + s·G`)
- `cGamma` (witness point: `c·gamma`)
- `v` (witness point: `c·gamma + s·h`)
- `zInv` (field element: `modInv(cGamma.X − V.X, P)`)

The witness points (`u`, `cGamma`, `v`, `zInv`) are pre-computed off-chain by
`VerifiableRandomness` and are required by the on-chain `TeeVRFVerifier` contract to
avoid expensive secp256k1 scalar multiplications or `BigModExp` inside the EVM.

## Cryptographic Logic

Implemented in [pkg/wallets/vrf/vrf.go](pkg/wallets/vrf/vrf.go).

### Proof generation (`VerifiableRandomness`)

Given private key `x`, public key `Y = x·G`, and nonce `m`:

1. `H = HashToCurve(m)`
2. `Gamma = x·H`
3. Sample random `k`
4. Compute `u = k·G` and `v = k·H`
5. Compute challenge:
    - `c = HashToZn(abi.encode(G, H, Y, Gamma, u, v))`
6. Compute response:
    - `s = (k - c·x) mod N`
7. Pre-compute witness points:
    - `cGamma = c·Gamma`
    - `zInv = modInv(cGamma.X − v.X, P)`
    - If the denominator is zero, re-sample `k` and retry (negligible probability).

Output proof is `(Gamma, c, s, u, cGamma, v, zInv)`.

### Proof verification (`VerifyRandomness`)

Off-chain verification performs four independent checks:

1. **ZInv**: `zInv · (cGamma.X − v.X) ≡ 1 (mod P)`
2. **U**: `c·pk + s·G == u`          *(prover knows sk such that pk = sk·G)*
3. **CGamma**: `c·Gamma == cGamma`   *(cGamma correctly derived from Gamma and c)*
4. **V**: `cGamma + s·H == v`        *(v correctly derived from Gamma, H, c, s)*
5. **Challenge**: `HashToZn(abi.encode(G, H, pk, Gamma, u, v)) == c`

Checks 1–4 verify the witness points independently; check 5 binds `c` to all
committed values. Together they prove `Gamma == sk·H`.

### On-chain verification

The `TeeVRFVerifier` Solidity contract (from `go-flare-common`) implements the same
verification logic using `ecrecover` to avoid expensive elliptic curve operations in
the EVM. The contract test in [pkg/wallets/vrf/vrf_contract_test.go](pkg/wallets/vrf/vrf_contract_test.go)
deploys the contract against a simulated backend and confirms that valid proofs pass
and tampered proofs revert.

## Randomness Extraction

`Proof.RandomnessFromProof()` derives final randomness as:

- `keccak256(gamma.X || gamma.Y)`

where `gamma.X` and `gamma.Y` are 32-byte big-endian values.

## Where It Is Tested

- Core VRF tests: [pkg/wallets/vrf/vrf_test.go](pkg/wallets/vrf/vrf_test.go)
- Contract compatibility tests: [pkg/wallets/vrf/vrf_contract_test.go](pkg/wallets/vrf/vrf_contract_test.go)
- Instruction processor tests: [internal/processors/instructions/vrfutils/vrfutils_test.go](internal/processors/instructions/vrfutils/vrfutils_test.go)
- End-to-end processor tests: [internal/processors/processor_test.go](internal/processors/processor_test.go)
