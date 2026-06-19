# EIP-712 Signature Replay (Malleability), Demonstration Security Review

![tests](https://github.com/Musyg/eip712-signature-replay-audit/actions/workflows/ci.yml/badge.svg)

A self-contained demonstration of a smart-contract security review: a deliberately
vulnerable gasless-claim contract whose replay guard keys on the signature bytes, the
ECDSA-malleability double-spend it allows (proven with a passing
[Foundry](https://book.getfoundry.sh) proof-of-concept), and a `fixed` branch where the
same scenario is neutralised.

> This is a demonstration on intentionally vulnerable code. `SignatureClaim` was written
> to showcase audit methodology end to end. It is not production code, not a real client
> engagement, and must never be deployed. The finding is a real vulnerability in this demo
> contract, not an invented severity.

## Why this repo exists

Anyone can write "I audit smart contracts" in a bio. This repo shows the work instead: a
target, a concrete finding, an executable proof, and a verified fix. If it isn't
reproducible, it isn't done.

## Repository layout

The review lives across two branches:

| Branch | Contents | What a green `forge test` means |
|--------|----------|---------------------------------|
| `master` | The vulnerable contract and the PoC that exploits it | the same signature pays out twice |
| `fixed`  | The remediated contract and the same scenario | both the malleable twin and the exact replay are rejected |

- `src/SignatureClaim.sol`, the contract under review
- `test/SignatureClaim.poc.t.sol`, the proof-of-concept
- `EIP712_Signature_Replay_Review.pdf`, the full written report

## Finding

| ID | Severity | Summary |
|----|----------|---------|
| H-01 | High | Signature-malleability replay. The replay guard stores `keccak256(r, s, v)`, but every ECDSA signature has a second valid encoding `(r, N - s, v ^ 1)` for the same message and signer. A relayer submits the malleable twin and the claim executes a second time, paying the recipient twice for one signed authorisation. |

PoC numbers on `master`: the authorizer signs one claim of 1,000 ether for `bob`. The
relayer submits the signature, then submits its malleable twin. `bob` receives 2,000
ether; the extra 1,000 is drained from the vault against a single authorisation. On
`fixed` the twin is rejected and `bob` receives exactly 1,000.

## Reproduce it

Requires [Foundry](https://book.getfoundry.sh/getting-started/installation).

```bash
git clone https://github.com/Musyg/eip712-signature-replay-audit.git
cd eip712-signature-replay-audit
forge install

# master: the double-spend succeeds
forge test -vv

# fixed: the same attack is neutralised
git checkout fixed
forge test -vv
```

## The fix

Two changes, both standard. First, the replay guard keys on the message digest rather than
the signature bytes, so any second encoding of the same authorisation collides with the
already-used digest. Second, the contract enforces EIP-2 by rejecting the upper half of the
`s` range and non-canonical `v`, so the malleable twin is refused before recovery. This
matches OpenZeppelin's `ECDSA` library behaviour.

## How severity is rated

High: direct theft of vault funds. Any party that can observe a relayable signature (every
relayer can) doubles the payout of any claim. No special role and no victim interaction
beyond signing one legitimate authorisation.
