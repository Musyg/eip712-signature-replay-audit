// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {MockERC20} from "./MockERC20.sol";

/// @title SignatureClaim (remediated)
/// @notice A gasless claim vault. An off-chain authorizer signs an EIP-712 Claim message
///         and any relayer submits it on-chain to release tokens to the named recipient.
/// @dev Replay protection keys on the message digest, not on the signature bytes, and the
///      contract rejects the upper half of the s range (EIP-2). A malleable twin of a
///      signature now either fails the low-s check or hits the already-used digest.
contract SignatureClaim {
    // secp256k1 N / 2. Signatures with s above this are the non-canonical (malleable) half.
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    bytes32 public constant CLAIM_TYPEHASH = keccak256("Claim(address to,uint256 amount)");
    bytes32 public immutable DOMAIN_SEPARATOR;
    address public immutable authorizer;
    MockERC20 public immutable token;

    mapping(bytes32 => bool) public usedDigest;

    constructor(address _authorizer, MockERC20 _token) {
        authorizer = _authorizer;
        token = _token;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("SignatureClaim")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function claim(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        require(uint256(s) <= HALF_N, "malleable signature");
        require(v == 27 || v == 28, "bad v");

        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, to, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        require(!usedDigest[digest], "claim already executed");

        address signer = ecrecover(digest, v, r, s);
        require(signer == authorizer && signer != address(0), "bad signature");

        usedDigest[digest] = true;
        require(token.transfer(to, amount), "transfer failed");
    }
}
