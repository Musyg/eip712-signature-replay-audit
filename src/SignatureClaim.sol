// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {MockERC20} from "./MockERC20.sol";

/// @title SignatureClaim (vulnerable)
/// @notice A gasless claim vault. An off-chain authorizer signs an EIP-712 Claim message
///         and any relayer submits it on-chain to release tokens to the named recipient.
/// @dev INTENTIONALLY VULNERABLE. Replay protection keys on the signature bytes
///      (r, s, v). ECDSA signatures are malleable, so a second valid encoding of the
///      same message passes the check and the claim executes twice. Do not deploy.
contract SignatureClaim {
    bytes32 public constant CLAIM_TYPEHASH = keccak256("Claim(address to,uint256 amount)");
    bytes32 public immutable DOMAIN_SEPARATOR;
    address public immutable authorizer;
    MockERC20 public immutable token;

    mapping(bytes32 => bool) public usedSig;

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
        bytes32 sigKey = keccak256(abi.encodePacked(r, s, v));
        require(!usedSig[sigKey], "signature already used");

        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, to, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer == authorizer && signer != address(0), "bad signature");

        usedSig[sigKey] = true;
        require(token.transfer(to, amount), "transfer failed");
    }
}
