// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {Test, console2} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {SignatureClaim} from "../src/SignatureClaim.sol";

contract SignatureClaimPoC is Test {
    // secp256k1 group order.
    uint256 constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    MockERC20 token;
    SignatureClaim vault;

    uint256 authorizerPk = 0xA11CE;
    address authorizer;
    address bob = address(0xB0B);

    function setUp() public {
        authorizer = vm.addr(authorizerPk);
        token = new MockERC20();
        vault = new SignatureClaim(authorizer, token);
        token.mint(address(vault), 100_000 ether);
    }

    function _digest(address to, uint256 amount) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(vault.CLAIM_TYPEHASH(), to, amount));
        return keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), structHash));
    }

    /// Same scenario as the master branch. Both the malleable twin and an exact replay
    /// are now rejected, so the authorizer's single signed claim pays out exactly once.
    function test_malleability_isBlocked() public {
        uint256 amount = 1_000 ether;
        bytes32 digest = _digest(bob, amount);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizerPk, digest);

        vault.claim(bob, amount, v, r, s);
        assertEq(token.balanceOf(bob), amount, "first claim paid");

        // Malleable twin: high-s form is rejected by the EIP-2 check.
        bytes32 s2 = bytes32(N - uint256(s));
        uint8 v2 = v == 27 ? 28 : 27;
        assertEq(ecrecover(digest, v2, r, s2), authorizer, "twin still recovers signer");
        vm.expectRevert(bytes("malleable signature"));
        vault.claim(bob, amount, v2, r, s2);

        // Exact replay of the original is rejected by digest tracking.
        vm.expectRevert(bytes("claim already executed"));
        vault.claim(bob, amount, v, r, s);

        assertEq(token.balanceOf(bob), amount, "no double spend");
        console2.log("authorizer signed (wei):", amount);
        console2.log("bob received      (wei):", token.balanceOf(bob));
    }
}
