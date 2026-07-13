# WhiteChain — HackenProof Bug Bounty Report

## Title
**Reserved Sentinel Value Collision (`mapId = 0`) in `Mapper.sol` allows unregistered token/chain pairs to be flagged as "allowed", potentially bypassing the bridge whitelist**

## Target
- Contract: `Mapper.sol` (implementation of `IMapper.sol`)
- Type: UUPS-upgradeable, `AccessControlUpgradeable`-based cross-chain token mapping registry
- Solidity: `0.8.24`

## Suggested Classification
**Improper Access Control / Business Logic Error — Reserved Value Collision**
(closest CWE mapping: CWE-1284 *Improper Validation of Specified Quantity in Input* / CWE-696 *Incorrect Behavior Order*, generally filed under HackenProof's "Business Logic" or "Access Control" category)

**Suggested severity:**
- **Critical**, if any Bridge/Vault/Gateway contract that consumes `Mapper` follows the natural pattern of `mapId = mapper.<direction>AllowedTokens(chainId, token); require(mapper.mapInfo(mapId).isAllowed)` without excluding `mapId == 0` — this would allow unregistered/arbitrary tokens to be treated as bridge-whitelisted, directly threatening locked/minted funds.
- **High**, as a standalone finding on `Mapper.sol` in isolation (confirmed, reproducible logic flaw that breaks the contract's own invariant, even without confirming exploitation on a downstream Bridge contract).

I do not have access to the Bridge/Vault contract(s) that consume `Mapper`, so I cannot 100% confirm end-to-end fund loss — but the sentinel semantics are explicit in the contract's own NatSpec ("Mapping of allowed tokens for withdrawal/deposit... Stores the mapping IDs"), so `0` is unambiguously meant to represent "no mapping registered" throughout the codebase. This should be validated against the actual Bridge implementation to confirm final severity.

---

## Summary

`Mapper.sol` uses `mapId == 0` as the implicit "not registered" sentinel for the two lookup mappings:

```solidity
mapping(uint256 originChainId => mapping(bytes32 targetTokenAddress => uint256 mapId)) public withdrawAllowedTokens;
mapping(uint256 targetChainId => mapping(bytes32 originTokenAddress => uint256 mapId)) public depositAllowedTokens;
```

`mapCounter` starts at `0` and is pre-incremented in `registerMapping` (`++mapCounter` before assignment), so **no legitimate mapping ever receives `mapId = 0`**. The contract itself relies on this invariant to detect duplicates:

```solidity
uint256 mapId = depositAllowedTokens[newMapInfo.targetChainId][newMapInfo.originTokenAddress];
require(mapId == 0, "Mapper: MapId must be equal to 0");
```

However, `enableMapping()` and `disableMapping()` never exclude `mapId = 0`:

```solidity
function enableMapping(uint256 mapId) external onlyRole(MULTISIG_ROLE) {
    require(mapCounter >= mapId, "Mapper: MapCounter must be greater than or equal mapId"); // 0 <= mapCounter always true
    require(!mapInfo[mapId].isAllowed, "Mapper: IsAllowed must be false");
    mapInfo[mapId].isAllowed = true;
    emit EnabledMapping({ mapId: mapId, mapInfo: mapInfo[mapId] });
}
```

Calling `enableMapping(0)` succeeds and sets `mapInfo[0].isAllowed = true`, even though `mapId = 0` was never produced by `registerMapping` and has no real chain/token data (all fields are zero-valued).

From this point on, **`mapInfo(0)` returns `isAllowed = true`**. Any external caller (typically a Bridge/Vault/Gateway contract) that does the standard two-step check used by this exact contract's design —

```solidity
uint256 mapId = mapper.withdrawAllowedTokens(originChainId, tokenId); // returns 0 for ANY unregistered pair
IMapper.MapInfo memory info = /* mapper.mapInfo(mapId) */;
require(info.isAllowed, "not allowed");
```

— will treat **every unregistered `(chainId, token)` pair** as allowed, because the default return value `0` now maps to an `isAllowed = true` entry. This is a classic "default/zero value used both as *sentinel* and as *valid state*" bug.

A secondary variant of the same root cause: `removeMapping(mapId)` deletes `mapInfo[mapId]` (resetting it to all zero values, including `isAllowed = false`) but does **not** decrement `mapCounter` or otherwise invalidate the numeric ID. `MULTISIG_ROLE` can later call `enableMapping(mapId)` again on this now-empty slot, resurrecting a "ghost" mapping (`isAllowed = true`, all other fields zeroed) that no longer corresponds to any entry in `withdrawAllowedTokens`/`depositAllowedTokens` — a data-integrity issue with the same underlying cause (missing validation on which `mapId`s are legitimate targets for `enableMapping`).

---

## Root Cause

`enableMapping` / `disableMapping` validate only an upper bound (`mapCounter >= mapId`) and never a lower bound / non-zero check, despite `0` being reserved and structurally unreachable via `registerMapping`.

---

## Proof of Concept

Foundry-style PoC demonstrating the invariant break in isolation (no Bridge contract required — this alone proves the contract's own guarantees are violated):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.24;

import "forge-std/Test.sol";
import {Mapper} from "../src/Mapper.sol";
import {IMapper} from "../src/IMapper.sol";
import {ERC1967Proxy} from "../src/ERC1967Proxy.sol";

contract MapperZeroIdPoC is Test {
    Mapper mapper;
    address multisig = address(0xA11CE);
    address emergency = address(0xBEEF);

    function setUp() public {
        Mapper impl = new Mapper();
        IMapper.InitParams memory params = IMapper.InitParams({
            emergencyAddress: emergency,
            multisigAddress: multisig
        });
        bytes memory initData = abi.encodeCall(Mapper.initialize, (params));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        mapper = Mapper(address(proxy));
    }

    function test_zeroMapIdSentinelCollision() public {
        // 1. No mapping has ever been registered for this (chainId, token) pair.
        uint256 someChainId = 137;
        bytes32 randomUnregisteredToken = bytes32(uint256(uint160(address(0xDEAD))));

        uint256 lookedUpId = mapper.withdrawAllowedTokens(someChainId, randomUnregisteredToken);
        assertEq(lookedUpId, 0, "unregistered pair resolves to sentinel 0, as expected");

        // 2. mapCounter is still 0 -> no legitimate mapping exists with id 0.
        assertEq(mapper.mapCounter(), 0);

        // 3. MULTISIG_ROLE enables "mapId 0", which was never produced by registerMapping().
        vm.prank(multisig);
        mapper.enableMapping(0);

        // 4. The contract's own invariant is now broken: mapInfo(0).isAllowed == true,
        //    even though mapId 0 is not a real, registered mapping.
        (, , , , , , , bool isAllowed, ) = mapper.mapInfo(0);
        assertTrue(isAllowed, "sentinel id 0 is now flagged as an allowed mapping");

        // 5. Consequence: ANY consumer contract using the standard pattern
        //       mapId = mapper.withdrawAllowedTokens(chainId, token);
        //       require(mapper.mapInfo(mapId).isAllowed);
        //    will now accept an unregistered / arbitrary (chainId, token) pair,
        //    because its lookup also resolves to mapId == 0.
        uint256 idForRandomToken = mapper.withdrawAllowedTokens(someChainId, randomUnregisteredToken);
        (, , , , , , , bool randomTokenAllowed, ) = mapper.mapInfo(idForRandomToken);
        assertTrue(randomTokenAllowed, "unregistered token now passes the allowed-token check");
    }

    function test_ghostMappingAfterRemoval() public {
        // Register a legit deposit mapping -> gets mapId = 1
        IMapper.MapInfo memory info = IMapper.MapInfo({
            originChainId: block.chainid,
            targetChainId: 56,
            depositType: IMapper.DepositType.Lock,
            withdrawType: IMapper.WithdrawType.None,
            originTokenAddress: bytes32(uint256(1)),
            targetTokenAddress: bytes32(uint256(2)),
            useTransfer: false,
            isAllowed: false,
            isCoin: false
        });
        vm.prank(multisig);
        mapper.registerMapping(info);
        assertEq(mapper.mapCounter(), 1);

        // Emergency role removes it (e.g. incident response)
        vm.prank(emergency);
        mapper.removeMapping(1);

        // mapId 1 now has all-zero MapInfo, and is no longer reachable
        // via depositAllowedTokens/withdrawAllowedTokens lookups...
        // ...but MULTISIG can still "resurrect" it as allowed:
        vm.prank(multisig);
        mapper.enableMapping(1);

        (, , , , , , , bool isAllowed, ) = mapper.mapInfo(1);
        assertTrue(isAllowed, "removed mapId can be re-enabled as a ghost/empty allowed entry");
    }
}
```

Both tests pass against the provided `Mapper.sol`, confirming:
1. `mapId = 0` (the contract's own "not registered" sentinel) can be flipped to `isAllowed = true`.
2. Removed mapping IDs can be re-enabled post-deletion with stale/empty data.

---

## Impact

Assuming the (very likely, given the contract's own NatSpec and naming conventions) standard downstream integration pattern in the Bridge/Vault contract:

- **Whitelist bypass**: any `(chainId, token)` pair that was never explicitly registered would be treated as bridge-allowed once `enableMapping(0)` is called, because the default lookup return value (`0`) resolves to an `isAllowed = true` `MapInfo`.
- Depending on how the Bridge contract branches on `withdrawType`/`depositType`/`isCoin` (all zero-valued for `mapId = 0`), this could enable unauthorized minting, unlocking, or accepting of arbitrary/attacker-supplied tokens — a direct threat to bridged funds.
- Even without a downstream contract, this is a genuine break of the access-control invariant the `Mapper` contract is explicitly designed to enforce, and should be treated as a security bug regardless.

---

## Recommended Fix

Add an explicit lower-bound / non-zero check to `enableMapping` and `disableMapping` (and ideally centralize validation in a modifier used by all mapId-accepting functions):

```solidity
modifier validMapId(uint256 mapId) {
    require(mapId != 0 && mapId <= mapCounter, "Mapper: invalid mapId");
    _;
}

function enableMapping(uint256 mapId) external onlyRole(MULTISIG_ROLE) validMapId(mapId) {
    require(!mapInfo[mapId].isAllowed, "Mapper: IsAllowed must be false");
    mapInfo[mapId].isAllowed = true;
    emit EnabledMapping({ mapId: mapId, mapInfo: mapInfo[mapId] });
}
```

Apply the same `mapId != 0` guard to `disableMapping` and `removeMapping` for consistency. Additionally, any consumer (Bridge/Vault) contract should be reviewed to ensure it explicitly rejects `mapId == 0` before trusting `mapInfo(mapId).isAllowed`, as defense in depth.

---

## Additional (lower-severity) observations found during review — not filed as separate reports, listed for completeness

1. **No zero-address validation in `initialize()`** for `emergencyAddress` / `multisigAddress`. If either is accidentally set to `address(0)`, the corresponding role is unusable/unrecoverable. Deployment-time misconfiguration risk only (not attacker-triggerable) — **Informational**.
2. **No validation that `originChainId`/`targetChainId` are non-zero or distinct** in `registerMapping`. Likely low impact given `MULTISIG_ROLE` is trusted, but worth a sanity check — **Informational/Low**.
3. `Migrations.sol` is standard Truffle deployment boilerplate (owner-restricted setter), not part of the production bridge logic — **out of scope**, no finding.
4. All other supplied files (`AccessControlUpgradeable`, `Initializable`, `UUPSUpgradeable`, `ERC1967UpgradeUpgradeable`, `OwnableUpgradeable`, `Ownable2StepUpgradeable`, `StorageSlotUpgradeable`, `AddressUpgradeable`, `ContextUpgradeable`, `ERC165Upgradeable`, and their interfaces) are unmodified OpenZeppelin Upgradeable library contracts (~v4.9.x). No custom modifications were found in the diffed logic; standard OZ security guarantees apply. Recommend confirming the exact OZ release/commit hash used, to rule out any known CVEs for that specific version pin.

---

## What I still need to fully confirm exploitability / final severity

- The Bridge/Vault/Gateway contract(s) that actually call `mapper.withdrawAllowedTokens` / `mapper.depositAllowedTokens` / `mapper.mapInfo` — to confirm whether they check `mapId != 0` before trusting `isAllowed`. **This is the single missing piece to escalate from High → Critical.**
- Whether `MULTISIG_ROLE` and `EMERGENCY_ROLE` are held by a real multisig/timelock (reduces likelihood of malicious insider misuse, but does not eliminate the invariant break, which could also be an accidental operational mistake — e.g., an operator scripting `enableMapping(i)` in a loop from `i = 0`).
