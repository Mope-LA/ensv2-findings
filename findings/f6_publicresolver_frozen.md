# Submission — ENSv2: PublicResolverV2 records are frozen for V2-only names

- **Target:** ensdomains/contracts-v2 @ `48b3e2d` (main)
- **Severity:** Low
- **Asset:** `src/resolver/PublicResolverV2.sol`

## Summary

`PublicResolverV2.canModifyName` resolves the name preimage exclusively through the
ENSv1 `NameWrapper` (`NAME_WRAPPER.names(node)`). Names registered only in ENSv2
(fresh registrations through `ETHRegistrar` after the phase-6 cutover) have no V1
NameWrapper preimage, so `canModifyName` returns `false` even for the name owner.
Consequently, every write path (`setAddr`, `setText`, `setContenthash`, `setData`,
`setPubkey`, … — all gated by `isAuthorised`) reverts forever: the name pays rent but
its records are permanently unwritable. `PublicResolverV2` is deployed on sepolia
(`docs/addresses/sepolia.md`) and no documentation warns about the V1-preimage
requirement.

## Evidence

1. `src/resolver/PublicResolverV2.sol:110-123`:
   ```solidity
   function canModifyName(bytes32 node, address operator) public view returns (bool) {
       bytes memory name = NAME_WRAPPER.names(node);
       if (name.length == 0) {
           return false;
       }
       address owner = LibRegistry.findOwner(ROOT_REGISTRY, name, 0);
       return
           owner == operator ||
           isApprovedForAll(owner, operator) ||
           isApprovedFor(owner, node, operator);
   }
   ```
2. `src/resolver/PublicResolverV2.sol:132-139` — all profile setters funnel through
   `isAuthorised(node)` → `canModifyName(node, msg.sender)`.
3. V1 preimage source: `NAME_WRAPPER` is an immutable pointing at the ENSv1
   NameWrapper (`src/resolver/PublicResolverV2.sol:96-101`); `names` entries are only
   created when a name is wrapped in V1. A fresh V2 registration
   (`ETHRegistrar.register` → `PermissionedRegistry.register`) only writes the V2
   `LabelStore` — it never populates the V1 NameWrapper.
4. The team's own test helper always registers the name in V1 first
   (`test/unit/resolver/PublicResolverV2.t.sol:203-221`,
   `registerWrappedETH2LD` before the V2 registration), so the V2-only case is
   untested.

## Attack/impact flow

1. After the phase-6 cutover, a user registers `fresh.eth` through `ETHRegistrar`
   (V2-only; no V1 counterpart), selecting `PublicResolverV2` (or a dApp defaulting
   to it) as the resolver.
2. `NAME_WRAPPER.names(namehash("fresh.eth"))` returns `""`.
3. `canModifyName(node, owner)` returns `false`; `setAddr`/`setText`/… revert with
   the profile's `Unauthorized` error.
4. The owner pays rent for a name whose records can never be set — silent, permanent
   DoS of the record layer for that name. No on-chain path can ever flip
   `canModifyName` to true for this name (no V1 preimage will ever appear).

## PoC

`contracts/test/poc/EnsV2AuditPoC.t.sol::test_poc_publicResolverV2_v2OnlyName_frozenRecords`

```
forge test --match-test test_poc_publicResolverV2_v2OnlyName_frozenRecords -vvv
```

Result: PASS. Registers a fresh V2-only name with `PublicResolverV2` as resolver;
asserts `canModifyName(node, owner) == false` and `setAddr` reverting for the owner.

## Remediation

In `canModifyName`, fall back to V2 sources when the V1 NameWrapper has no preimage:
- `ROOT_REGISTRY` label lookup via the shared `LabelStore`
  (`ILabelStore.getLabel(labelId)`), and/or
- `LibRegistry.findCanonicalName(ROOT_REGISTRY, resolverContract)`-style reverse
  lookup for nodes that live in V2 registries.

Alternatively, document the limitation explicitly and route fresh V2 registrations to
`PermissionedResolver` by default.

## Defense analysis

- *"PublicResolverV2 is only the premigration fallback resolver"* — it is deployed
  and usable as a general resolver (`IPublicResolver` profiles, deployed on sepolia);
  nothing on-chain or in docs prevents selecting it for a fresh name. The failure is
  silent (reads return empty, writes revert without explanation).
- *"Fresh names should use PermissionedResolver"* — true as the intended happy path,
  but the contract itself accepts any name and the registry allows setting it as a
  resolver for any name; the safe configuration is not enforced anywhere.
- *"Low severity"* — agreed: no fund loss beyond wasted rent, no theft; the impact is
  permanent record-freezing for affected configurations.
