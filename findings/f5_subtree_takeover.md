# Submission — ENSv2: Subtree takeover on parent lapse (WrapperRegistry virtual owner)

- **Target:** ensdomains/contracts-v2 @ `48b3e2d` (main)
- **Severity:** Medium
- **Assets:** `PermissionedRegistry`, `WrapperRegistry`, `LockedMigrationController` / `LockedWrapperReceiver`

## Summary

When a migrated, locked `.eth` name expires and is re-registered by a new owner, the
new owner automatically becomes the **virtual owner** of the existing `WrapperRegistry`
for that name. The virtual owner inherits the wrapper's ROOT roles (`REGISTRAR`,
`RENEW`, `UPGRADE`, `CAN_NAME`, plus their admin counterparts when the V1 fuses were
not frozen), gaining control over the entire migrated subtree — including
re-registering every expired subdomain to themselves and squatting new labels for
free. In ENSv1, expiry never transferred the locked ERC1155 token: the original owner
kept the token and a lapsed subtree froze instead of changing hands.

## Evidence

1. `src/registry/WrapperRegistry.sol:251-262` — `_getRoles` maps an account to the
   parent registry contract's root roles whenever the account is the current owner of
   the child label in the parent registry ("virtual owner"):
   ```solidity
   function _getRoles(uint256 resource, address account) internal view override returns (uint256) {
       if (resource == ROOT_RESOURCE) {
           address parent = address(_parentRegistry); // virtual owner
           if (parent != address(0) &&
               account == PermissionedRegistry(parent).findOwner(_childLabel)) {
               return super._getRoles(resource, parent); // replace, instead of OR
           }
       }
       return super._getRoles(resource, account);
   }
   ```
2. `src/registry/WrapperRegistry.sol:130-133` — root roles are granted to the parent
   registry contract at `initialize`:
   ```solidity
   address virtualOwner = address(_parentRegistry);
   _grantRoles(ROOT_RESOURCE, roleBitmap, virtualOwner, false);
   ```
3. `src/migration/LockedWrapperReceiver.sol:210-225` — the wrapper root roles are
   derived from fuses at migration time:
   ```solidity
   function _subregistryRoleBitmapFromFuses(uint32 fuses) internal pure returns (uint256 roleBitmap) {
       if ((fuses & CANNOT_CREATE_SUBDOMAIN) == 0) roleBitmap |= RegistryRolesLib.ROLE_REGISTRAR;
       roleBitmap |= RegistryRolesLib.ROLE_RENEW | RegistryRolesLib.ROLE_UPGRADE | RegistryRolesLib.ROLE_CAN_NAME;
       if (LibMigration.notFrozen(fuses)) roleBitmap |= roleBitmap << 128; // give admin
   }
   ```
   `CANNOT_CREATE_SUBDOMAIN` is unburned by default, so `REGISTRAR` is present for
   the overwhelming majority of wrapped names.
4. `src/registry/PermissionedRegistry.sol:411-477` (`_register`) — re-registering an
   expired name burns the old token and mints a fresh one to the new owner; nothing
   detaches or rotates the existing `subregistry` (the `WrapperRegistry`), and the
   registrar (`ETHRegistrar.register`) lets the registrant pass an arbitrary
   `subregistry` — including the pre-existing wrapper.
5. `src/registry/PermissionedRegistry.sol:214-230` (`renew`) — only checks
   `newExpiry >= expiry`; `src/migration/LockedWrapperReceiver.sol:228-241`
   (`_tokenRoleBitmapFromFuses`) grants subdomain owners `ROLE_RENEW` only when the
   V1 `CAN_EXTEND_EXPIRY` fuse is burned — which the subdomain owner typically cannot
   set themselves (V1 `setFuses` takes `uint16`, `setChildFuses` is parent-gated and
   PCC-blocked). Subdomain owners therefore **cannot renew their own names** and rely
   entirely on the virtual owner.
6. V1 divergence — `lib/ens-contracts/.../wrapper/ERC1155Fuse.sol` / `NameWrapper.sol`:
   expiry never moves the wrapped token; `BaseRegistrar._reclaim` (on
   re-registration) changes the registry owner but does not hand the subtree to the
   new registrant — the subtree freezes.

## Attack flow

1. Victim migrated a locked `.eth` name (e.g. `alice.eth`) with subdomains
   (`pay.alice.eth`). The `WrapperRegistry` for `alice.eth` holds root
   `REGISTRAR | RENEW | UPGRADE | CAN_NAME` roles granted to the eth registry
   contract; the virtual owner is `alice.eth`'s V2 owner.
2. `alice.eth` lapses (no renewal through `ETHRegistrar`).
3. Attacker registers `alice.eth` through `ETHRegistrar` (commit-reveal + rent),
   passing the existing `WrapperRegistry` as `subregistry`.
4. Attacker is now the virtual owner: `hasRoles(subTokenId, ROLE_RENEW, attacker)`
   returns `true` for every subdomain in the wrapper.
5. Subdomain owners cannot renew (no `ROLE_RENEW` on their tokens); each subdomain
   expires and the attacker re-registers it to themselves via
   `WrapperRegistry.register(...)` — free of charge (no rent path exists in
   `PermissionedRegistry.register`) and with any future expiry, including 1 second.
6. The attacker can also squat new labels under `alice.eth` indefinitely (rotation
   bot), holding the namespace hostage.

## Impact

- Theft of migrated subdomains **after their expiry** (subdomain owners cannot renew
  themselves; the attacker controls renewal and registration of the whole subtree).
- Free namespace squatting under the taken-over name (no rent, no minimum duration).
- Root `UPGRADE` on the wrapper (bounded by the `ApprovedUpgradeGate` allowlist) and
  root `CAN_NAME`.
- Live subdomains cannot be seized directly (the fuse translation grants no root
  `SET_RESOLVER`/`UNREGISTER`), stated honestly.

## PoC

`contracts/test/poc/EnsV2AuditPoC.t.sol::test_poc_parentLapse_subtreeTakeover`

```
forge test --match-test test_poc_parentLapse_subtreeTakeover -vvv
```

Result: PASS (1368k gas). The test migrates a locked 2LD + locked child, lets the
parent lapse, re-registers it to an attacker, asserts the attacker inherits root
`ROLE_RENEW` over the subtree, then expires the child and re-registers it to the
attacker.

## Remediation

On re-registration of a name that has an existing `WrapperRegistry` attached, either:
- (a) detach/rotate the wrapper (fresh registry for the new owner; migrate or freeze
  the old subtree explicitly), or
- (b) scope wrapper root roles to names registered BEFORE the parent's
  re-registration (e.g. snapshot `tokenVersionId` of the parent at wrapper
  initialization and refuse virtual-owner privilege for later versions).

## Defense analysis

- *"Parent controls subdomains — that's V1 PCC semantics"* — true while the parent is
  live. The divergence is the HANDOVER: V1 expiry never moved the locked token, so
  control never transferred; V2 hands the subtree to whoever re-registers the name.
- *"Parent lapse is rare"* — .eth names expire daily; re-registration is the core
  economic loop of the protocol. Every lapse of a migrated locked name with
  subdomains is exploitable.
- *"The attacker pays rent"* — for the parent only; the subtree control and all
  subsequent registrations are free.
