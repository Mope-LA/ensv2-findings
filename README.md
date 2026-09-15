# ENSv2 (contracts-v2) — Security Findings

Two documented findings against ENSv2's `contracts-v2` (`ensdomains/contracts-v2`
@ `48b3e2d`), with passing Foundry PoCs. EVM/Solidity scope.

## Findings

### F5 — Subtree takeover on parent lapse (Medium)

When a migrated, locked `.eth` name expires and is re-registered, the new owner
becomes the **virtual owner** of the name's existing `WrapperRegistry` and
inherits its root roles (`REGISTRAR`, `RENEW`, `UPGRADE`, `CAN_NAME`). Subdomain
owners cannot renew their own names (no `ROLE_RENEW` on their tokens), so after
each child expiry the new parent owner re-registers the child to themselves —
taking over the migrated subtree name by name, and squatting new labels without
rent.

- Full report: [`findings/f5_subtree_takeover.md`](findings/f5_subtree_takeover.md)
- PoC: `poc/EnsV2AuditPoC.t.sol::test_poc_parentLapse_subtreeTakeover` — PASS

### F6 — PublicResolverV2 records frozen for V2-only names (Low)

`PublicResolverV2.canModifyName` resolves the name preimage exclusively through
the ENSv1 `NameWrapper`. Names registered only in ENSv2 have no V1 preimage, so
`canModifyName` returns `false` even for the owner — every profile write path
reverts permanently. The name pays rent but its records can never be written.

- Full report: [`findings/f6_publicresolver_frozen.md`](findings/f6_publicresolver_frozen.md)
- PoC: `poc/EnsV2AuditPoC.t.sol::test_poc_publicResolverV2_v2OnlyName_frozenRecords` — PASS

## PoC test files

| File | Contents |
|---|---|
| `poc/EnsV2AuditPoC.t.sol` | 4 PoC tests: the two findings above, plus `test_poc_subdomainRenew_beyondParentExpiry` and `test_poc_operatorRevokeOwnerAdminRoles_bricksName` (internal checks, not submitted separately) |
| `poc/FuseDifferential.t.sol` | Differential checks of the fuse → role translation logic (exhaustive + invariants), used to rule out a fuse-mapping class |

## Run

```bash
# in a checkout of ensdomains/contracts-v2 @ 48b3e2d,
# copy poc/* into contracts/test/poc/ and run:
forge test --match-path test/poc/EnsV2AuditPoC.t.sol -vvv
forge test --match-path test/poc/FuseDifferential.t.sol -vvv
```

## Disclosure

Prepared as submission documents against the ENSv2 contracts. See each finding
for the full attack flow, evidence with line references, remediation
suggestions, and defense analysis.

## License

MIT. ENS contracts are © ENS Labs / ENS DAO; the PoC tests and finding reports
in this repo are original work.
