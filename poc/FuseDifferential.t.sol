// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// Exhaustive differential over the fuse→role translation tables
// (_tokenRoleBitmapFromFuses / _subregistryRoleBitmapFromFuses).
// 2^18 = 262144 fuse values; only 5 bits influence the output, but the loop
// proves no OTHER bit does. Bodies copied verbatim from
// src/migration/LockedWrapperReceiver.sol with the same constants imported
// from the vendored V1 INameWrapper. Functions are INTERNAL so the 2^18 loop
// costs no memory allocations.

import {
    CANNOT_BURN_FUSES,
    CANNOT_TRANSFER,
    CANNOT_SET_RESOLVER,
    CANNOT_CREATE_SUBDOMAIN,
    CAN_EXTEND_EXPIRY
} from "@ens/contracts/wrapper/INameWrapper.sol";

import {RegistryRolesLib} from "~src/registry/libraries/RegistryRolesLib.sol";
import {Test} from "forge-std/Test.sol";

contract FuseDifferentialTest is Test {
    // Verbatim copy of LockedWrapperReceiver._tokenRoleBitmapFromFuses
    function _tokenRoles(uint32 fuses) internal pure returns (uint256 roleBitmap) {
        if ((fuses & CAN_EXTEND_EXPIRY) != 0) {
            roleBitmap |= RegistryRolesLib.ROLE_RENEW;
        }
        if ((fuses & CANNOT_SET_RESOLVER) == 0) {
            roleBitmap |= RegistryRolesLib.ROLE_SET_RESOLVER;
        }
        if ((fuses & CANNOT_BURN_FUSES) == 0) {
            roleBitmap |= roleBitmap << 128; // give admin
        }
        if ((fuses & CANNOT_TRANSFER) == 0) {
            roleBitmap |= RegistryRolesLib.ROLE_CAN_TRANSFER_ADMIN; // no user
        }
    }

    // Verbatim copy of LockedWrapperReceiver._subregistryRoleBitmapFromFuses
    function _subregistryRoles(uint32 fuses) internal pure returns (uint256 roleBitmap) {
        if ((fuses & CANNOT_CREATE_SUBDOMAIN) == 0) {
            roleBitmap |= RegistryRolesLib.ROLE_REGISTRAR;
        }
        roleBitmap |=
            RegistryRolesLib.ROLE_RENEW |
            RegistryRolesLib.ROLE_UPGRADE |
            RegistryRolesLib.ROLE_CAN_NAME;
        if ((fuses & CANNOT_BURN_FUSES) == 0) {
            roleBitmap |= roleBitmap << 128; // give admin
        }
    }

    function test_fuseDifferential_exhaustive() external {
        // only these 5 bits matter; loop all 2^18 to prove no other bit leaks
        uint32 mask =
            uint32(
                CAN_EXTEND_EXPIRY |
                CANNOT_SET_RESOLVER |
                CANNOT_TRANSFER |
                CANNOT_BURN_FUSES |
                CANNOT_CREATE_SUBDOMAIN
            );
        bool ok = true;
        for (uint256 i = 0; i < (1 << 18); i++) {
            uint32 fuses = uint32(i);
            // bits outside the mask must not influence anything
            if (_tokenRoles(fuses) != _tokenRoles(fuses & mask)) ok = false;
            if (_subregistryRoles(fuses) != _subregistryRoles(fuses & mask)) ok = false;
        }
        assertTrue(ok, "some bit outside the 5-bit mask influences the translation");
    }

    function test_fuseDifferential_invariants() external {
        uint256 ctAdmin = RegistryRolesLib.ROLE_CAN_TRANSFER_ADMIN >> 128; // 1<<28
        for (uint32 i = 0; i < (1 << 5); i++) {
            uint32 fuses = i; // canonical: only 5 relevant bits
            uint256 tr = _tokenRoles(fuses);
            uint256 sr = _subregistryRoles(fuses);

            bool frozen = (fuses & CANNOT_BURN_FUSES) != 0;
            bool transferable = (fuses & CANNOT_TRANSFER) == 0;

            // --- token roles ---
            // RENEW <=> CAN_EXTEND_EXPIRY set
            assertEq(
                (tr & RegistryRolesLib.ROLE_RENEW) != 0,
                (fuses & CAN_EXTEND_EXPIRY) != 0,
                "RENEW vs CAN_EXTEND_EXPIRY"
            );
            // SET_RESOLVER <=> CANNOT_SET_RESOLVER unburned
            assertEq(
                (tr & RegistryRolesLib.ROLE_SET_RESOLVER) != 0,
                (fuses & CANNOT_SET_RESOLVER) == 0,
                "SET_RESOLVER vs CANNOT_SET_RESOLVER"
            );
            // CAN_TRANSFER_ADMIN <=> CANNOT_TRANSFER unburned (added after the
            // admin shift, so it is present even for frozen names)
            assertEq(
                (tr & RegistryRolesLib.ROLE_CAN_TRANSFER_ADMIN) != 0,
                transferable,
                "CAN_TRANSFER_ADMIN vs CANNOT_TRANSFER"
            );
            // admin half: mirror of RENEW|SET_RESOLVER when not frozen; frozen
            // names only keep CAN_TRANSFER_ADMIN's admin slot (if transferable)
            assertEq(
                (tr >> 128) & ~ctAdmin,
                frozen ? 0 : tr & (RegistryRolesLib.ROLE_RENEW | RegistryRolesLib.ROLE_SET_RESOLVER),
                "admin half mirror"
            );
            assertEq(
                (tr >> 128) & ctAdmin,
                transferable ? ctAdmin : 0,
                "frozen + transferable keeps CAN_TRANSFER_ADMIN"
            );
            // no roles outside the expected set
            uint256 allowed =
                (RegistryRolesLib.ROLE_RENEW | RegistryRolesLib.ROLE_SET_RESOLVER) |
                ((RegistryRolesLib.ROLE_RENEW | RegistryRolesLib.ROLE_SET_RESOLVER) << 128) |
                RegistryRolesLib.ROLE_CAN_TRANSFER_ADMIN;
            assertEq(tr & ~allowed, 0, "unexpected token roles");

            // --- subregistry roles ---
            assertEq(
                (sr & RegistryRolesLib.ROLE_REGISTRAR) != 0,
                (fuses & CANNOT_CREATE_SUBDOMAIN) == 0,
                "REGISTRAR vs CANNOT_CREATE_SUBDOMAIN"
            );
            assertTrue(sr & RegistryRolesLib.ROLE_RENEW != 0, "RENEW always");
            assertTrue(sr & RegistryRolesLib.ROLE_UPGRADE != 0, "UPGRADE always");
            assertTrue(sr & RegistryRolesLib.ROLE_CAN_NAME != 0, "CAN_NAME always");
            if (frozen) {
                assertEq(sr >> 128, 0, "frozen => no admin root roles");
            } else {
                // full regular half (UPGRADE/CAN_NAME sit at bits 120/124)
                assertEq(sr >> 128, sr & type(uint128).max, "root admin mirrors regular");
            }
            uint256 sAllowed =
                (RegistryRolesLib.ROLE_REGISTRAR |
                    RegistryRolesLib.ROLE_RENEW |
                    RegistryRolesLib.ROLE_UPGRADE |
                    RegistryRolesLib.ROLE_CAN_NAME);
            sAllowed |= sAllowed << 128;
            assertEq(sr & ~sAllowed, 0, "unexpected subregistry roles");
        }
    }

    function test_fuseDifferential_conflicts() external {
        uint256 ctAdmin = RegistryRolesLib.ROLE_CAN_TRANSFER_ADMIN >> 128;
        for (uint32 i = 0; i < (1 << 5); i++) {
            uint32 fuses = i;
            uint256 tr = _tokenRoles(fuses);
            // soulbound and transferable can't co-occur
            if ((fuses & CANNOT_TRANSFER) != 0) {
                assertEq(tr & RegistryRolesLib.ROLE_CAN_TRANSFER_ADMIN, 0, "soulbound");
            }
            // frozen names: no delegation surface except the transfer flag
            if ((fuses & CANNOT_BURN_FUSES) != 0) {
                assertEq(tr >> 128, (fuses & CANNOT_TRANSFER) == 0 ? ctAdmin : 0, "frozen admin surface");
                assertEq(_subregistryRoles(fuses) >> 128, 0, "frozen root admin surface");
            }
        }
    }
}
