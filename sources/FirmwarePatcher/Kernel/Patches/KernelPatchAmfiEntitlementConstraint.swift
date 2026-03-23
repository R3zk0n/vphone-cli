// KernelPatchAmfiEntitlementConstraint.swift — AMFI non-main-binary entitlement constraint bypass.
//
// AMFI enforces a launch constraint that kills processes whose embedded
// frameworks or dylibs carry entitlements ("has entitlements but is not a
// main binary"). This affects apps with many embedded frameworks (WeChat,
// TikTok) after ad-hoc re-signing with ldid.
//
// Strategy:
//   1. Find the "AMFI: constraint violation %s has entitlements but is not a main binary" string.
//   2. Find ADRP+ADD xref from AMFI code to that string.
//   3. Walk backward from the xref to locate the B.CC (version gate) that branches
//      to the entitlement parsing path. The pattern is:
//        REV     Wn, Wm          ; byte-swap code signing version
//        LSR     Wn, Wn, #0xA    ; extract version field
//        CMP     Wn, #0x81       ; version threshold
//        B.CC    <entitlement_parsing>   ← patch target
//   4. Change B.CC to unconditional B, so all binaries (regardless of version
//      or main-binary flag) proceed to entitlement parsing.

import Capstone
import Foundation

extension KernelPatcher {
    // MARK: - AMFI Entitlement Constraint Bypass

    /// Bypass the AMFI "entitlements but is not a main binary" constraint check.
    ///
    /// Changes the conditional branch (B.CC) at the code signing version gate to
    /// an unconditional branch (B), so non-main binaries with entitlements are
    /// always sent to the entitlement parsing path instead of being rejected.
    @discardableResult
    func patchAmfiEntitlementConstraint() -> Bool {
        log("\n[26] AMFI entitlement constraint: bypass non-main-binary check")

        // Step 1: Locate the constraint violation string.
        guard let strOff = buffer.findString(
            "AMFI: constraint violation %s has entitlements but is not a main binary"
        ) else {
            log("  [-] constraint violation string not found")
            return false
        }

        // Step 2: Find ADRP+ADD references from AMFI code to the string.
        let amfiRange = amfiTextRange()
        let refs = findStringRefs(strOff, in: amfiRange)
        guard !refs.isEmpty else {
            log("  [-] no code refs to constraint violation string")
            return false
        }

        // Step 3: Walk backward from the first xref's ADRP to find the B.CC.
        // The pattern within ~0x60 bytes before the string ref is:
        //   REV Wn, Wm; LSR Wn, Wn, #0xA; CMP Wn, #0x81; B.CC <target>
        for (adrpOff, _) in refs {
            let scanStart = max(adrpOff - 0x80, amfiRange.start)
            for off in stride(from: adrpOff - 4, through: scanStart, by: -4) {
                let insns = disasm.disassemble(in: buffer.data, at: off, count: 1)
                guard let insn = insns.first else { continue }

                // Look for B.CC (also called B.LO): conditional branch with CC condition
                guard insn.mnemonic == "b.lo" || insn.mnemonic == "b.cc" else { continue }

                // Verify the preceding instruction is CMP Wn, #0x81
                let prevInsns = disasm.disassemble(in: buffer.data, at: off - 4, count: 1)
                guard let prevInsn = prevInsns.first,
                      prevInsn.mnemonic == "cmp"
                else { continue }

                // Check the CMP has immediate operand 0x81
                guard let detail = prevInsn.aarch64,
                      detail.operands.count >= 2,
                      detail.operands[1].type == AARCH64_OP_IMM,
                      detail.operands[1].imm == 0x81
                else { continue }

                // Step 4: Patch B.CC → unconditional B to the same target.
                // B.cond encoding: [31:25]=0b0101010 [24]=0 [23:5]=imm19 [4]=0 [3:0]=cond
                // B encoding:      [31:26]=0b000101 [25:0]=imm26
                let raw = buffer.readU32(at: off)

                // Extract the signed imm19 field from B.cond (bits [23:5])
                let imm19 = (raw >> 5) & 0x7FFFF
                let signedImm19 = Int32(bitPattern: imm19 << 13) >> 13
                // imm19 is in units of 4 bytes, same as imm26
                let imm26 = UInt32(bitPattern: signedImm19) & 0x03FF_FFFF
                let bInsn = (0b000101 << 26) | imm26

                var patchData = Data(count: 4)
                patchData.withUnsafeMutableBytes { ptr in
                    ptr.storeBytes(of: bInsn.littleEndian, as: UInt32.self)
                }

                let va = fileOffsetToVA(off)
                emit(
                    off,
                    patchData,
                    patchID: "kernel.amfi.entitlement_constraint_bypass",
                    virtualAddress: va,
                    description: "B (was B.CC) [AMFI entitlement constraint — allow non-main binaries with entitlements]"
                )
                return true
            }
        }

        log("  [-] B.CC version gate not found before constraint violation string ref")
        return false
    }
}
