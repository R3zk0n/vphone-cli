// KernelPatchAmfiOSEntitlementsConsistency.swift — AMFI OSEntitlements context consistency bypass.
//
// After patch 26 allows entitlement parsing for non-main binaries, the parsed
// entitlements flow into OSEntitlements::mergeContexts. This function asserts
// that the "instance" and "monitor" entitlement contexts are either both present
// or both NULL. For ad-hoc signed non-main binaries the instance context is NULL
// while the monitor context exists from the app's main binary, producing a
// "1 | 0" mismatch → kernel panic at OSEntitlements.cpp:239.
//
// Strategy:
//   1. Find the "AMFI: inconsistency between instance and monitor context" string.
//   2. Find ADRP+ADD xref from AMFI code to that string.
//   3. Walk backward from the xref to locate the B.NE (consistency check) preceded
//      by CMP Wn, Wn (register-register compare of CSET results).
//   4. Decode the CBZ at B.NE+8 to find the function's return epilogue.
//   5. Re-encode B.NE as unconditional B to the return epilogue.
//
// Safety: no locks held, no resources allocated, epilogue properly restores
// callee-saved registers. Returning early means the entitlement merge is skipped
// (correct behavior when instance_ctx is NULL — nothing to merge).

import Capstone
import Foundation

extension KernelPatcher {
    // MARK: - AMFI OSEntitlements Context Consistency Bypass

    /// Bypass the OSEntitlements "inconsistency between instance and monitor context" panic.
    ///
    /// Changes the B.NE at the consistency check to an unconditional B targeting the
    /// function's return epilogue, so mismatched contexts (instance=NULL, monitor!=NULL)
    /// return cleanly instead of panicking.
    @discardableResult
    func patchAmfiOSEntitlementsConsistency() -> Bool {
        log("\n[27] AMFI OSEntitlements: bypass context consistency panic")

        // Step 1: Locate the panic string.
        guard let strOff = buffer.findString(
            "AMFI: inconsistency between instance and monitor context"
        ) else {
            log("  [-] OSEntitlements consistency panic string not found")
            return false
        }

        // Step 2: Find ADRP+ADD references from AMFI code to the string.
        let amfiRange = amfiTextRange()
        let refs = findStringRefs(strOff, in: amfiRange)
        guard !refs.isEmpty else {
            log("  [-] no code refs to OSEntitlements consistency string")
            return false
        }

        // Step 3: Walk backward from each xref's ADRP to find the B.NE.
        // The B.NE is ~0xB4 bytes before the ADRP (the panic path has several
        // STP/CSET/MOV instructions between the B.NE and the string load).
        // Pattern before the string ref:
        //   CMP  X_, #0; CSET W8, NE; CMP  X_, #0; CSET W9, NE; CMP W8, W9; B.NE <panic>
        for (adrpOff, _) in refs {
            let scanStart = max(adrpOff - 0x120, amfiRange.start)
            for off in stride(from: adrpOff - 4, through: scanStart, by: -4) {
                let insns = disasm.disassemble(in: buffer.data, at: off, count: 1)
                guard let insn = insns.first else { continue }

                // Look for B.NE
                guard insn.mnemonic == "b.ne" else { continue }

                // Verify the preceding instruction is CMP Wn, Wn (register-register)
                let prevInsns = disasm.disassemble(in: buffer.data, at: off - 4, count: 1)
                guard let prevInsn = prevInsns.first,
                      prevInsn.mnemonic == "cmp"
                else { continue }

                // Both operands must be W-registers (not immediate)
                guard let detail = prevInsn.aarch64,
                      detail.operands.count >= 2,
                      detail.operands[0].type == AARCH64_OP_REG,
                      detail.operands[1].type == AARCH64_OP_REG
                else { continue }

                // Step 4: Decode CBZ at B.NE + 8 to find the return epilogue target.
                // Pattern: B.NE <panic>; LDR X8, [X19, #0x50]; CBZ X8, <return>
                let cbzOff = off + 8
                let cbzInsns = disasm.disassemble(in: buffer.data, at: cbzOff, count: 1)
                guard let cbzInsn = cbzInsns.first,
                      cbzInsn.mnemonic == "cbz"
                else { continue }

                // Decode the CBZ branch target from raw instruction bits.
                // CBZ encoding: [31]=sf [30:25]=011010 [24]=0 [23:5]=imm19 [4:0]=Rt
                let cbzRaw = buffer.readU32(at: cbzOff)
                let cbzImm19 = (cbzRaw >> 5) & 0x7FFFF
                let signedCbzImm = Int32(bitPattern: cbzImm19 << 13) >> 13
                let returnOff = cbzOff + Int(signedCbzImm) * 4

                // Sanity: return target should be within AMFI range and after the B.NE
                guard returnOff > off, returnOff < amfiRange.end else {
                    log("  [-] CBZ target out of range")
                    continue
                }

                // Step 5: Encode unconditional B from B.NE location to the return epilogue.
                guard let bData = ARM64Encoder.encodeB(from: off, to: returnOff) else {
                    log("  [-] failed to encode B to return epilogue")
                    continue
                }

                let va = fileOffsetToVA(off)
                emit(
                    off,
                    bData,
                    patchID: "kernel.amfi.osentitlements_context_consistency",
                    virtualAddress: va,
                    description: "B (was B.NE) [OSEntitlements — skip context consistency panic, branch to return]"
                )
                return true
            }
        }

        log("  [-] B.NE consistency check not found before panic string ref")
        return false
    }
}
