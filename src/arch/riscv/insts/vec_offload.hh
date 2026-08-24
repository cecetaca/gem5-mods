/*
 * vec_offload.hh — interface between the RISC-V ISA's vector-offload
 * decode path and an external vector unit backend (e.g. the act-gem5
 * ActUnit bridge, built via EXTRAS).
 *
 * When RiscvISA.vector_offload is set, RVV macro-ops decode to a single
 * VecOffloadMicroInst (no LMUL cracking); at commit the micro-op builds
 * a VecOffloadRecord and hands it to the registered backend. The backend
 * normalizes the raw encoding fields (vfunct6/funct3) into its own op
 * ids — this header stays binding-agnostic.
 *
 * Phase-1 process-wide hookup: one backend, one offloading hart.
 */

#ifndef __ARCH_RISCV_INSTS_VEC_OFFLOAD_HH__
#define __ARCH_RISCV_INSTS_VEC_OFFLOAD_HH__

#include <cstdint>

namespace gem5
{
namespace RiscvISA
{

struct VecOffloadRecord
{
    // raw identifying encoding (normalized by the backend)
    uint32_t rawInst = 0;    // full 32-bit instruction word
    uint8_t vfunct6 = 0;     // bits 31:26
    uint8_t funct3 = 0;      // bits 14:12 (OPIVV/OPFVV/OPMVV/OPIVI/...)
    uint8_t opClass = 0;     // VecOffloadOpClass below
    // operands
    uint8_t vd = 0;
    uint8_t vs1 = 0;         // vs1 / rs1 index / simm5, by funct3
    uint8_t vs2 = 0;
    uint8_t vm = 0;          // 0 = masked by v0
    // vector configuration at decode
    uint8_t vsew = 0;        // vtype encoding
    uint8_t vlmul = 0;       // vtype encoding (3 bits, fractional incl.)
    uint8_t vta = 0;
    uint8_t vma = 0;
    uint16_t vl = 0;
    uint16_t vstart = 0;     // phase 1: always 0, still carried
    // scalar operand value (.vx/.vf forms), read at execute
    uint64_t scalar = 0;
};

enum VecOffloadOpClass : uint8_t
{
    VecOffloadArith = 0,
    VecOffloadLoad = 1,
    VecOffloadStore = 2,
    VecOffloadToScalar = 3,
    VecOffloadConfig = 4,
};

class VecOffloadBackend
{
  public:
    virtual ~VecOffloadBackend() = default;

    // Fire-and-forget offload of an arithmetic (VRF-internal) record.
    // Called at commit (the micro-op is non-speculative), in program
    // order.
    virtual void issueArith(const VecOffloadRecord &rec) = 0;
};

// Process-wide state (phase 1: single backend / single offloading hart).
// `enabled` is set from the RiscvISA.vector_offload param at ISA
// construction; the backend registers itself at construction time.
struct VecOffload
{
    static bool enabled;
    static VecOffloadBackend *backend;
};

inline bool vecOffloadActive() { return VecOffload::enabled; }

} // namespace RiscvISA
} // namespace gem5

#endif // __ARCH_RISCV_INSTS_VEC_OFFLOAD_HH__
