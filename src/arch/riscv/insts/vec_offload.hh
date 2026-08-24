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

class ThreadContext;

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

enum class VecMemMode : uint8_t
{
    Unit = 0,
    Strided = 1,
    Indexed = 2,     // ordered and unordered (executed sequentially)
    Fof = 4,         // unit-stride fault-only-first
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

    // Vector-to-scalar (deferred wakeup): the query micro-op issues the
    // record at the ROB head (fire-and-forget, program order); the
    // dependent collect micro-op is an uncacheable load from the
    // backend's response device, so younger instructions keep executing
    // while the response is pending. At most one query is outstanding
    // (the collect load must commit before the next query reaches the
    // head).
    virtual void v2sIssueQuery(const VecOffloadRecord &rec) = 0;
    // VA of the response device word for the pending query; lazily maps
    // the device page into the SE process on first use.
    virtual uint64_t v2sLoadVAddr(ThreadContext *tc) = 0;

    // Vector memory: the external unit owns address generation and
    // element traffic; gem5 services its requests. The instruction
    // still blocks at the ROB head for the whole transfer (phase-1
    // ordering pessimism retained). First call for a dynamic seqNum
    // starts the access; returns true while incomplete. base/stride
    // are architectural register values read at the ROB head.
    // rec.funct3 carries the raw mem width bits (14:12); segment nf
    // comes from rec.rawInst bits 31:29.
    virtual bool vecMemBlocked(uint64_t seqNum,
                               const VecOffloadRecord &rec,
                               ThreadContext *tc, uint64_t base,
                               uint64_t stride, bool isStore,
                               VecMemMode mode) = 0;

    // Valid at execute() of a fault-only-first op that unblocked: the
    // number of elements completed before the first faulting element
    // (the new vl).
    virtual uint32_t consumeFofVl() = 0;

    // Decoupled vector memory (default): the instruction hands the
    // access off at the commit point and retires immediately; ordering
    // against the scalar memory stream is enforced by the external
    // memory interlock (cpu/external_mem_interlock.hh), whose ranges
    // the backend registers per in-flight access.
    virtual void vecMemIssue(const VecOffloadRecord &rec,
                             ThreadContext *tc, uint64_t base,
                             uint64_t stride, bool isStore,
                             VecMemMode mode) = 0;

    // Current value of the vector-to-scalar response word (used when a
    // CPU model completes the collect load with a null packet).
    virtual uint64_t v2sPeekValue() = 0;
};

// Process-wide state (phase 1: single backend / single offloading hart).
// `enabled` is set from the RiscvISA.vector_offload param at ISA
// construction; the backend registers itself at construction time.
struct VecOffload
{
    static bool enabled;
    // decoupled vector memory (retire at issue + address-range
    // interlock) vs the blocking A/B baseline
    static bool decoupledMem;
    static VecOffloadBackend *backend;
};

inline bool vecOffloadActive() { return VecOffload::enabled; }

} // namespace RiscvISA
} // namespace gem5

#endif // __ARCH_RISCV_INSTS_VEC_OFFLOAD_HH__
