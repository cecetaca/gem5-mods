/*
 * external_mem_interlock.hh — CPU-generic address-range interlock between
 * the core's scalar memory stream and an external (co-simulated) unit
 * that issues its own memory traffic.
 *
 * The external unit's backend registers itself here and answers
 * conflicts() against its set of in-flight address ranges. CPU models
 * consult it before letting a scalar load/store proceed to memory and
 * defer the access (retrying each cycle) while it conflicts. The query
 * is side-effect free, so wrong-path callers are safe.
 *
 * onRelease is invoked by the backend whenever a range is retired, so a
 * CPU that has gone idle with a deferred access is woken to retry.
 */

#ifndef __CPU_EXTERNAL_MEM_INTERLOCK_HH__
#define __CPU_EXTERNAL_MEM_INTERLOCK_HH__

#include <functional>

#include "base/types.hh"

namespace gem5
{

class ExternalMemInterlock
{
  public:
    class Interface
    {
      public:
        virtual ~Interface() = default;
        // True iff [vaddr, vaddr+size) overlaps an in-flight external
        // access and the scalar access must wait.
        virtual bool conflicts(Addr vaddr, unsigned size) = 0;
    };

    static Interface *iface;
    // Set by the CPU-side hook when it defers an access; called by the
    // backend when any range is released.
    static std::function<void()> onRelease;

    static bool
    conflicts(Addr vaddr, unsigned size)
    {
        return iface && iface->conflicts(vaddr, size);
    }

    static void
    released()
    {
        if (onRelease) {
            onRelease();
        }
    }
};

} // namespace gem5

#endif // __CPU_EXTERNAL_MEM_INTERLOCK_HH__
