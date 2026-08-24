#include "cpu/external_mem_interlock.hh"

namespace gem5
{

ExternalMemInterlock::Interface *ExternalMemInterlock::iface = nullptr;
std::function<void()> ExternalMemInterlock::onRelease;

} // namespace gem5
