#include "sbmr_boot_progress.hpp"

int main()
{
    auto bus = sdbusplus::bus::new_default();

    sdbusplus::server::manager_t objManager(bus, sbmrBootProgressService);
    bus.request_name(sbmrBootProgressService);

    SbmrBootProgress SbmrBootProgress{bus, sbmrBootProgressObj};

    while (true)
    {
        bus.process_discard();
        bus.wait();
    }
    return 0;
}
