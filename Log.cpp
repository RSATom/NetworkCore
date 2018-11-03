#include "Log.h"


namespace NetworkCore
{

static std::shared_ptr<spdlog::logger> NetworkCore;

void InitLoggers(bool daemon)
{
    if(NetworkCore)
        return;

    spdlog::sink_ptr sink;
    if(daemon)
        sink = std::make_shared<spdlog::sinks::syslog_sink>("NetworkCore", LOG_PID);
     else
        sink = std::make_shared<spdlog::sinks::stderr_sink_st>();

    NetworkCore = spdlog::create("NetworkCore", { sink });

#ifndef NDEBUG
    NetworkCore->set_level(spdlog::level::debug);
#else
    NetworkCore->set_level(spdlog::level::info);
#endif
}

const std::shared_ptr<spdlog::logger>& Log()
{
    return NetworkCore;
}

}
