#pragma once

#include <memory>

#ifdef CHAR_WIDTH
#undef CHAR_WIDTH
#endif
#define SPDLOG_ENABLE_SYSLOG 1
#include <spdlog/spdlog.h>


namespace NetworkCore
{

void InitLoggers(bool daemon);

const std::shared_ptr<spdlog::logger>& Log();

}
