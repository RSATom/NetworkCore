#pragma once

#include <string>

#include <asio.hpp>

#include "session.h"

namespace NetworkCore
{

class Client : public ClientSession
{
public:
    Client(asio::io_service* ioService, SecureContext*);

protected:
    asio::io_service& ioService();

private:
    asio::io_service* _ioService;
};

}
