#include "client.h"

using namespace NetworkCore;

Client::Client(asio::io_service* ioService, SecureContext* context) :
    ClientSession(std::make_shared<asio::ip::tcp::socket>(*ioService), context),
    _ioService(ioService)
{
}

asio::io_service& Client::ioService()
{
    return *_ioService;
}
