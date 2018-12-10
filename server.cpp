#include "server.h"

#include <functional>


using namespace NetworkCore;

Server::Server(asio::io_service* ioService, unsigned short port) :
    _ioService(ioService),
    _acceptor(*ioService, asio::ip::tcp::endpoint(asio::ip::tcp::v6(), port))
{
}

asio::io_service* Server::ioService() const
{
    return _ioService;
}

void Server::startAccept()
{
    using namespace asio;

    std::shared_ptr<ip::tcp::socket> socket =
        std::make_shared<ip::tcp::socket>(*_ioService);

    _acceptor.async_accept(
        *socket,
        std::bind(
            &Server::handleAccept, this,
            socket, std::placeholders::_1));
}

void Server::handleAccept(const std::shared_ptr<asio::ip::tcp::socket>& socket,
                          const asio::error_code& errorCode)
{
    if(!errorCode)
        onNewConnection(socket);

    startAccept();
}
