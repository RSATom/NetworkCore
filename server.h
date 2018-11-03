#pragma once

#include <asio.hpp>

namespace NetworkCore
{

class Server
{
public:
    Server(asio::io_service* ioService, unsigned short port);

    void startAccept();

protected:
    asio::io_service* ioService() const;

    virtual void onNewConnection(
        const std::shared_ptr<asio::ip::tcp::socket>& socket) = 0;

private:
    void handleAccept(const std::shared_ptr<asio::ip::tcp::socket>& socket,
                      const asio::error_code& errorCode);

private:
    asio::io_service* _ioService;
    asio::ip::tcp::acceptor _acceptor;
};

}
