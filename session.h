#pragma once

#include <limits>
#include <memory>
#include <deque>

#include <asio.hpp>
#include <asio/ssl.hpp>

namespace NetworkCore
{

///////////////////////////////////////////////////////////////////////////////
class Session : public std::enable_shared_from_this<Session>
{
public:
    typedef uint32_t MessageType;
    typedef asio::ssl::context SecureContext;

    enum : MessageType {
        PING = std::numeric_limits<MessageType>::max() - 1,
        PONG = std::numeric_limits<MessageType>::max() - 2,
    };

    // body will be swapped
    void writeMessageAsync(MessageType type, std::string* body);

    void disconnect();

    virtual void shutdown(const std::function<void ()>& finished);
    bool shuttingDown() const;

protected:
    Session(const std::shared_ptr<asio::ip::tcp::socket>&, SecureContext*, bool client);

    asio::ip::tcp::socket& socket();
    asio::io_service& ioService();

    typedef asio::ssl::stream<asio::ip::tcp::socket&> SecureStream;
    SecureStream& secureStream();

    virtual void onConnected(const asio::error_code& errorCode);

    void readMessageAsync();
    virtual void onMessage(MessageType, const std::string&, const asio::error_code&) = 0;

    virtual void onWriteFail(MessageType, const std::string&, const asio::error_code&);

private:
    typedef uint32_t MessageSize;

    const bool _clientSession;

    struct MessagePrefix
    {
        MessagePrefix(MessageType, MessageSize);

        MessageType type;
        MessageSize size;
    };

    struct Message
    {
        Message(MessageType type, std::string* body);
        Message(const MessagePrefix& prefix);

        MessagePrefix prefix;
        std::string message;
    };

    void messageReaded(
        const std::shared_ptr<Message>& message,
        const asio::error_code& error, std::size_t bytesTransferred);
    void prefixReaded(
        const std::shared_ptr<MessagePrefix>& prefix,
        const asio::error_code& error, std::size_t bytesTransferred);

    void writeMessageAsync(const std::shared_ptr<Message>&);
    void messageWritten(
        const std::shared_ptr<Message>& message,
        const asio::error_code& error,
        std::size_t bytesTransferred);

    void schedulePing();

private:
    bool _shuttingDown;

    std::shared_ptr<asio::ip::tcp::socket> _socket;

    SecureStream _secureStream;

    std::deque<std::shared_ptr<Message> > _outgoingMessages;

    asio::steady_timer _pingTimer;
};

///////////////////////////////////////////////////////////////////////////////
class ServerSession : public Session
{
public:
    void handshake(); // had to move out from constructor to be able use shared_from_this

protected:
    ServerSession(const std::shared_ptr<asio::ip::tcp::socket>& socket, SecureContext*);
};

///////////////////////////////////////////////////////////////////////////////
class ClientSession : public Session
{
public:
    void connect(const std::string& server, unsigned short port);

protected:
    ClientSession(const std::shared_ptr<asio::ip::tcp::socket>& socket, SecureContext*);

    void onSocketConnected(const asio::error_code& errorCode);

private:
    void onServerResolved(
        const asio::error_code, asio::ip::tcp::resolver::iterator, unsigned short port);

private:
    asio::ip::tcp::resolver _resolver;
};

}
