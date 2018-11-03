#include "session.h"

#include <functional>

#include "Log.h"


enum {
#ifdef NDEBUG
    BASE_PING_TIMEOUT = 5 * 60,
#else
    BASE_PING_TIMEOUT = 30,
#endif
    SERVER_PING_TIMEOUT = 2 * BASE_PING_TIMEOUT,
    CLIENT_PING_TIMEOUT = BASE_PING_TIMEOUT,
};

using namespace NetworkCore;

///////////////////////////////////////////////////////////////////////////////
Session::MessagePrefix::MessagePrefix(MessageType type, MessageSize size) :
    type(type), size(size)
{
}

Session::Message::Message(MessageType type, std::string* body) :
    prefix(static_cast<MessageType>(type), (body ? body->size() : 0))
{
    if(body)
        message.swap(*body);
}

Session::Message::Message(const MessagePrefix& prefix) :
    prefix(prefix), message(prefix.size, 0)
{
}

Session::Session(
    const std::shared_ptr<asio::ip::tcp::socket>& socket,
    SecureContext* context,
    bool clientSession) :
    _clientSession(clientSession),
    _shuttingDown(false),
    _socket(socket),
    _secureStream(*socket, *context),
    _pingTimer(_socket->get_io_service())
{
}

asio::ip::tcp::socket& Session::socket()
{
    return *_socket;
}

asio::io_service& Session::ioService()
{
    return _secureStream.get_io_service();
}

Session::SecureStream& Session::secureStream()
{
    return _secureStream;
}

void Session::onConnected(const asio::error_code& errorCode)
{
    if(errorCode)
        disconnect();
    else if(_outgoingMessages.empty())
        schedulePing();
}

void Session::onWriteFail(MessageType, const std::string&, const asio::error_code& errorCode)
{
    if(errorCode)
        disconnect();
}

void Session::messageReaded(
    const std::shared_ptr<Message>& message,
    const asio::error_code& error, std::size_t bytesTransferred)
{
    if(!error && (PING ==message->prefix.type || PONG == message->prefix.type)) {
        if(PING ==message->prefix.type) {
            Log()->trace("Got PING. Sending PONG.");
            writeMessageAsync(PONG, nullptr);
        } else if(PONG ==message->prefix.type)
            Log()->trace("Got PONG");

        readMessageAsync();
    } else
        onMessage(message->prefix.type, message->message, error);

    if(error)
        disconnect();
}

void Session::prefixReaded(
    const std::shared_ptr<MessagePrefix>& prefix,
    const asio::error_code& error, std::size_t bytesTransferred)
{
    std::shared_ptr<Message> message = std::make_shared<Message>(*prefix);

    if(sizeof(prefix->type) + sizeof(prefix->size) != bytesTransferred) {
        Log()->error("Got message prefix with wrong size");
        messageReaded(message, asio::error::invalid_argument, 0);
        return;
    }

    if(!error && prefix->size) {
        asio::async_read(
            secureStream(), asio::buffer(&message->message[0], prefix->size),
            std::bind(
                &Session::messageReaded, shared_from_this(), message,
                std::placeholders::_1, std::placeholders::_2));
    } else {
        messageReaded(message, error, 0);
    }
}

void Session::readMessageAsync()
{
    std::shared_ptr<MessagePrefix> prefix = std::make_shared<MessagePrefix>(0, 0);

    std::array<asio::mutable_buffer, 2> buffers = {
        asio::buffer(&prefix->type, sizeof(prefix->type)),
        asio::buffer(&prefix->size, sizeof(prefix->size))
    };

    asio::async_read(
        secureStream(), buffers,
        std::bind(
            &Session::prefixReaded, shared_from_this(), prefix,
            std::placeholders::_1, std::placeholders::_2));
}

void Session::messageWritten(
    const std::shared_ptr<Message>& message,
    const asio::error_code& error, std::size_t bytesTransferred)
{
    if(error)
        onWriteFail(message->prefix.type, message->message, error);

    assert(
        !_outgoingMessages.empty() &&
        message == _outgoingMessages.front());

    _outgoingMessages.pop_front();

    if(!_outgoingMessages.empty())
        writeMessageAsync(_outgoingMessages.front());
    else
        schedulePing();
}

void Session::writeMessageAsync(MessageType type, std::string* body)
{
    std::shared_ptr<Message> message = std::make_shared<Message>(type, body);

    const bool sendNow = _outgoingMessages.empty();
    _outgoingMessages.emplace_back(message);

    if(sendNow)
        writeMessageAsync(message);
}

void Session::writeMessageAsync(const std::shared_ptr<Message>& message)
{
    if(message->prefix.size) {
        std::array<asio::const_buffer, 3> buffers = {
            asio::buffer(&message->prefix.type, sizeof(message->prefix.type)),
            asio::buffer(&message->prefix.size, sizeof(message->prefix.size)),
            asio::buffer(message->message.data(), message->message.size())
        };

        asio::async_write(
            secureStream(), buffers,
            std::bind(
                &Session::messageWritten, shared_from_this(), message,
                std::placeholders::_1, std::placeholders::_2));
    } else {
        std::array<asio::const_buffer, 2> buffers = {
            asio::buffer(&message->prefix.type, sizeof(message->prefix.type)),
            asio::buffer(&message->prefix.size, sizeof(message->prefix.size)),
        };

        asio::async_write(
            secureStream(), buffers,
            std::bind(
                &Session::messageWritten, shared_from_this(), message,
                std::placeholders::_1, std::placeholders::_2));
    }
}

void Session::schedulePing()
{
    Log()->trace("Session::schedulePing");

    _pingTimer.expires_from_now(
        std::chrono::seconds(
            _clientSession ?
                CLIENT_PING_TIMEOUT :
                SERVER_PING_TIMEOUT));
    _pingTimer.async_wait(
        [this] (const asio::error_code& error) {
            if(error)
                return;

            Log()->trace("Sending PING");
            writeMessageAsync(PING, nullptr);
        }
    );
}

void Session::disconnect()
{
    _pingTimer.cancel();

    std::error_code secureStreamShutdownError;
    // maybe should use async_shutdown
    _secureStream.shutdown(secureStreamShutdownError);
    // will assert if connection was not established
    // don't know how check it before shutdown
    //assert(!secureStreamShutdownError);

    std::error_code socketShutdownError;
    // maybe should use async_shutdown
    _socket->shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both, socketShutdownError);
    // will assert if connection was not established
    // don't know how check it before shutdown
    //assert(!socketShutdownError);

    _socket->close();
}

void Session::shutdown(const std::function<void ()>& finished)
{
    _shuttingDown = true;

    disconnect();

    _socket->get_io_service().post(finished);
}

bool Session::shuttingDown() const
{
    return _shuttingDown;
}

///////////////////////////////////////////////////////////////////////////////
ServerSession::ServerSession(
    const std::shared_ptr<asio::ip::tcp::socket>& socket, SecureContext* context) :
    Session(socket, context, false)
{
}

void ServerSession::handshake()
{
    secureStream().async_handshake(
        asio::ssl::stream_base::server,
        std::bind(
            &ServerSession::onConnected,
            shared_from_this(),
            std::placeholders::_1));
}

///////////////////////////////////////////////////////////////////////////////
ClientSession::ClientSession(
    const std::shared_ptr<asio::ip::tcp::socket>& socket,
    SecureContext* context) :
    Session(socket, context, true), _resolver(socket->get_io_service())
{
}

void ClientSession::onSocketConnected(const asio::error_code& errorCode)
{
    if(!errorCode) {
        secureStream().async_handshake(
            asio::ssl::stream_base::client,
            std::bind(
                &ClientSession::onConnected,
                std::static_pointer_cast<ClientSession>(shared_from_this()),
                std::placeholders::_1));
    } else
        onConnected(errorCode);
}

void ClientSession::onServerResolved(
    const asio::error_code errorCode,
    asio::ip::tcp::resolver::iterator it,
    unsigned short port)
{
    using namespace asio::ip;

    if(!errorCode) {
        tcp::endpoint endpoint = *it;
        endpoint.port(port);

        socket().async_connect(
            endpoint,
            std::bind(
                &ClientSession::onSocketConnected,
                std::static_pointer_cast<ClientSession>(shared_from_this()),
                std::placeholders::_1));
    } else
        onConnected(errorCode);
}

void ClientSession::connect(const std::string& server, unsigned short port)
{
    using namespace asio::ip;
    tcp::resolver::query query(server, std::string());

    _resolver.async_resolve(
        query,
        std::bind(
            &ClientSession::onServerResolved,
            std::static_pointer_cast<ClientSession>(shared_from_this()),
            std::placeholders::_1, std::placeholders::_2, port));
}
