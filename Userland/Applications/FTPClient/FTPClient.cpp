/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "FTPClient.h"
#include <LibCore/FileStream.h>
#include <LibCore/SocketAddress.h>
#include <LibCore/Stream.h>
#include <unistd.h>

#undef FTP_DEBUG
#define FTP_DEBUG 1

ErrorOr<void> FTPClient::run()
{
    m_socket = MUST(Core::Stream::TCPSocket::connect(Core::SocketAddress({ 127, 0, 0, 1 }, 2121)));
    MUST(m_socket.value()->set_blocking(true));
    dbgln("Connected, waiting for server accept code");
    MUST(drain_socket());

    MUST(send("USER stelar7\r\n"));
    MUST(drain_socket());

    MUST(send("PASS buggie\r\n"));
    MUST(drain_socket());

    MUST(send("CWD /res/html\r\n"));
    MUST(drain_socket());

    MUST(send("PASV\r\n"));
    String data = MUST(drain_socket());

    if (!data.contains("("sv)) {
        dbgln("Invalid response from server, closing");
        outln("Invalid response from server, closing");
        return {};
    }

    auto parts = data.split('(').at(1).split(')').at(0).split(',');
    auto port0 = parts.take_last();
    auto port1 = parts.take_last();
    IPv4Address ip = IPv4Address::from_string(String::join("."sv, parts)).value();
    u16 port = ((port1.to_int().value() & 0xFF) << 8 | (port0.to_int().value() & 0xFF)) & 0xFFFF;
    auto address = Core::SocketAddress(ip, port);

    MUST(send("RETR error.html\r\n"));

    dbgln("Connecting to data socket {}:{}", ip.to_string(), port);
    auto data_socket = TRY(Core::Stream::TCPSocket::connect(address));
    TRY(data_socket->set_blocking(true));

    MUST(drain_socket());

    auto outstream = TRY(Core::Stream::File::open("/home/anon/error_copy.html"sv, Core::Stream::OpenMode::Write | Core::Stream::OpenMode::Truncate));

    auto transfer_buffer = TRY(ByteBuffer::create_uninitialized(4 * KiB));

    while (true) {
        auto buffer_data = TRY(data_socket->read(transfer_buffer));

        if (buffer_data.is_empty()) {
            break;
        }

        dbgln_if(FTP_DEBUG, "Data socket sendt {}", String(buffer_data, AK::NoChomp));

        TRY(outstream->write(buffer_data));
    }

    data_socket->close();

    MUST(drain_socket());
    m_socket.value()->close();

    return {};
}

ErrorOr<String> FTPClient::drain_socket()
{
    dbgln_if(FTP_DEBUG, "Draining socket replies...");

    auto transfer_buffer = TRY(ByteBuffer::create_uninitialized(4 * KiB));

    auto trimmed_buffer = TRY(m_socket.value()->read(transfer_buffer));
    String data = String(trimmed_buffer, AK::NoChomp);

    // remove \r\n
    if (data.length() > 2) {
        data = data.substring(0, data.length() - 2);
    }

    dbgln_if(FTP_DEBUG, "Received: {}", data);

    return data;
}

void FTPClient::quit()
{
    if (m_socket.value()->is_open())
        m_socket.value()->close();
}

ErrorOr<size_t> FTPClient::send(String data)
{
    dbgln_if(FTP_DEBUG, "Sending: {}", data);

    if (!m_socket.value()->is_open()) {
        quit();
        return Error::from_string_literal("No socket to send data on");
    }

    return m_socket.value()->write(data.bytes());
}
