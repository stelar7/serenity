/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "FTPClient.h"
#include <LibCore/Stream.h>

class FTPClient final {
public:
    ErrorOr<void> run();

private:
    ErrorOr<String> drain_socket();
    void quit();
    ErrorOr<size_t> send(String);

    Optional<NonnullOwnPtr<Core::Stream::TCPSocket>> m_socket;
};
