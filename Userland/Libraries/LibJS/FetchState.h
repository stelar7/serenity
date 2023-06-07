/*
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Forward.h>
#include <LibJS/Heap/Cell.h>
#include <LibJS/Script.h>

namespace JS {

// Record { [[ParseError]]: null, [[Destination]]: destination, [[PerformFetch]]: null }
struct FetchState : public Cell
    , public JS::Script::HostDefined {
    JS_CELL(FetchState, Cell);

    FetchState(JS::GCPtr<JS::Value> parse_error, StringView destination, Function<void()> perform_fetch)
        : m_parse_error(move(parse_error))
        , m_destination(destination)
        , m_perform_fetch(move(perform_fetch))
    {
    }

    virtual void visit_host_defined_self(JS::Cell::Visitor&) override
    {
    }

    JS::GCPtr<JS::Value> m_parse_error;
    StringView m_destination;
    Function<void()> m_perform_fetch;
};

}
