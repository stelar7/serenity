/*
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibYAML/Parser/Parser.h>

namespace YAML {

ErrorOr<RefPtr<Event>> Parser::produce_stream_start_event()
{
    auto start_token = TRY(m_tokenizer.next_token());
    auto event = make_ref_counted<StreamStartEvent>(start_token->start_mark(), start_token->end_mark());
    m_state = ProductionState::ParseImplicitDocumentStart;

    dbgln("Produced StreamStartEvent");

    return event;
}

ErrorOr<RefPtr<Event>> Parser::produce_implicit_document_start_event()
{
    // if (m_tokenizer.peek_token())
    auto start_token = TRY(m_tokenizer.next_token());
    auto event = make_ref_counted<StreamStartEvent>(start_token->start_mark(), start_token->end_mark());
    m_state = ProductionState::ParseImplicitDocumentStart;

    dbgln("Produced StreamStartEvent");

    return event;
}

ErrorOr<Vector<Node>> Parser::parse()
{
    Vector<Node> nodes;

    while (has_next()) {
        auto event = TRY(next_event());
        dbgln("Event: {}", (u8)event->type());
        (void)event;
    }

    return Error::from_string_view("Not implemented parse"sv);
}

ErrorOr<RefPtr<Event>> Parser::next_event()
{
    TRY(peek_event());

    auto event = m_current_event;
    m_current_event = nullptr;
    return event;
}

ErrorOr<void> Parser::peek_event()
{
    TRY(produce_event());

    if (!m_current_event) {
        return Error::from_string_view("No more events"sv);
    }

    dbgln("Peeked event: {}", (u8)m_current_event->type());

    return {};
}

bool Parser::has_next()
{
    if (is_event(EventType::StreamStart)) {
        (void)next_event();
    }

    dbgln("Has next: {}", !is_event(EventType::StreamEnd));

    return !is_event(EventType::StreamEnd);
}

bool Parser::is_event(EventType type)
{
    auto event = peek_event();
    if (event.is_error()) {
        return false;
    }

    dbgln("Is event: {}", (u8)m_current_event->type());

    return m_current_event->type() == type;
}

ErrorOr<void> Parser::produce_event()
{
    if (m_current_event) {
        return {};
    }

    dbgln("Producing event from state: {}", (u8)m_state);

    if (m_state != ProductionState::Invalid) {
        m_current_event = TRY(produce_event_from_state());
    }

    return {};
}

ErrorOr<RefPtr<Event>> Parser::produce_event_from_state()
{
    switch (m_state) {
    case ProductionState::ParseStreamStart:
        return produce_stream_start_event();
    case ProductionState::ParseImplicitDocumentStart:
        return produce_implicit_document_start_event();
    default:
        return Error::from_string_view("Invalid state"sv);
    }
}

}
