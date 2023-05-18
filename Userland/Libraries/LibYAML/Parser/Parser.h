/*
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/RefPtr.h>
#include <AK/String.h>
#include <AK/Vector.h>
#include <LibYAML/Parser/Tokenizer.h>

namespace YAML {

enum class ProductionState : u8 {
    Invalid,
    ParseStreamStart,
    ParseImplicitDocumentStart,
};

enum class EventType : u8 {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Alias,
    Scalar,
    SequenceStart,
    SequenceEnd,
    MappingStart,
    MappingEnd,
};

class Event : public RefCounted<Event> {
public:
    Event(EventType type, Mark start_mark, Mark end_mark)
        : m_type(type)
        , m_start_mark(start_mark)
        , m_end_mark(end_mark)
    {
    }

    EventType type() const { return m_type; }

private:
    EventType m_type;
    Mark m_start_mark;
    Mark m_end_mark;
};

class StreamStartEvent : public Event {
public:
    StreamStartEvent(Mark start_mark, Mark end_mark)
        : Event(EventType::StreamStart, start_mark, end_mark)
    {
    }
};

class Node {
};

class Parser {
public:
    Parser(String source)
        : m_tokenizer(source)
        , m_state(ProductionState::ParseStreamStart)
    {
    }

    ErrorOr<Vector<Node>> parse();

    ErrorOr<void> peek_event();
    bool is_event(EventType type);
    bool has_next();
    ErrorOr<RefPtr<Event>> next_event();
    ErrorOr<void> produce_event();

    ErrorOr<RefPtr<Event>> produce_event_from_state();
    ErrorOr<RefPtr<Event>> produce_stream_start_event();
    ErrorOr<RefPtr<Event>> produce_implicit_document_start_event();

private:
    Tokenizer m_tokenizer;
    ProductionState m_state;
    RefPtr<Event> m_current_event;
};
}
