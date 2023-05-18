/*
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/RefPtr.h>
#include <AK/String.h>
#include <AK/Vector.h>

namespace YAML {

class Mark {
public:
    Mark(u32 index, u32 line, u32 column)
        : m_index(index)
        , m_line(line)
        , m_column(column)
    {
    }

    u32 index() const { return m_index; }
    u32 line() const { return m_line; }
    u32 column() const { return m_column; }

private:
    u32 m_index { 0 };
    u32 m_line { 0 };
    u32 m_column { 0 };
};

enum class TokenType : u8 {
    Alias,
    Anchor,
    BlockEnd,
    BlockEntry,
    BlockMappingStart,
    BlockSequenceStart,
    Directive,
    DocumentEnd,
    DocumentStart,
    FlowEntry,
    FlowMappingEnd,
    FlowMappingStart,
    FlowSequenceEnd,
    FlowSequenceStart,
    Key,
    Scalar,
    StreamEnd,
    StreamStart,
    Tag,
    Comment,
    Value,
};

class Token : public RefCounted<Token> {
public:
    Token(Mark start_mark, Mark end_mark, TokenType type)
        : m_start_mark(start_mark)
        , m_end_mark(end_mark)
        , m_type(type)
    {
    }

    Mark start_mark() const { return m_start_mark; }
    Mark end_mark() const { return m_end_mark; }

    TokenType type() const { return m_type; }

private:
    Mark m_start_mark;
    Mark m_end_mark;

    TokenType m_type;
};

class StreamStartToken : public Token {
public:
    StreamStartToken(Mark start_mark, Mark end_mark)
        : Token(start_mark, end_mark, TokenType::StreamStart)
    {
    }
};

class Tokenizer {
public:
    Tokenizer(String source)
        : m_source(source)
    {
        add_start_token();
    }

    void add_start_token()
    {
        auto token_mark = create_mark();
        m_tokens.append(make_ref_counted<StreamStartToken>(token_mark, token_mark));
    }

    Mark create_mark() const
    {
        return Mark(m_index, m_line, m_column);
    }

    ErrorOr<RefPtr<Token>> next_token();
    ErrorOr<bool> is_token(Vector<TokenType> types);
    bool needs_more_tokens();
    ErrorOr<void> fetch_more_tokens();
    ErrorOr<void> scan_to_next_token();

private:
    String m_source;
    u32 m_index { 0 };
    u32 m_line { 0 };
    u32 m_column { 0 };

    u32 m_tokens_taken { 0 };

    bool is_done { false };

    Vector<RefPtr<Token>> m_tokens;
};
}
