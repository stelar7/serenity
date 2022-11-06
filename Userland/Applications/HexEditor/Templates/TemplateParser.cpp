/*
 * Copyright (c) 2022, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "TemplateParser.h"
#include <AK/BitStream.h>
#include <AK/CharacterTypes.h>
#include <AK/MemoryStream.h>

enum ValidType {
    type_u8,
    type_u16,
    type_u32,
    type_u64,
    unknown
};

static ValidType string_to_valid_type(String input)
{
#define HANDLE_CASE(value)                        \
    if (input.equals_ignoring_case(#value##sv)) { \
        return ValidType::type_##value;           \
    }

    HANDLE_CASE(u8);
    HANDLE_CASE(u16);
    HANDLE_CASE(u32);
    HANDLE_CASE(u64);

    return ValidType::unknown;

#undef HANDLE_CASE
}

void TemplateParser::parse_to_classmap()
{
    while (!m_lexer.is_eof()) {
        auto type = m_lexer.consume_until(is_ascii_space);
        m_lexer.consume_while(is_ascii_space);

        if (type.equals_ignoring_case("struct"sv)) {
            auto struct_name = m_lexer.consume_until(is_ascii_space);
            dbgln("found struct '{}'", struct_name);
            m_lexer.consume_while(is_ascii_space);
            auto struct_values = parse_struct_definition();
            m_structs.set(struct_name, struct_values);
        }
    }
}

OrderedHashMap<String, String> TemplateParser::parse_struct_definition()
{
    OrderedHashMap<String, String> data;

    m_lexer.consume_specific("{"sv);
    do {
        m_lexer.consume_while(is_ascii_space);

        auto type = m_lexer.consume_until(is_ascii_space);
        m_lexer.consume_while(is_ascii_space);

        auto name = m_lexer.consume_until(is_any_of(";"sv));
        m_lexer.consume_specific(";"sv);
        m_lexer.consume_while(is_ascii_space);

        dbgln("found type '{}'", type);
        dbgln("found name '{}'", name);
        data.set(name, type);

    } while (!m_lexer.consume_specific("}"sv));

    return data;
}

ErrorOr<OrderedHashMap<String, OrderedHashMap<String, TemplateParser::Foo>>> TemplateParser::parse(Bytes bytes)
{
    OrderedHashMap<String, OrderedHashMap<String, TemplateParser::Foo>> data;
    auto temp_stream = InputMemoryStream(bytes);
    auto stream = InputBitStream(temp_stream);

    auto start_or_error = m_structs.get("main");
    if (!start_or_error.has_value()) {
        return Error::from_string_view("No main struct provided"sv);
    }

    auto start = start_or_error.value();
    auto parsed = TRY(parse_struct_from_bytes(stream, start));

    data.set("main", move(parsed));

    return data;
}

ErrorOr<OrderedHashMap<String, TemplateParser::Foo>> TemplateParser::parse_struct_from_bytes(InputBitStream& stream, OrderedHashMap<String, String> typemap)
{
    OrderedHashMap<String, NonnullOwnPtr<TemplateParser::Foo>> data;

    for (auto it = typemap.begin(); it != typemap.end(); ++it) {
        auto name = it->key;
        auto type = it->value;

        dbgln("parsing {} to {}", name, type);

        switch (string_to_valid_type(type)) {

#define READ_OR_FAIL(type, bits)                                \
    case ValidType::type_##type: {                              \
        auto parsed = stream.read_bits(bits);                   \
        if (stream.has_any_error()) {                           \
            return Error::from_string_view("Failed to read"sv); \
        }                                                       \
        dbgln("got {}", parsed);                                \
        auto value = make<TemplateParser::Foo>(parsed);         \
        data.set(name, move(value));                            \
        break;                                                  \
    }

            READ_OR_FAIL(u8, 8);
            READ_OR_FAIL(u16, 16);
            READ_OR_FAIL(u32, 32);
            READ_OR_FAIL(u64, 64);

#undef READ_OR_FAIL

        default: {
            auto start_or_error = m_structs.get(type);
            if (!start_or_error.has_value()) {
                dbgln("{} is not part of the template, but used as type", type);
                return Error::from_string_view("No definition for struct provided"sv);
            }

            auto to_parse = start_or_error.value();
            auto parsed = TRY(parse_struct_from_bytes(stream, to_parse));
            auto value = make<TemplateParser::Foo>(parsed);
            data.set(name, move(value));
            break;
        }
        }
    }

    return data;
}
