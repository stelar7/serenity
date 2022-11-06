/*
 * Copyright (c) 2022, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/GenericLexer.h>
#include <AK/HashMap.h>
#include <AK/OwnPtr.h>
#include <AK/String.h>

class TemplateParser {
public:
    struct Foo;
    using FooUnderlyingType = Variant<u64, OrderedHashMap<String, NonnullOwnPtr<Foo>>>; // look out for HM.get() and NNOP's weird interactions

    struct Foo : public FooUnderlyingType {
        using FooUnderlyingType::FooUnderlyingType;
    };

    TemplateParser(String format_template)
        : m_template(format_template)
        , m_lexer(format_template)
    {
        parse_to_classmap();
    }

    ErrorOr<OrderedHashMap<String, OrderedHashMap<String, Foo>>> parse(Bytes);

private:
    void parse_to_classmap();
    OrderedHashMap<String, String> parse_struct_definition();
    ErrorOr<OrderedHashMap<String, Foo>> parse_struct_from_bytes(InputBitStream&, OrderedHashMap<String, String>);

    String m_template;
    GenericLexer m_lexer;

    HashMap<String, OrderedHashMap<String, String>> m_structs;
};
