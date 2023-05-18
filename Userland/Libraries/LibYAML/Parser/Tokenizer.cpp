/*
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibYAML/Parser/Tokenizer.h>

namespace YAML {

ErrorOr<RefPtr<Token>> Tokenizer::next_token()
{
    m_tokens_taken++;
    if (m_tokens.is_empty()) {
        return Error::from_string_view("No more tokens"sv);
    }

    auto token = m_tokens.take_first();
    return token;
}

ErrorOr<bool> Tokenizer::is_token(Vector<TokenType> types)
{
    while (needs_more_tokens()) {
        TRY(fetch_more_tokens());
    }

    if (m_tokens.is_empty()) {
        return false;
    }

    if (types.size() == 0) {
        return false;
    }

    auto token = m_tokens.first();
    for (auto type : types) {
        if (token->type() == type) {
            return true;
        }
    }

    return false;
}

bool Tokenizer::needs_more_tokens()
{
    if (is_done) {
        return false;
    }

    if (m_tokens.is_empty()) {
        return true;
    }

    return false;
}

ErrorOr<void> Tokenizer::fetch_more_tokens()
{
    TRY(scan_to_next_token());

    return {};
}

ErrorOr<void> Tokenizer::scan_to_next_token()
{
    bool found = false;

    while (!found) {
        // TODO
        return {};
    }

    return {};
}

}
