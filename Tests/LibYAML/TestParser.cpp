/*
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibTest/TestCase.h>
#include <LibYAML/Parser/Parser.h>

TEST_CASE(parses_ok)
{
    auto text = MUST(String::from_utf8("a: 1"sv));
    YAML::Parser parser(text);
    auto result = parser.parse();
    if (result.is_error()) {
        FAIL(result.error());
    }
}
