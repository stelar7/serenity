/*
 * Copyright (c) 2022-2023, Sam Atkins <atkinssj@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/String.h>
#include <LibWeb/Forward.h>

namespace Web::CSS {

class Resolution {
public:
    enum class Type {
        Dpi,
        Dpcm,
        Dppx,
    };

    static Optional<Type> unit_from_name(StringView);

    Resolution(int value, Type type);
    Resolution(float value, Type type);

    ErrorOr<String> to_string() const;
    float to_dots_per_pixel() const;

    bool operator==(Resolution const& other) const
    {
        return m_type == other.m_type && m_value == other.m_value;
    }

    int operator<=>(Resolution const& other) const
    {
        auto this_dots_per_pixel = to_dots_per_pixel();
        auto other_dots_per_pixel = other.to_dots_per_pixel();

        if (this_dots_per_pixel < other_dots_per_pixel)
            return -1;
        if (this_dots_per_pixel > other_dots_per_pixel)
            return 1;
        return 0;
    }

    StringView unit_name() const;

private:
    Type m_type;
    float m_value { 0 };
};
}
