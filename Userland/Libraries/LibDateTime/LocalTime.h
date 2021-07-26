/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "Time.h"
#include <AK/Types.h>
#include <sys/time.h>

namespace Time {

class LocalTime {
public:
    LocalTime(u8 hour, u8 minute, u8 second, u32 nano)
        : hour(hour)
        , minute(minute)
        , second(second)
        , nano(nano)
    {
    }

    static LocalTime now()
    {
        timeval time_val;
        gettimeofday(&time_val, nullptr);

        LocalTime time { 0, 0, 0, 0 };
        return time.plus_seconds(time_val.tv_sec);
    }

    LocalTime plus_seconds(i64);
    LocalTime plus_minutes(i64);
    LocalTime plus_hours(i64);
    LocalTime plus_nanos(i64);
    LocalTime minus_seconds(i64);
    LocalTime minus_minutes(i64);
    LocalTime minus_hours(i64);
    LocalTime minus_nanos(i64);
    u64 to_nano_of_day();
    u32 to_second_of_day();
    u64 query(TimeField);

    constexpr bool operator==(const LocalTime& other) const
    {
        return hour == other.hour && minute == other.minute && second == other.second && nano == other.nano;
    }

    constexpr bool operator>(const LocalTime& other) const
    {
        if (hour > other.hour)
            return true;

        if (hour < other.hour)
            return false;

        if (minute > other.minute)
            return true;

        if (minute < other.minute)
            return false;

        if (second > other.second)
            return true;

        if (second < other.second)
            return false;

        if (nano > other.nano)
            return true;

        if (nano < other.nano)
            return false;

        return false;
    }

    constexpr bool operator<(const LocalTime& other) const
    {
        return !(*this > other) && !(*this == other);
    }

private:
    u8 hour {};
    u8 minute {};
    u8 second {};
    u32 nano {};
};

}
