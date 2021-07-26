/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "LocalTime.h"

namespace Time {

LocalTime LocalTime::plus_nanos(i64 to_add)
{
    if (to_add == 0)
        return *this;

    u64 current_time = to_nano_of_day();
    u64 new_time = ((to_add % NANOS_PER_DAY) + current_time + NANOS_PER_DAY) % NANOS_PER_DAY;

    if (current_time == new_time)
        return *this;

    u8 new_hour = new_time / NANOS_PER_HOUR;
    u8 new_minute = (new_time / NANOS_PER_MINUTE) % MINUTES_PER_HOUR;
    u8 new_second = (new_time / NANOS_PER_SECOND) % SECONDS_PER_MINUTE;
    u32 new_nano = new_time % NANOS_PER_SECOND;

    return { new_hour, new_minute, new_second, new_nano };
}

LocalTime LocalTime::plus_seconds(i64 to_add)
{
    if (to_add == 0)
        return *this;

    u64 current_time = hour * SECONDS_PER_HOUR + minute * SECONDS_PER_MINUTE + second;
    u64 new_time = ((to_add % SECONDS_PER_DAY) + current_time + SECONDS_PER_DAY) % SECONDS_PER_DAY;

    if (current_time == new_time)
        return *this;

    u8 new_hour = new_time / SECONDS_PER_HOUR;
    u8 new_minute = (new_time / SECONDS_PER_MINUTE) % MINUTES_PER_HOUR;
    u8 new_second = new_time % SECONDS_PER_MINUTE;

    return { new_hour, new_minute, new_second, nano };
}

LocalTime LocalTime::plus_minutes(i64 to_add)
{
    if (to_add == 0)
        return *this;

    u64 current_time = hour * MINUTES_PER_HOUR + minute;
    u64 new_time = ((to_add % MINUTES_PER_DAY) + current_time + MINUTES_PER_DAY) % MINUTES_PER_DAY;

    if (current_time == new_time)
        return *this;

    u8 new_hour = new_time / MINUTES_PER_HOUR;
    u8 new_minute = new_time % MINUTES_PER_HOUR;

    return { new_hour, new_minute, second, nano };
}

LocalTime LocalTime::plus_hours(i64 to_add)
{
    if (to_add == 0)
        return *this;

    u8 new_hour = ((to_add % HOURS_PER_DAY) + hour + HOURS_PER_DAY) % HOURS_PER_DAY;

    return { new_hour, minute, second, nano };
}

LocalTime LocalTime::minus_hours(i64 to_subtract)
{
    return plus_hours(-(to_subtract % HOURS_PER_DAY));
}

LocalTime LocalTime::minus_minutes(i64 to_subtract)
{
    return plus_minutes(-(to_subtract % MINUTES_PER_DAY));
}

LocalTime LocalTime::minus_seconds(i64 to_subtract)
{
    return plus_seconds(-(to_subtract % SECONDS_PER_DAY));
}

LocalTime LocalTime::minus_nanos(i64 to_subtract)
{
    return plus_nanos(-(to_subtract % NANOS_PER_DAY));
}

u64 LocalTime::to_nano_of_day()
{
    return hour * NANOS_PER_HOUR + minute * NANOS_PER_MINUTE + second * NANOS_PER_SECOND + nano;
}

u32 LocalTime::to_second_of_day()
{
    return hour * SECONDS_PER_HOUR + minute * SECONDS_PER_MINUTE + second;
}

u64 LocalTime::query(TimeField field)
{
    switch (field) {
    case TimeField::NANO_OF_SECOND:
        return nano;
    case TimeField::NANO_OF_DAY:
        return to_nano_of_day();
    case TimeField::MICRO_OF_SECOND:
        return nano / 1000;
    case TimeField::MICRO_OF_DAY:
        return to_nano_of_day() / 1'000;
    case TimeField::MILLI_OF_SECOND:
        return nano / 1'000'000;
    case TimeField::MILLI_OF_DAY:
        return to_nano_of_day() / 1'000'000;
    case TimeField::SECOND_OF_MINUTE:
        return second;
    case TimeField::SECOND_OF_DAY:
        return to_second_of_day();
    case TimeField::MINUTE_OF_HOUR:
        return minute;
    case TimeField::MINUTE_OF_DAY:
        return hour * 60 + minute;
    case TimeField::HOUR_OF_AMPM:
        return hour % 12;
    case TimeField::CLOCK_HOUR_OF_AMPM: {
        u8 hour_am = hour % 12;
        return (hour_am % 12 == 0 ? 12 : hour_am);
    }
    case TimeField::HOUR_OF_DAY:
        return hour;
    case TimeField::CLOCK_HOUR_OF_DAY:
        return (hour == 0 ? 24 : hour);
    case TimeField::AMPM_OF_DAY:
        return hour / 12;

    default:
        VERIFY_NOT_REACHED();
    }
}

}
