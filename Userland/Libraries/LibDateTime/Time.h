/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Types.h>
#include <sys/time.h>

namespace Time {

constexpr u8 HOURS_PER_DAY = 24;
constexpr u8 MINUTES_PER_HOUR = 60;
constexpr u16 MINUTES_PER_DAY = MINUTES_PER_HOUR * HOURS_PER_DAY;
constexpr u8 SECONDS_PER_MINUTE = 60;
constexpr u16 SECONDS_PER_HOUR = SECONDS_PER_MINUTE * MINUTES_PER_HOUR;
constexpr u32 SECONDS_PER_DAY = SECONDS_PER_HOUR * HOURS_PER_DAY;
constexpr u32 MILLIS_PER_DAY = SECONDS_PER_DAY * 1'000;
constexpr u64 MICROS_PER_DAY = SECONDS_PER_DAY * 1'000'000;
constexpr u32 NANOS_PER_SECOND = 1'000'000'000;
constexpr u64 NANOS_PER_MINUTE = NANOS_PER_SECOND * SECONDS_PER_MINUTE;
constexpr u64 NANOS_PER_HOUR = NANOS_PER_MINUTE * MINUTES_PER_HOUR;
constexpr u64 NANOS_PER_DAY = NANOS_PER_HOUR * HOURS_PER_DAY;

constexpr u8 LEAP_YEARS_FROM_1970_TO_2000 = 7;
constexpr u16 DAYS_PER_YEAR = 365;
constexpr u32 DAYS_PER_400_YEAR_CYCLE = 146'097;
constexpr u64 DAYS_TO_1970 = (DAYS_PER_400_YEAR_CYCLE * 5) - (DAYS_PER_YEAR * 30 + LEAP_YEARS_FROM_1970_TO_2000);

enum class TimeField {
    NANO_OF_SECOND,
    NANO_OF_DAY,
    MICRO_OF_SECOND,
    MICRO_OF_DAY,
    MILLI_OF_SECOND,
    MILLI_OF_DAY,
    SECOND_OF_MINUTE,
    SECOND_OF_DAY,
    MINUTE_OF_HOUR,
    MINUTE_OF_DAY,
    HOUR_OF_AMPM,
    CLOCK_HOUR_OF_AMPM,
    HOUR_OF_DAY,
    CLOCK_HOUR_OF_DAY,
    AMPM_OF_DAY,

    DAY_OF_WEEK,
    ALIGNED_DAY_OF_WEEK_IN_MONTH,
    ALIGNED_DAY_OF_WEEK_IN_YEAR,
    DAY_OF_MONTH,
    DAY_OF_YEAR,
    EPOCH_DAY,
    ALIGNED_WEEK_OF_MONTH,
    ALIGNED_WEEK_OF_YEAR,
    MONTH_OF_YEAR,
    PROLEPTIC_MONTH,
    YEAR_OF_ERA,
    YEAR,
    ERA,
};

enum class DayOfWeek : u8 {
    MONDAY = 1,
    TUESDAY,
    WEDNESDAY,
    THURSDAY,
    FRIDAY,
    SATURDAY,
    SUNDAY
};

enum class Month : u8 {
    JANUARY = 1,
    FEBRUARY,
    MARCH,
    APRIL,
    MAY,
    JUNE,
    JULY,
    AUGUST,
    SEPTEMBER,
    OCTOBER,
    NOVEMBER,
    DECEMBER
};

constexpr u16 first_day_of_year(Month month, bool leap_year)
{
    u8 leap = leap_year ? 1 : 0;
    switch (month) {
    case Month::JANUARY:
        return 1;
    case Month::FEBRUARY:
        return 32;
    case Month::MARCH:
        return 60 + leap;
    case Month::APRIL:
        return 91 + leap;
    case Month::MAY:
        return 121 + leap;
    case Month::JUNE:
        return 152 + leap;
    case Month::JULY:
        return 182 + leap;
    case Month::AUGUST:
        return 213 + leap;
    case Month::SEPTEMBER:
        return 244 + leap;
    case Month::OCTOBER:
        return 274 + leap;
    case Month::NOVEMBER:
        return 305 + leap;
    case Month::DECEMBER:
        return 335 + leap;
    default:
        VERIFY_NOT_REACHED();
    }
}

constexpr bool is_leap_year(i16 year)
{
    return ((year & 3) == 0) && ((year % 100) != 0 || (year % 400) == 0);
}

constexpr i64 floor_div(i64 x, i64 y)
{
    i64 result = x / y;
    if ((x ^ y) < 0 && result * y != x) {
        result--;
    }

    return result;
}

constexpr i64 floor_mod(i64 x, i64 y)
{
    return x - floor_div(x, y) * y;
}

}
