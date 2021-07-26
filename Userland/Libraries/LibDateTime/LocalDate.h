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

class LocalDate {
public:
    constexpr LocalDate(i16 year, u8 month, u8 day)
        : year(year)
        , month(month)
        , day(day)
    {
    }

    static LocalDate now()
    {
        timeval time_val;
        gettimeofday(&time_val, nullptr);

        u64 days_since_epoch = time_val.tv_sec / SECONDS_PER_DAY;

        return LocalDate::from_epoch_days(days_since_epoch);
    }

    constexpr bool operator==(const LocalDate& other) const
    {
        return year == other.year && month == other.month && day == other.day;
    }

    constexpr bool operator>(const LocalDate& other) const
    {
        if (year > other.year)
            return true;

        if (year < other.year)
            return false;

        if (month > other.month)
            return true;

        if (month < other.month)
            return false;

        if (day > other.day)
            return true;

        if (day < other.day)
            return false;

        return false;
    }

    constexpr bool operator<(const LocalDate& other) const
    {
        return !(*this > other) && !(*this == other);
    }

    static constexpr LocalDate from_epoch_days(i64);
    LocalDate plus_days(i64);
    LocalDate plus_weeks(i64);
    LocalDate plus_months(i64);
    LocalDate plus_years(i64);
    LocalDate minus_days(i64);
    LocalDate minus_weeks(i64);
    LocalDate minus_months(i64);
    LocalDate minus_years(i64);

    u16 get_day_of_year();
    u8 get_days_in_month();
    u16 get_days_in_year();
    u64 to_epoch_day();
    u64 query(TimeField);

private:
    i16 year {};
    u8 month {};
    u8 day {};
};

}
