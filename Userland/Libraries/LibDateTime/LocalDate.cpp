/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "LocalDate.h"
#include <AK/Math.h>

namespace Time {

static LocalDate resolve_changed_date(i16 new_year, u8 new_month, u8 new_day)
{
    if (new_month == 2) {
        new_day = min(new_day, is_leap_year(new_year) ? 29 : 28);
    }

    if (new_month == 4 || new_month == 6 || new_month == 9 || new_month == 11) {
        new_day = min(new_day, 30);
    }

    return { new_year, new_month, new_day };
}

constexpr LocalDate LocalDate::from_epoch_days(i64 days)
{
    i64 days_since_0 = days + DAYS_TO_1970;

    // Offset so the next leap year is at the end of the 400 year cycle
    days_since_0 -= 60;

    // Support negative years
    u64 adjust = 0;
    if (days_since_0 < 0) {
        u64 adjusted_cycle_count = (days_since_0 + 1) / DAYS_PER_400_YEAR_CYCLE - 1;
        adjust = adjusted_cycle_count * 400;
        days_since_0 += -adjusted_cycle_count * DAYS_PER_400_YEAR_CYCLE;
    }

    u64 year_estimate = (400 * days_since_0 + 591) / DAYS_PER_400_YEAR_CYCLE;
    i64 day_estimate = days_since_0 - (DAYS_PER_YEAR * year_estimate + year_estimate / 4 - year_estimate / 100 + year_estimate / 400);
    if (day_estimate < 0) {
        year_estimate--;
        day_estimate = days_since_0 - (DAYS_PER_YEAR * year_estimate + year_estimate / 4 - year_estimate / 100 + year_estimate / 400);
    }
    year_estimate += adjust;

    // Convert the cycle back from the initial offset
    u32 march_month_year_0 = (day_estimate * 5 + 2) / 153;
    u8 month = (march_month_year_0 + 2) % 12 + 1;
    u8 day = day_estimate - (march_month_year_0 * 306 + 5) / 10 + 1;
    i16 year = year_estimate + march_month_year_0 / 10;

    return LocalDate { year, month, day };
}

u64 LocalDate::query(TimeField field)
{
    switch (field) {
    case TimeField::DAY_OF_WEEK:
        return floor_mod(to_epoch_day() + 3, 7);
    case TimeField::ALIGNED_DAY_OF_WEEK_IN_MONTH:
        return ((day - 1) % 7) + 1;
    case TimeField::ALIGNED_DAY_OF_WEEK_IN_YEAR:
        return ((get_day_of_year() - 1) % 7) + 1;
    case TimeField::DAY_OF_MONTH:
        return day;
    case TimeField::DAY_OF_YEAR:
        return get_day_of_year();
    case TimeField::EPOCH_DAY:
        return to_epoch_day();
    case TimeField::ALIGNED_WEEK_OF_MONTH:
        return ((day - 1) / 7) + 1;
    case TimeField::ALIGNED_WEEK_OF_YEAR:
        return ((get_day_of_year() - 1) / 7) + 1;
    case TimeField::MONTH_OF_YEAR:
        return month;
    case TimeField::PROLEPTIC_MONTH:
        return year * 12 + month - 1;
    case TimeField::YEAR_OF_ERA:
        return year >= 1 ? year : 1 - year;
    case TimeField::YEAR:
        return year;
    case TimeField::ERA:
        return year >= 1 ? 1 : 0;

    default:
        VERIFY_NOT_REACHED();
    }
}

u64 LocalDate::to_epoch_day()
{
    u64 total = 365 * year;
    if (year >= 0) {
        total += (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400;
    } else {
        total -= year / -4 - year / -100 + year / -400;
    }
    total += ((367 * month - 362) / 12);
    total += day - 1;
    if (month > 2) {
        total--;
        if (!is_leap_year(year)) {
            total--;
        }
    }

    return total - DAYS_TO_1970;
}

u16 LocalDate::get_day_of_year()
{
    return first_day_of_year(static_cast<Month>(month), is_leap_year(year)) + day - 1;
}

u8 LocalDate::get_days_in_month()
{
    switch (static_cast<Month>(month)) {
    case Month::FEBRUARY:
        return is_leap_year(year) ? 29 : 28;
    case Month::APRIL:
    case Month::JUNE:
    case Month::SEPTEMBER:
    case Month::NOVEMBER:
        return 30;
    default:
        return 31;
    }
}

u16 LocalDate::get_days_in_year()
{
    return is_leap_year(year) ? DAYS_PER_YEAR + 1 : DAYS_PER_YEAR;
}

LocalDate LocalDate::plus_days(i64 to_add)
{
    if (to_add == 0)
        return *this;

    i64 epoch_days = to_epoch_day() + to_add;
    return from_epoch_days(epoch_days);
}

LocalDate LocalDate::plus_weeks(i64 to_add)
{
    return plus_days(to_add * 7);
}

LocalDate LocalDate::plus_months(i64 to_add)
{
    if (to_add == 0)
        return *this;

    i64 current_months = year * 12 + (month - 1);
    i64 new_months = current_months + to_add;

    i16 new_year = floor_div(new_months, 12);
    u8 new_month = floor_mod(new_months, 12) + 1;

    return resolve_changed_date(new_year, new_month, day);
}

LocalDate LocalDate::plus_years(i64 to_add)
{
    if (to_add == 0)
        return *this;

    i16 new_year = year + to_add;

    return resolve_changed_date(new_year, month, day);
}

LocalDate LocalDate::minus_days(i64 to_subtract)
{
    return plus_days(-to_subtract);
}

LocalDate LocalDate::minus_weeks(i64 to_subtract)
{
    return plus_weeks(-to_subtract);
}

LocalDate LocalDate::minus_months(i64 to_subtract)
{
    return plus_months(-to_subtract);
}

LocalDate LocalDate::minus_years(i64 to_subtract)
{
    return plus_years(-to_subtract);
}

}
