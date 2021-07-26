/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Array.h>
#include <AK/GenericLexer.h>
#include <AK/SourceGenerator.h>
#include <AK/String.h>
#include <AK/StringUtils.h>
#include <AK/Types.h>
#include <AK/Vector.h>
#include <LibCore/ArgsParser.h>
#include <LibCore/File.h>
#include <ctype.h>

struct TimeZoneRule {
    String name;
    String from;
    String to;
    String in;
    String on;
    String at;
    String save;
    String letter;
};

struct TimeZoneLink {
    String from;
    String to;
};

struct TimeZoneZone {
    String name;
    String gmt_offset;
    String format;
    String rule;
    String until;
};

struct TimeZoneData {
    Vector<TimeZoneRule> rules;
    Vector<TimeZoneZone> zones;
    Vector<TimeZoneLink> links;
};

static void parse_rule(TimeZoneData& time_zone_data, String data)
{
    GenericLexer lexer(data);

    lexer.consume_specific("Rule");
    lexer.ignore_while(isspace);

    auto name = lexer.consume_until(isspace);
    lexer.ignore_while(isspace);

    auto from = lexer.consume_until(isspace);
    lexer.ignore_while(isspace);

    auto to = lexer.consume_until(isspace);
    lexer.ignore_while(isspace);
    if (to == "max") {
        to = "9999";
    }
    if (to == "only") {
        to = from;
    }

    lexer.consume_specific('-');
    lexer.ignore_while(isspace);

    auto in = lexer.consume_until(isspace);
    lexer.ignore_while(isspace);

    auto on = lexer.consume_until(isspace);
    lexer.ignore_while(isspace);

    auto at = lexer.consume_until(isspace);
    lexer.ignore_while(isspace);

    auto save = lexer.consume_until(isspace);
    lexer.ignore_while(isspace);

    auto letter = lexer.consume_until(isspace);

    time_zone_data.rules.append(TimeZoneRule { name, from, to, in, on, at, save, letter });
}

static void parse_link(TimeZoneData& time_zone_data, String data)
{
    GenericLexer lexer(data);

    lexer.consume_specific("Link");
    lexer.ignore_while(isspace);

    auto to = lexer.consume_until(isspace);
    lexer.ignore_while(isspace);

    auto from = lexer.consume_until(isspace);
    lexer.ignore_while(isspace);

    time_zone_data.links.append(TimeZoneLink { from, to });
}
static void parse_zone(TimeZoneData& time_zone_data, String data)
{
    TimeZoneZone link;
    GenericLexer lexer(data);

    lexer.consume_specific("Zone");
    lexer.ignore_while(isspace);

    auto name = lexer.consume_until(isspace);

    while (!lexer.is_eof()) {
        lexer.ignore_while(isspace);

        auto gmt_offset = lexer.consume_until(isspace);
        lexer.ignore_while(isspace);

        auto rules = lexer.consume_until(isspace);
        lexer.ignore_while(isspace);

        auto format = lexer.consume_until(isspace);
        lexer.ignore_while(isspace);

        auto until = lexer.consume_until([](char c) {
            return c == '\n' || c == '#';
        });

        if (lexer.peek() == '#') {
            lexer.ignore_until([](char c) {
                return c == '\n';
            });
        }

        time_zone_data.zones.append(TimeZoneZone { name, gmt_offset, rules, format, until });
    }
}

static void parse_time_zone_data(TimeZoneData& time_zone_data, String data)
{
    Vector<String> lines = data.split('\n', true);

    for (size_t i = 0; i < lines.size(); i++) {
        auto& line = lines.at(i);

        if (line.is_empty())
            continue;

        if (line.starts_with('#'))
            continue;

        if (line.starts_with("Rule")) {
            parse_rule(time_zone_data, line);
            continue;
        }

        if (line.starts_with("Link")) {
            parse_link(time_zone_data, line);
            continue;
        }

        if (line.starts_with("Zone")) {
            StringBuilder builder;

            while (true) {
                builder.appendff("{}\n", line);
                do {
                    if (i + 1 >= lines.size())
                        break;
                    line = lines.at(++i);
                } while (line.starts_with('#') || line.is_empty());

                if (line.starts_with("Zone") || line.starts_with("Link") || line.starts_with("Rule") || line.is_empty()) {
                    i--;
                    break;
                }
            }

            parse_zone(time_zone_data, builder.to_string());
            continue;
        }

        dbgln("{}", line);
        VERIFY_NOT_REACHED();
    }
}

static void generate_time_zone_header()
{
    StringBuilder builder;
    SourceGenerator generator { builder };

    generator.append(R"~~~(
#pragma once

#include <AK/Types.h>
#include <AK/Vector.h>

namespace Time {

struct TimeZone {
    String time_zone;
};

struct TimeZoneData {
    Vector<TimeZone> time_zones;
};

}
)~~~");

    outln("{}", generator.as_string_view());
}

static void generate_time_zone_implementation(TimeZoneData time_zone_data)
{
    StringBuilder builder;
    SourceGenerator generator { builder };

    generator.set("size", String::number(time_zone_data.rules.size()));

    generator.append(R"~~~(
#include <AK/Array.h>
#include <AK/Find.h>
#include <LibDateTime/TimeZone/TimeZoneData.h>

namespace Time {

}

)~~~");

    outln("{}", generator.as_string_view());
}

int main(int argc, char** argv)
{
    bool generate_header = false;
    bool generate_implementation = false;
    char const* timezone_data_path = nullptr;

    Core::ArgsParser args_parser;
    args_parser.add_option(generate_header, "Generate the TimeZone Data header file", "generate-header", 'h');
    args_parser.add_option(generate_implementation, "Generate the TimeZone Data implementation file", "generate-implementation", 'c');
    args_parser.add_option(timezone_data_path, "Path to tzdata2021a.tar.gz extract folder", "timezone-data-path", 'u', "timezone-data-path");
    args_parser.parse(argc, argv);

    if (!generate_header && !generate_implementation) {
        warnln("At least one of -h/--generate-header or -c/--generate-implementation is required");
        args_parser.print_usage(stderr, argv[0]);
        return 1;
    }

    if (!timezone_data_path) {
        warnln("-u/--timezone-data-path is required");
        args_parser.print_usage(stderr, argv[0]);
        return 1;
    }

    TimeZoneData time_zone_data;

    Vector<String> data_files { "africa", "antarctica", "asia", "australasia", "europe", "northamerica", "southamerica", "backward" };

    for (auto& file : data_files) {
        auto target = String::formatted("{}/{}", timezone_data_path, file);

        dbgln("parsing file {}", target);

        auto file_open_result = Core::File::open(target, Core::OpenMode::ReadOnly, 0666);

        if (file_open_result.is_error()) {
            warnln("Failed opening input file ({}) for reading: {}", target, file_open_result.error());
            return 1;
        }

        auto raw_content = file_open_result.value()->read_all();
        auto text_content = String(raw_content.bytes(), AK::NoChomp);

        parse_time_zone_data(time_zone_data, text_content);
    }

    /*
    if (generate_header)
        generate_time_zone_header();
    if (generate_implementation)
        generate_time_zone_implementation(time_zone_data);
        */

    return 0;
}
