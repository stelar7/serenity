/*
 * Copyright (c) 2023, stelar7 <dudedbz@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "GeneratorUtil.h"
#include <AK/DeprecatedString.h>
#include <AK/SourceGenerator.h>
#include <AK/String.h>
#include <AK/StringBuilder.h>
#include <LibCore/ArgsParser.h>
#include <LibMain/Main.h>

ErrorOr<void> generate_implementation_file(JsonArray& enums_data, Core::File& file);

ErrorOr<int> serenity_main(Main::Arguments arguments)
{
    StringView generated_implementation_path;
    StringView identifiers_json_path;

    Core::ArgsParser args_parser;
    args_parser.add_option(generated_implementation_path, "Path to the implementation file to generate", "generated-implementation-path", 'c', "generated-implementation-path");
    args_parser.add_option(identifiers_json_path, "Path to the JSON file to read from", "json-path", 'j', "json-path");
    args_parser.parse(arguments);

    auto json = TRY(read_entire_file_as_json(identifiers_json_path));
    VERIFY(json.is_array());

    auto method_data = json.as_array();

    auto generated_implementation_file = TRY(Core::File::open(generated_implementation_path, Core::File::OpenMode::Write));
    TRY(generate_implementation_file(method_data, *generated_implementation_file));

    return 0;
}

ErrorOr<void> generate_implementation_file(JsonArray& method_data, Core::File& file)
{
    StringBuilder builder;
    SourceGenerator generator { builder };

    generator.append(R"~~~(
#include <AK/Debug.h>
#include <LibWeb/CSS/Parser/Parser.h>
#include <LibWeb/CSS/Parser/TokenStream.h>
#include <LibWeb/CSS/StyleValues/CalculatedStyleValue.h>

namespace Web::CSS::Parser {
)~~~");

    for (auto& value : method_data.values()) {
        VERIFY(value.is_object());
        auto& method = value.as_object();

        auto method_generator = generator.fork();
        auto parameters = method.get("parameters"sv).value().as_array();
        auto can_have_infinite_parameters = parameters.size() == 1 && parameters[0].as_string() == "∞";

        auto has_optional_parameters = false;
        for (auto& parameter : parameters.values()) {
            if (parameter.is_string() && parameter.as_string().contains("?"sv)) {
                has_optional_parameters = true;
                break;
            }
        }

        auto method_name = method.get("name"sv).value().as_string();
        method_generator.set("method_name"sv, method_name);
        method_generator.set("method_name:title_case"sv, title_casify(method_name));
        method_generator.set("expected_parameter_count"sv, TRY(String::number(parameters.size())).to_deprecated_string());
        method_generator.append(R"~~~(
ErrorOr<OwnPtr<CalculationNode>> Parser::parse_@method_name@_function(Function const& function)
{
    TokenStream stream { function.values() };
    auto parameters = parse_a_comma_separated_list_of_component_values(stream);
)~~~");

        if (!can_have_infinite_parameters && !has_optional_parameters) {
            method_generator.append(R"~~~(
    if (parameters.size() != @expected_parameter_count@) {
        dbgln_if(CSS_PARSER_DEBUG, "@method_name@() must have exactly @expected_parameter_count@ parameter(s)"sv);
        return nullptr;
    }
)~~~");
        }

        if (!can_have_infinite_parameters && parameters.size() == 1) {
            method_generator.append(R"~~~(
    auto calculation_node = TRY(parse_a_calculation(parameter));

    if (!calculation_node) {
        dbgln_if(CSS_PARSER_DEBUG, "@method_name@() parameter must be a valid calculation"sv);
        return nullptr;
    }

    return TRY(@method_name:title_case@CalculationNode::create(calculation_node.release_nonnull()));
}
            )~~~");
            continue;
        } else {
            method_generator.append(R"~~~(
    Vector<NonnullOwnPtr<CalculationNode>> calculated_parameters;
    calculated_parameters.ensure_capacity(parameters.size());

    CalculatedStyleValue::ResolvedType type;
    bool first = true;
    for (auto& parameter : parameters) {
        auto calculation_node = TRY(parse_a_calculation(parameter));

        if (!calculation_node) {
            dbgln_if(CSS_PARSER_DEBUG, "@method_name@() parameters must be valid calculations"sv);
            return nullptr;
        }

        auto parameter_type = calculation_node->resolved_type();
        if (!parameter_type.has_value()) {
            dbgln_if(CSS_PARSER_DEBUG, "Failed to resolve type for @method_name@() parameter #{}"sv, calculated_parameters.size() + 1);
            return nullptr;
        }

        if (first) {
            type = parameter_type.value();
            first = false;
        }

        if (parameter_type != type) {
            dbgln_if(CSS_PARSER_DEBUG, "@method_name@() parameters must all be of same type"sv);
            return nullptr;
        }

        calculated_parameters.append(calculation_node.release_nonnull());
    }
        )~~~");
        }

        if (can_have_infinite_parameters) {
            method_generator.append(R"~~~(
            return TRY(@method_name:title_case@CalculationNode::create(move(calculated_parameters)));
            )~~~");
            method_generator.appendln("}");
            continue;
        } else {
            method_generator.append(R"~~~(
            return TRY(@method_name:title_case@CalculationNode::create(
            )~~~");

            for (size_t i = 0; i < parameters.size(); ++i) {
                method_generator.set("i"sv, TRY(String::number(i)).to_deprecated_string());
                method_generator.append(R"~~~(
                move(calculated_parameters[@i@])
                )~~~");
                if (i != parameters.size() - 1) {
                    method_generator.append(", "sv);
                }
            }

            method_generator.append(R"~~~(
            ));
            )~~~");
        }
        method_generator.appendln("}");
    }

    generator.append(R"~~~(})~~~");
    TRY(file.write_until_depleted(generator.as_string_view().bytes()));
    return {};
}
