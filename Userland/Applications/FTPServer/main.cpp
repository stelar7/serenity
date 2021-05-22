/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "FTPServer.h"
#include "FTPServerTransferModel.h"
#include <AK/JsonParser.h>
#include <AK/String.h>
#include <LibCore/ArgsParser.h>
#include <LibCore/EventLoop.h>
#include <LibCore/File.h>
#include <LibCore/StandardPaths.h>
#include <LibCore/System.h>
#include <LibGUI/Application.h>
#include <LibGUI/BoxLayout.h>
#include <LibGUI/Splitter.h>
#include <LibGUI/TableView.h>
#include <LibGUI/TextEditor.h>
#include <LibGUI/Widget.h>
#include <LibGUI/Window.h>
#include <stdio.h>
#include <unistd.h>

ErrorOr<int> serenity_main(Main::Arguments arguments)
{
    String config_path = "/home/anon/.config/FTPServerConfig.json";
    bool nogui = false;
    int port = 21;

    if (geteuid() != 0) {
        port = 2121;
        config_path = String::formatted("{}/{}", Core::StandardPaths::config_directory(), "FTPServerConfig.json");
    }

    Core::ArgsParser args_parser;
    args_parser.add_option(port, "Sets the port to use", "port", 'p', "port");
    args_parser.add_option(nogui, "Runs in terminal-only mode", "nogui", 'n');
    args_parser.add_option(config_path, "The file used to load server configurations", "config_path", 'c', "config_path");
    args_parser.parse(arguments);

    if (!Core::File::exists(config_path)) {
        outln("FTPServer: Unable to find config file, creating new: {}", config_path);
        auto file = TRY(Core::Stream::File::open(config_path, Core::Stream::OpenMode::Write));
        AK::JsonObject default_content;
        default_content.set("allow_anonymous_logins", false);
        default_content.set("default_home_directory", "/");

        AK::JsonObject user_list;
        AK::JsonObject anon_user;
        anon_user.set("home_directory", "/home/anon");
        user_list.set("anon", anon_user);
        default_content.set("users", user_list);

        MUST(file->write(default_content.to_string().bytes()));
    }

    outln("FTPServer: Loading config file from: {}", config_path);

    auto file = TRY(Core::Stream::File::open(config_path, Core::Stream::OpenMode::ReadWrite));

    auto read_buffer = TRY(ByteBuffer::create_uninitialized(4 * KiB));

    auto trimmed_buffer = TRY(file->read(read_buffer));
    auto file_contents = String(trimmed_buffer, AK::NoChomp);
    auto json = TRY(JsonValue::from_string(file_contents));

    TRY(Core::System::pledge("stdio inet accept unix thread rpath sendfd recvfd"sv));

    Core::EventLoop event_loop;
    FTPServer server(port, move(json.as_object()));

    if (!nogui) {
        auto app = GUI::Application::construct(arguments);

        auto window = GUI::Window::construct();
        window->set_title("FTP Server"sv);
        window->resize(450, 600);
        window->center_on_screen();

        auto app_icon = GUI::Icon::default_icon("app-ftp-server"sv);
        window->set_icon(app_icon.bitmap_for_size(16));

        auto& widget = window->set_main_widget<GUI::Widget>();
        widget.set_fill_with_background_color(true);
        widget.set_layout<GUI::VerticalBoxLayout>();

        auto& splitter = widget.add<GUI::VerticalSplitter>();
        server.m_log_view = splitter.add<GUI::TextEditor>(GUI::TextEditor::Type::MultiLine);
        server.m_log_view->set_mode(GUI::TextEditor::Mode::ReadOnly);

        server.m_transfer_table = splitter.add<GUI::TableView>();
        server.m_transfer_table->set_column_headers_visible(true);
        server.m_transfer_table->set_model(FTPServerTransferModel::create(server));
        server.m_transfer_table->model()->invalidate();

        server.start();
        window->show();

        return GUI::Application::the()->exec();
    }

    server.start();

    return event_loop.exec();
}
