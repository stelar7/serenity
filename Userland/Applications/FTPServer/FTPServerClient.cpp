/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "FTPServerClient.h"
#include <LibCore/Account.h>
#include <LibCore/DirIterator.h>
#include <LibCore/File.h>
#include <LibCore/FileStream.h>
#include <LibCore/MappedFile.h>
#include <LibCore/SecretString.h>
#include <LibCore/Stream.h>
#include <LibCore/System.h>
#include <LibCrypto/Checksum/CRC32.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <utime.h>

#undef FTP_DEBUG
#define FTP_DEBUG 1

FTPServerClient::FTPServerClient(u32 id, IPv4Address source_address, NonnullOwnPtr<Core::Stream::TCPSocket> socket, AK::JsonObject json_settings)
    : m_id(id)
    , m_source_address(source_address)
    , m_control_connection(move(socket))
    , m_json_settings(json_settings)
{
}

ErrorOr<void> FTPServerClient::initialize()
{
    TRY(send_welcome());
    TRY(drain_socket());

    return {};
}

ErrorOr<void> FTPServerClient::drain_socket()
{
    auto transfer_buffer = TRY(ByteBuffer::create_uninitialized(TRANSFER_BUFFER_DEFAULT_SIZE));

    TRY(m_control_connection->can_read_without_blocking(100));

    while (!m_should_die && m_control_connection && m_control_connection->is_readable()) {
        if (!m_control_connection->is_open()) {
            return quit();
        }

        auto trimmed_buffer = m_control_connection->read(transfer_buffer);
        if (trimmed_buffer.is_error()) {
            dbgln_if(FTP_DEBUG, "Unable to read from control connection");
            dbgln_if(FTP_DEBUG, trimmed_buffer.error().string_literal());
            return send_request_aborted_local_error();
        }

        auto buffer_data = trimmed_buffer.value();
        if (buffer_data.is_empty()) {
            dbgln_if(FTP_DEBUG, "Got 0 bytes, treating as EOF");
            return quit();
        }

        // remove \r\n

        auto command = String(buffer_data, AK::NoChomp);
        dbgln_if(FTP_DEBUG, "Received parsed: {}", command);

        if (on_receive_command)
            on_receive_command(this, command);

        (void)handle_command(command);
    }

    dbgln_if(FTP_DEBUG, "OUTSIDE WHILE");

    return quit();
}

ErrorOr<void> FTPServerClient::handle_command(String input)
{
    Vector<String> parts = input.split(' ');
    String command = parts.take_first();

    if (command.equals_ignoring_case("AUTH"sv)) {
        return handle_auth_command(parts);
    }

    if (command.equals_ignoring_case("FEAT"sv)) {
        return handle_feat_command();
    }

    if (command.equals_ignoring_case("PWD"sv) || command.equals_ignoring_case("XPWD"sv)) {
        return handle_pwd_command();
    }

    if (command.equals_ignoring_case("SYST"sv)) {
        return handle_syst_command();
    }

    if (command.equals_ignoring_case("RETR"sv)) {
        return handle_retr_command(parts);
    }

    if (command.equals_ignoring_case("STOR"sv)) {
        return handle_stor_command(parts);
    }

    if (command.equals_ignoring_case("STOU"sv)) {
        return handle_stou_command(parts);
    }

    if (command.equals_ignoring_case("MKD"sv) || command.equals_ignoring_case("XMKD"sv)) {
        return handle_mkd_command(parts);
    }

    if (command.equals_ignoring_case("RMD"sv) || command.equals_ignoring_case("XRMD"sv)) {
        return handle_rmd_command(parts);
    }

    if (command.equals_ignoring_case("DELE"sv)) {
        return handle_dele_command(parts);
    }

    if (command.equals_ignoring_case("CWD"sv) || command.equals_ignoring_case("XCWD"sv)) {
        return handle_cwd_command(parts);
    }

    if (command.equals_ignoring_case("CDUP"sv) || command.equals_ignoring_case("XCUP"sv)) {
        return handle_cdup_command();
    }

    if (command.equals_ignoring_case("LIST"sv)) {
        return handle_list_command(parts);
    }

    if (command.equals_ignoring_case("NLST"sv)) {
        return handle_nlst_command(parts);
    }

    if (command.equals_ignoring_case("TYPE"sv)) {
        return handle_type_command(parts);
    }

    if (command.equals_ignoring_case("STRU"sv)) {
        return handle_stru_command(parts);
    }

    if (command.equals_ignoring_case("PASV"sv)) {
        return handle_pasv_command();
    }

    if (command.equals_ignoring_case("USER"sv)) {
        return handle_user_command(parts);
    }

    if (command.equals_ignoring_case("PASS"sv)) {
        return handle_pass_command(parts);
    }

    if (command.equals_ignoring_case("QUIT"sv)) {
        return handle_quit_command();
    }

    if (command.equals_ignoring_case("APPE"sv)) {
        return handle_appe_command(parts);
    }

    if (command.equals_ignoring_case("RNFR"sv)) {
        return handle_rnfr_command(parts);
    }

    if (command.equals_ignoring_case("RNTO"sv)) {
        return handle_rnto_command(parts);
    }

    if (command.equals_ignoring_case("NOOP"sv)) {
        return handle_noop_command();
    }

    if (command.equals_ignoring_case("REIN"sv)) {
        return handle_rein_command();
    }

    if (command.equals_ignoring_case("MDTM"sv)) {
        return handle_mdtm_command(parts);
    }

    if (command.equals_ignoring_case("SIZE"sv)) {
        return handle_size_command(parts);
    }

    if (command.equals_ignoring_case("MODE"sv)) {
        return handle_mode_command(parts);
    }

    if (command.equals_ignoring_case("XCRC"sv)) {
        return handle_xcrc_command(parts);
    }

    if (command.equals_ignoring_case("MLST"sv)) {
        return handle_mlst_command(parts);
    }

    if (command.equals_ignoring_case("MLSD"sv)) {
        return handle_mlsd_command(parts);
    }

    if (command.equals_ignoring_case("SITE"sv)) {
        return handle_site_command();
    }

    if (command.equals_ignoring_case("MFCT"sv)) {
        return handle_mfct_command();
    }

    dbgln_if(FTP_DEBUG, "Unhandled command: {}", command);

    if (on_info)
        on_info(this, String::formatted("Tried invalid command {} {}\n", command, String::join(" "sv, parts)));

    return send_command_not_implemented();
}

ErrorOr<void> FTPServerClient::handle_size_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_command_not_implemented_for_parameter();
    }

    auto filename = params.at(0);
    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(filename);
    auto path = LexicalPath::canonicalized_path(builder.to_string());

    if (!Core::File::exists(path)) {
        return send_file_unavailable();
    }

    struct stat stat;
    int rc = lstat(builder.to_string().characters(), &stat);
    if (rc < 0) {
        perror("lstat");
        memset(&stat, 0, sizeof(stat));
        return send_request_aborted_local_error();
    }

    return send_file_status(String::formatted("{}", stat.st_size));
}

ErrorOr<void> FTPServerClient::handle_mdtm_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_command_not_implemented_for_parameter();
    }

    auto filename = params.at(0);
    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(filename);
    auto path = LexicalPath::canonicalized_path(builder.to_string());

    if (!Core::File::exists(path)) {
        return send_file_unavailable();
    }

    struct stat stat;
    int rc = lstat(builder.to_string().characters(), &stat);
    if (rc < 0) {
        perror("lstat");
        memset(&stat, 0, sizeof(stat));
        return send_request_aborted_local_error();
    }

    return send_file_status(Core::DateTime::from_timestamp(stat.st_mtime).to_string("%Y%m%d%H%M%S"sv));
}

ErrorOr<void> FTPServerClient::handle_rein_command()
{
    m_account = {};
    m_username = {};
    m_is_logged_in = false;
    m_working_dir = { "/" };
    m_transfer_type = { "I" };
    m_transfer_mode = { "S" };
    m_file_structure = { "F" };
    m_rename_from = {};
    m_is_passive = {};

    return send_ok();
}

ErrorOr<void> FTPServerClient::handle_noop_command()
{
    return send_ok();
}

ErrorOr<void> FTPServerClient::handle_rnfr_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_command_not_implemented_for_parameter();
    }

    auto old_name = params.at(0);
    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(old_name);
    auto from_path = LexicalPath::canonicalized_path(builder.to_string());

    if (!Core::File::exists(from_path)) {
        return send_file_action_not_taken();
    }

    m_rename_from = from_path;
    return send_file_action_needs_additional_command();
}

ErrorOr<void> FTPServerClient::handle_rnto_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_command_not_implemented_for_parameter();
    }

    if (m_rename_from.is_empty()) {
        return send_bad_sequence_of_commands();
    }

    auto new_name = params.at(0);

    if (!Core::File::exists(m_rename_from)) {
        return send_file_action_not_taken();
    }

    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(new_name);
    auto to_path = LexicalPath::canonicalized_path(builder.to_string());

    if (Core::File::exists(to_path)) {
        return send_file_action_not_taken();
    }

    auto rc = rename(m_rename_from.characters(), to_path.characters());
    if (rc < 0) {
        if (errno == EXDEV) {
            auto result = Core::File::copy_file_or_directory(
                m_rename_from, to_path,
                Core::File::RecursionMode::Allowed,
                Core::File::LinkMode::Disallowed,
                Core::File::AddDuplicateFileMarker::No);

            if (result.is_error()) {
                return send_request_aborted_local_error();
            }
            rc = unlink(m_rename_from.characters());
            if (rc < 0) {
                return send_request_aborted_local_error();
            }
        } else {
            return send_request_aborted_local_error();
        }
    }

    m_rename_from = {};
    return send_file_action_ok();
}

ErrorOr<void> FTPServerClient::handle_auth_command(Vector<String> params)
{
    if (params.size() < 1) {
        return send_command_not_implemented_for_parameter();
    }

    String type = params.at(0);
    if (type.equals_ignoring_case("TLS"sv)) {
        TLS::Options options;
        TRY(TLS::TLSv12::connect(m_source_address.to_string(), *m_control_connection, move(options)));
    }

    if (type.equals_ignoring_case("SSL"sv)) {
        // FIXME: Add server-side SSL to LibTLS
        return send_command_not_implemented_for_parameter();
    }

    return send_command_not_implemented();
}

ErrorOr<void> FTPServerClient::handle_stou_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    String file = String::join(" "sv, params);

    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(file);
    auto path = LexicalPath::canonicalized_path(builder.to_string());

    while (Core::File::exists(path)) {
        builder.append(".1"sv);
        path = LexicalPath::canonicalized_path(builder.to_string());
    }

    auto connection = TRY(create_data_socket());
    TRY(connection->set_blocking(true));

    TRY(send(String::formatted("150 FILE:{}\r\n", path)));
    auto outstream = TRY(Core::Stream::File::open(path.substring_view(0), Core::Stream::OpenMode::Write));

    TRY(send_initiating_transfer(builder.to_string()));

    auto transfer_buffer = TRY(ByteBuffer::create_uninitialized(TRANSFER_BUFFER_DEFAULT_SIZE));

    while (true) {
        auto trimmed_buffer = TRY(connection->read(transfer_buffer));

        if (trimmed_buffer.is_empty()) {
            break;
        }

        TRY(outstream->write(trimmed_buffer));

        if (on_data_transfer_update)
            on_data_transfer_update(m_id, trimmed_buffer.size());
    }

    connection->close();
    return send_transfer_success();
}

ErrorOr<void> FTPServerClient::handle_appe_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_command_not_implemented_for_parameter();
    }

    String file = String::join(" "sv, params);

    auto connection = TRY(create_data_socket());
    TRY(connection->set_blocking(true));

    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(file);
    auto path = LexicalPath::canonicalized_path(builder.to_string());
    auto outstream = TRY(Core::Stream::File::open(path, Core::Stream::OpenMode::Write));

    auto transfer_buffer = TRY(ByteBuffer::create_uninitialized(TRANSFER_BUFFER_DEFAULT_SIZE));

    TRY(send_initiating_transfer(builder.to_string()));

    while (true) {
        auto trimmed_buffer = TRY(connection->read(transfer_buffer));

        if (trimmed_buffer.is_empty()) {
            break;
        }

        TRY(outstream->write(trimmed_buffer));

        if (on_data_transfer_update)
            on_data_transfer_update(m_id, trimmed_buffer.size());
    }

    connection->close();
    return send_transfer_success();
}

ErrorOr<void> FTPServerClient::handle_feat_command()
{
    return send_system_status();
}

ErrorOr<void> FTPServerClient::handle_pwd_command()
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    return send_current_working_directory();
}

ErrorOr<void> FTPServerClient::handle_syst_command()
{
    return send_system_info();
}

ErrorOr<void> FTPServerClient::handle_retr_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_command_not_implemented_for_parameter();
    }

    String file = params.at(0);

    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(file);

    auto stream = TRY(Core::InputFileStream::open(builder.to_string()));

    auto connection = TRY(create_data_socket());
    TRY(connection->set_blocking(true));

    TRY(send_initiating_transfer(builder.to_string()));

    // FIXME: use the default_transfer_buffer_size
    auto buffer = TRY(ByteBuffer::create_uninitialized(5));
    while (!stream.has_any_error() && buffer.size() > 0) {

        auto nread = stream.read(buffer);
        buffer.resize(nread);

        TRY(connection->write(buffer));

        if (on_data_transfer_update)
            on_data_transfer_update(m_id, nread);

        // FIXME: Remove sleep
        sleep(1);
    }

    connection->close();
    return send_transfer_success();
}

ErrorOr<void> FTPServerClient::handle_stor_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_command_not_implemented_for_parameter();
    }

    String file = String::join(" "sv, params);

    auto connection = TRY(create_data_socket());

    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(file);
    auto path = LexicalPath::canonicalized_path(builder.to_string());

    if (Core::File::exists(path)) {
        TRY(Core::File::remove(path, Core::File::RecursionMode::Disallowed, false));
    }

    auto outstream = TRY(Core::Stream::File::open(path, Core::Stream::OpenMode::Write));
    TRY(connection->set_blocking(true));

    auto transfer_buffer = TRY(ByteBuffer::create_uninitialized(TRANSFER_BUFFER_DEFAULT_SIZE));

    TRY(send_initiating_transfer(builder.to_string()));

    while (true) {
        auto trimmed_buffer = TRY(connection->read(transfer_buffer));

        if (trimmed_buffer.is_empty()) {
            break;
        }

        TRY(outstream->write(trimmed_buffer));

        if (on_data_transfer_update)
            on_data_transfer_update(m_id, trimmed_buffer.size());
    }

    connection->close();
    return send_transfer_success();
}

ErrorOr<void> FTPServerClient::handle_mkd_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_command_not_implemented_for_parameter();
    }

    String file = String::join(" "sv, params);

    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(file);
    auto path = LexicalPath::canonicalized_path(builder.to_string());

    TRY(Core::System::mkdir(path, 0755));

    return send_file_action_ok();
}

ErrorOr<void> FTPServerClient::handle_rmd_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_command_not_implemented_for_parameter();
    }

    String file = String::join(" "sv, params);

    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(file);
    auto path = LexicalPath::canonicalized_path(builder.to_string());

    // FIXME: TRY()
    rmdir(path.characters());

    return send_file_action_ok();
}

ErrorOr<void> FTPServerClient::handle_dele_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_command_not_implemented_for_parameter();
    }

    String file = String::join(" "sv, params);

    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(file);
    auto path = LexicalPath::canonicalized_path(builder.to_string());

    TRY(Core::File::remove(path, Core::File::RecursionMode::Disallowed, false));
    return send_file_action_ok();
}

ErrorOr<void> FTPServerClient::handle_cwd_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_command_not_implemented_for_parameter();
    }

    if (!params.at(0).starts_with("/"sv)) {
        StringBuilder builder;
        builder.append(m_working_dir);
        builder.append("/"sv);
        builder.append(params.at(0));
        (void)params.take_first();

        params.prepend(builder.to_string());
    }

    String path = String::join(" "sv, params);

    m_working_dir = LexicalPath::canonicalized_path(path);
    return send_file_action_ok();
}

ErrorOr<void> FTPServerClient::handle_cdup_command()
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/.."sv);
    m_working_dir = LexicalPath::canonicalized_path(builder.to_string());
    return send_file_action_ok();
}

ErrorOr<void> FTPServerClient::handle_list_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_directory_content(m_working_dir, true, DirectoryTransferFormat::LS);
    }

    String path = String::join(" "sv, params);

    if (path.starts_with('-')) {
        return send_directory_content(m_working_dir, true, DirectoryTransferFormat::LS);
    }

    return send_directory_content(path, true, DirectoryTransferFormat::LS);
}

ErrorOr<void> FTPServerClient::handle_nlst_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_directory_content(m_working_dir, true, DirectoryTransferFormat::NAME_ONLY);
    }

    String path = String::join(" "sv, params);

    if (path.starts_with('-')) {
        return send_directory_content(m_working_dir, true, DirectoryTransferFormat::NAME_ONLY);
    }

    return send_directory_content(path, true, DirectoryTransferFormat::NAME_ONLY);
}

ErrorOr<void> FTPServerClient::handle_type_command(Vector<String> params)
{
    if (params.size() < 1) {
        return send_invalid_parameters();
    }

    String type = params.at(0);

    if (!type.equals_ignoring_case("I"sv) && !type.equals_ignoring_case("A"sv)) {
        return send_command_not_implemented_for_parameter();
    }

    m_transfer_type = type;
    return send_ok();
}

ErrorOr<void> FTPServerClient::handle_stru_command(Vector<String> params)
{
    if (params.size() < 1) {
        return send_invalid_parameters();
    }

    String type = params.at(0);

    if (!type.equals_ignoring_case("F"sv)) {
        return send_command_not_implemented_for_parameter();
    }

    m_file_structure = type;
    return send_ok();
}

ErrorOr<void> FTPServerClient::handle_mode_command(Vector<String> params)
{
    if (params.size() < 1) {
        return send_invalid_parameters();
    }

    String mode = params.at(0);

    if (!mode.equals_ignoring_case("S"sv)) {
        return send_command_not_implemented_for_parameter();
    }

    m_transfer_mode = mode;
    return send_ok();
}

ErrorOr<void> FTPServerClient::handle_xcrc_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_invalid_parameters();
    }

    auto filename = params.at(0);
    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(filename);
    auto path = LexicalPath::canonicalized_path(builder.to_string());

    if (!Core::File::exists(path)) {
        return send_file_unavailable();
    }

    auto stream = TRY(Core::InputFileStream::open(path));

    auto crc = Crypto::Checksum::CRC32();
    auto buffer = TRY(ByteBuffer::create_uninitialized(TRANSFER_BUFFER_DEFAULT_SIZE));
    while (!stream.has_any_error() && buffer.size() > 0) {
        auto nread = stream.read(buffer);
        buffer.resize(nread);
        crc.update(buffer);
    }

    return send_file_action_ok(String::formatted("{}", crc.digest()));
}

ErrorOr<void> FTPServerClient::handle_pasv_command()
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    m_data_connection = TRY(Core::TCPServer::try_create());
    TRY(m_data_connection->set_blocking(true));

    while (m_data_connection->listen(m_source_address, 0).is_error()) {
        if (on_receive_command)
            on_receive_command(this, String::formatted("Failed to open passive socket on {}:{} failed, port taken?", m_source_address, m_data_connection->local_port().value()));
    }

    if (!m_data_connection->is_listening()) {
        return send_request_aborted_local_error();
    }

    m_is_passive = true;

    if (on_info)
        on_info(this, String::formatted("Opened passive socket on {}:{}", m_source_address, m_data_connection->local_port().value()));

    return send_entering_passive_mode(m_data_connection->local_address().value(), m_data_connection->local_port().value());
}

ErrorOr<void> FTPServerClient::handle_user_command(Vector<String> params)
{
    if (m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_invalid_parameters();
    }

    auto username = params.at(0);

    auto allow_anonymous = m_json_settings.get("allow_anonymous_logins"sv).to_bool(false);
    if (!allow_anonymous) {
        auto maybe_account = Core::Account::from_name(username, Core::Account::Read::PasswdOnly);
        if (maybe_account.is_error()) {
            dbgln_if(FTP_DEBUG, "Failed to find user with username {}", username);
            dbgln_if(FTP_DEBUG, maybe_account.error().string_literal());
            return send_not_logged_in();
        }

        m_account = maybe_account.value();
    }

    m_username = username;

    return send_user_ok_need_password();
}

ErrorOr<void> FTPServerClient::handle_pass_command(Vector<String> params)
{
    if (m_is_logged_in) {
        return send_command_not_needed();
    }

    if (params.size() < 1) {
        return send_invalid_parameters();
    }

    auto password = params.at(0);

    auto allow_anonymous = m_json_settings.get("allow_anonymous_logins"sv).to_bool(false);
    if (!allow_anonymous) {
        if (!m_account.has_value()) {
            return send_bad_sequence_of_commands();
        }

        if (!m_account->authenticate(Core::SecretString::take_ownership(password.to_byte_buffer()))) {
            dbgln_if(FTP_DEBUG, "Failed to authenticate user '{}' with password '{}'", m_username.value(), password);
            return send_not_logged_in();
        }
    }

    if (!m_username.has_value()) {
        return send_bad_sequence_of_commands();
    }

    auto default_work_dir = m_json_settings.get("default_home_directory"sv).as_string_or("/");
    auto users_settings = m_json_settings.get("users"sv).as_object();
    if (users_settings.has(m_username.value())) {
        auto current_user_settings = users_settings.get(m_username.value()).as_object();
        m_working_dir = current_user_settings.get("home_directory"sv).as_string_or(default_work_dir);
    }

    m_is_logged_in = true;
    return send_user_logged_in();
}

ErrorOr<void> FTPServerClient::handle_quit_command()
{
    return quit();
}

ErrorOr<void> FTPServerClient::handle_mlst_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_directory_content(m_working_dir, false, DirectoryTransferFormat::MLSX);
    }

    String path = String::join(" "sv, params);

    if (path.starts_with('-')) {
        return send_directory_content(m_working_dir, false, DirectoryTransferFormat::MLSX);
    }

    return send_directory_content(path, false, DirectoryTransferFormat::MLSX);
}

ErrorOr<void> FTPServerClient::handle_mlsd_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 1) {
        return send_directory_content(m_working_dir, true, DirectoryTransferFormat::MLSX);
    }

    String path = String::join(" "sv, params);

    if (path.starts_with('-')) {
        return send_directory_content(m_working_dir, true, DirectoryTransferFormat::MLSX);
    }

    return send_directory_content(path, true, DirectoryTransferFormat::MLSX);
}

ErrorOr<void> FTPServerClient::handle_site_command()
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    return send_command_not_implemented();
}

ErrorOr<void> FTPServerClient::handle_help_command()
{
    return send_help_message();
}

ErrorOr<void> FTPServerClient::handle_mfct_command()
{
    return send_command_not_needed();
}

ErrorOr<void> FTPServerClient::handle_mfmt_command(Vector<String> params)
{
    if (!m_is_logged_in) {
        return send_not_logged_in();
    }

    if (params.size() < 2) {
        return send_invalid_parameters();
    }

    auto time = params.at(0);
    auto file = params.at(1);

    StringBuilder builder;
    builder.append(m_working_dir);
    builder.append("/"sv);
    builder.append(file);
    auto path = LexicalPath::canonicalized_path(builder.to_string());

    if (!Core::File::exists(path)) {
        return send_file_unavailable();
    }

    auto new_time = Core::DateTime::parse("%Y%m%d%H%M%S"sv, time);
    if (!new_time.has_value()) {
        return send_invalid_parameters();
    }

    utimbuf buf = { new_time->timestamp(), new_time->timestamp() };
    TRY(Core::System::utime(path, buf));

    return send_file_attribute_change_ok();
}

ErrorOr<void> FTPServerClient::quit()
{
    if (m_control_connection->is_open())
        m_control_connection->close();

    // TODO: close the data connection?

    if (on_exit)
        on_exit();

    m_should_die = true;

    return {};
}

ErrorOr<void> FTPServerClient::send_directory_content(String path, bool use_data_socket, DirectoryTransferFormat format)
{
    Optional<ErrorOr<NonnullOwnPtr<Core::Stream::TCPSocket>>> connection;

    if (use_data_socket) {
        connection = TRY(create_data_socket());
        TRY(connection.value().value()->set_blocking(true));
        TRY(send_initiating_transfer(path));
    }

    dbgln_if(FTP_DEBUG, "Sending content of directory \"{}\"", path);

    Core::DirIterator di(path, Core::DirIterator::SkipDots);
    while (di.has_next()) {
        String name = di.next_path();

        StringBuilder builder;
        builder.append(path);
        builder.append('/');
        builder.append(name);

        auto path = LexicalPath(builder.to_string());
        auto data = TRY(format_to_transfer_format(path, format));

        dbgln_if(FTP_DEBUG, "{}", data);

        if (use_data_socket) {
            TRY(connection.value().value()->write(data.bytes()));
        } else {
            TRY(send(data));
        }
    }

    if (use_data_socket) {
        connection.value().value()->close();
    }

    return send_transfer_success();
}

ErrorOr<NonnullOwnPtr<Core::Stream::TCPSocket>> FTPServerClient::create_data_socket()
{
    if (!m_is_passive.has_value()) {
        (void)send_unable_to_open_data_connection();
        return Error::from_string_literal("Unable to open data connection");
    }

    auto is_passive = m_is_passive.value();

    if (!is_passive) {
        TODO();
        return Error::from_string_literal("Unhandled case");
    }

    auto connection = TRY(m_data_connection->accept());
    TRY(connection->set_blocking(true));

    return connection;
}

ErrorOr<String> FTPServerClient::format_to_transfer_format(LexicalPath path, DirectoryTransferFormat format)
{
    switch (format) {
    case DirectoryTransferFormat::LS:
        return format_for_ls(path);
    case DirectoryTransferFormat::NAME_ONLY:
        return format_for_name_only(path);
    case DirectoryTransferFormat::MLSX:
        return format_for_mlsx(path);
    default:
        VERIFY_NOT_REACHED();
    }
}

ErrorOr<String> FTPServerClient::format_for_name_only(LexicalPath path)
{
    return path.basename().to_string();
}

ErrorOr<String> FTPServerClient::format_for_ls(LexicalPath path)
{
    struct stat st = TRY(Core::System::lstat(path.string()));

    StringBuilder builder;

    if (S_ISDIR(st.st_mode))
        builder.append("d"sv);
    else if (S_ISLNK(st.st_mode))
        builder.append("l"sv);
    else if (S_ISBLK(st.st_mode))
        builder.append("b"sv);
    else if (S_ISCHR(st.st_mode))
        builder.append("c"sv);
    else if (S_ISFIFO(st.st_mode))
        builder.append("f"sv);
    else if (S_ISSOCK(st.st_mode))
        builder.append("s"sv);
    else if (S_ISREG(st.st_mode))
        builder.append("-"sv);
    else
        builder.append("?"sv);

    builder.appendff("{}{}{}{}{}{}{}{}",
        st.st_mode & S_IRUSR ? 'r' : '-',
        st.st_mode & S_IWUSR ? 'w' : '-',
        st.st_mode & S_ISUID ? 's' : (st.st_mode & S_IXUSR ? 'x' : '-'),
        st.st_mode & S_IRGRP ? 'r' : '-',
        st.st_mode & S_IWGRP ? 'w' : '-',
        st.st_mode & S_ISGID ? 's' : (st.st_mode & S_IXGRP ? 'x' : '-'),
        st.st_mode & S_IROTH ? 'r' : '-',
        st.st_mode & S_IWOTH ? 'w' : '-');

    if (st.st_mode & S_ISVTX)
        builder.append("t"sv);
    else
        builder.appendff("{}", st.st_mode & S_IXOTH ? 'x' : '-');

    builder.appendff(" {}", st.st_nlink);
    builder.appendff(" {}", st.st_uid);
    builder.appendff(" {}", st.st_gid);

    if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) {
        builder.appendff("  {},{} ", major(st.st_rdev), minor(st.st_rdev));
    } else {
        builder.appendff(" {} ", (uint64_t)st.st_size);
    }

    builder.appendff("  {}  ", Core::DateTime::from_timestamp(st.st_mtime).to_string("%h %d  %Y"sv));

    builder.append(path.basename());
    builder.append("\r\n"sv);

    return builder.to_string();
}

ErrorOr<String> FTPServerClient::format_for_mlsx(LexicalPath path)
{
    StringBuilder builder;

    struct stat stat = TRY(Core::System::lstat(path.string()));

    // FIXME: split into file, dir, cdir, pdir
    builder.appendff("Type={};", S_ISDIR(stat.st_mode) ? "dir" : "file");

    builder.appendff("Size={};", (uint64_t)stat.st_size);
    builder.appendff("Modify={};", Core::DateTime::from_timestamp(stat.st_mtime).to_string("%Y%m%d%H%M%S"sv));
    builder.appendff("Unique={};", stat.st_ino);

    /*
    a + type=file;  append is ok
    c + type=dir;   store is ok
    d;              delete is ok
    e + type=dir;   CD to the dir is ok
    f;              rename is ok
    l + type=dir;   listing files is ok
    m + type=dir;   create new dir is ok
    p + type=dir;   directory contents can be deleted
    r + type=file;  file can be downloaded
    w + type=file;  file can be uploaded
    */
    // Note: This does not imply the actions are guaranteed to work, just that it might.
    builder.appendff("Perm={};", "acdeflmprw");

    return builder.to_string();
}

ErrorOr<void> FTPServerClient::send_restart_marker()
{
    // 110
    // TODO:
    return send_command_not_implemented();
}

ErrorOr<void> FTPServerClient::send_service_ready_in_minutes([[maybe_unused]] u32 minutes)
{
    // 120
    // TODO:
    return send_command_not_implemented();
}

ErrorOr<void> FTPServerClient::send_data_connection_already_open()
{
    return send("125 Data connection already opened; transfer starting\r\n");
}

ErrorOr<void> FTPServerClient::send_initiating_transfer(String path)
{
    if (on_data_transfer_start)
        on_data_transfer_start(m_id, path);
    return send("150 File status okay; about to open data connection\r\n");
}

ErrorOr<void> FTPServerClient::send_ok()
{
    return send("200 OK\r\n");
}

ErrorOr<void> FTPServerClient::send_command_not_needed()
{
    return send("202 Command not implemented, superfluous at this site\r\n");
}

ErrorOr<void> FTPServerClient::send_system_status()
{
    return send("211 System status, or system help reply\r\n");
}

ErrorOr<void> FTPServerClient::send_directory_status()
{
    return send("212 Directory status\r\n");
}

ErrorOr<void> FTPServerClient::send_file_status(String status)
{
    return send(String::formatted("213 {}\r\n", status));
}

ErrorOr<void> FTPServerClient::send_help_message()
{
    return send("214 System status, or system help reply\r\n");
}

ErrorOr<void> FTPServerClient::send_system_info()
{
    return send("215 SerenityOS\r\n");
}

ErrorOr<void> FTPServerClient::send_welcome()
{
    return send("220 Ready\r\n");
}

ErrorOr<void> FTPServerClient::send_closing_control_connection()
{
    return send("221 Service closing control connection\r\n");
}

ErrorOr<void> FTPServerClient::send_data_connection_open_no_transfer_in_progress()
{
    return send("225 Data connection open; no transfer in progress\r\n");
}

ErrorOr<void> FTPServerClient::send_transfer_success()
{
    if (on_data_transfer_end)
        on_data_transfer_end(m_id);
    return send("226 Closing data connection; transfer ok\r\n");
}

ErrorOr<void> FTPServerClient::send_entering_passive_mode(IPv4Address address, u16 port)
{
    StringBuilder builder;
    builder.appendff("227 Entering Passive Mode ({},{},{},{},{},{})\r\n", address[0], address[1], address[2], address[3], port >> 8, port & 0xFF);
    return send(builder.to_string());
}

ErrorOr<void> FTPServerClient::send_user_logged_in()
{
    return send("230 User logged in\r\n");
}

ErrorOr<void> FTPServerClient::send_auth_ok()
{
    return send("234 AUTH command OK. Initializing connection\r\n");
}

ErrorOr<void> FTPServerClient::send_file_action_ok_start(String data)
{
    return send(String::formatted("250- {}\r\n", data));
}

ErrorOr<void> FTPServerClient::send_file_action_ok(String data)
{
    return send(String::formatted("250 {}\r\n", data));
}

ErrorOr<void> FTPServerClient::send_file_action_ok_stop()
{
    return send("250 End\r\n");
}

ErrorOr<void> FTPServerClient::send_file_attribute_change_ok()
{
    return send("253 Attributes changed ok.\r\n");
}

ErrorOr<void> FTPServerClient::send_current_working_directory()
{
    StringBuilder builder;
    builder.appendff("257 \"{}\"\r\n", m_working_dir);
    return send(builder.to_string());
}

ErrorOr<void> FTPServerClient::send_user_ok_need_password()
{
    return send("331 Username okay, need password\r\n");
}

ErrorOr<void> FTPServerClient::send_need_account_for_login()
{
    return send("332 Need account for login\r\n");
}

ErrorOr<void> FTPServerClient::send_auth_security_data(String base64data)
{
    StringBuilder builder;
    builder.append("334 "sv);
    builder.append("[ADAT="sv);
    builder.append(base64data);
    builder.append("]\r\n"sv);
    return send(builder.to_string());
}

ErrorOr<void> FTPServerClient::send_file_action_needs_additional_command()
{
    return send("350 Requested file action pending further information\r\n");
}

ErrorOr<void> FTPServerClient::send_service_unavailable()
{
    return send("421 Service not available, closing control connection\r\n");
}

ErrorOr<void> FTPServerClient::send_unable_to_open_data_connection()
{
    return send("425 Unable to open data connection\r\n");
}

ErrorOr<void> FTPServerClient::send_connection_closed_transfer_aborted()
{
    return send("426 Connection closed; transfer aborted\r\n");
}

ErrorOr<void> FTPServerClient::send_security_resource_unavailable()
{
    return send("431 Need unavailable resource to process security\r\n");
}

ErrorOr<void> FTPServerClient::send_file_action_not_taken()
{
    return send("450 Requested file action not taken\r\n");
}

ErrorOr<void> FTPServerClient::send_request_aborted_local_error()
{
    return send("451 Requested action aborted: local error in processing\r\n");
}

ErrorOr<void> FTPServerClient::send_request_aborted_not_enough_filesystem_space()
{
    return send("452 Requested action not taken; insufficient storage space\r\n");
}

ErrorOr<void> FTPServerClient::send_command_unrecognized()
{
    return send("500 Syntax error, command unrecognized\r\n");
}

ErrorOr<void> FTPServerClient::send_invalid_parameters()
{
    return send("501 Syntax error in parameters or argument\r\n");
}

ErrorOr<void> FTPServerClient::send_command_not_implemented()
{
    return send("502 Command not implemented\r\n");
}

ErrorOr<void> FTPServerClient::send_bad_sequence_of_commands()
{
    return send("503 Bad sequence of commands\r\n");
}

ErrorOr<void> FTPServerClient::send_command_not_implemented_for_parameter()
{
    return send("504 Command not implemented for that parameter\r\n");
}

ErrorOr<void> FTPServerClient::send_not_logged_in()
{
    return send("530 Not logged in\r\n");
}

ErrorOr<void> FTPServerClient::send_need_account_to_store_files()
{
    return send("532 Need account for storing files\r\n");
}

ErrorOr<void> FTPServerClient::send_request_denied_due_to_policy()
{
    return send("534 Request denied for policy reasons\r\n");
}

ErrorOr<void> FTPServerClient::send_failed_security_check()
{
    return send("535 Failed security check\r\n");
}

ErrorOr<void> FTPServerClient::send_file_unavailable()
{
    return send("550 Requested action not taken; file unavailable\r\n");
}

ErrorOr<void> FTPServerClient::send_page_type_unknown()
{
    return send("551 Requested action aborted: page type unknown\r\n");
}

ErrorOr<void> FTPServerClient::send_exceeded_storage_allocation()
{
    return send("552 Requested file action aborted; Exceeded storage allocation\r\n");
}

ErrorOr<void> FTPServerClient::send_filename_not_allowed()
{
    return send("553 Requested action not taken; File name not allowed\r\n");
}

ErrorOr<void> FTPServerClient::send(String data)
{
    dbgln_if(FTP_DEBUG, "Sending: {}", data.substring_view(0, data.length() - 2));

    if (on_send_command)
        on_send_command(this, data);

    if (!m_control_connection->is_open()) {
        dbgln_if(FTP_DEBUG, "{}", "Closed?");
        return Error::from_string_literal("Socket closed; Unable to write");
    }

    TRY(m_control_connection->write(data.bytes()));

    return {};
}
