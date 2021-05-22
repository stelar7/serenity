/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/JsonObject.h>
#include <AK/LexicalPath.h>
#include <LibCore/Account.h>
#include <LibCore/Stream.h>
#include <LibCore/TCPServer.h>
#include <LibTLS/TLSv12.h>

enum class DirectoryTransferFormat {
    NAME_ONLY,
    LS,
    MLSX
};

constexpr size_t TRANSFER_BUFFER_DEFAULT_SIZE = 4 * KiB;

class FTPServerClient : public RefCounted<FTPServerClient> {
public:
    static NonnullRefPtr<FTPServerClient> create(u32 id, IPv4Address source_address, NonnullOwnPtr<Core::Stream::TCPSocket> socket, AK::JsonObject json_settings)
    {
        return adopt_ref(*new FTPServerClient(id, source_address, move(socket), json_settings));
    }

    Function<void()> on_exit;
    Function<void(FTPServerClient*, String)> on_info;
    Function<void(FTPServerClient*, String)> on_receive_command;
    Function<void(FTPServerClient*, String)> on_send_command;
    Function<void(u32, String)> on_data_transfer_start;
    Function<void(u32, u32)> on_data_transfer_update;
    Function<void(u32)> on_data_transfer_end;

    ErrorOr<void> send_auth_ok();
    ErrorOr<void> send_auth_security_data(String);
    ErrorOr<void> send_bad_sequence_of_commands();
    ErrorOr<void> send_closing_control_connection();
    ErrorOr<void> send_command_not_implemented_for_parameter();
    ErrorOr<void> send_command_not_implemented();
    ErrorOr<void> send_command_not_needed();
    ErrorOr<void> send_command_unrecognized();
    ErrorOr<void> send_connection_closed_transfer_aborted();
    ErrorOr<void> send_current_working_directory();
    ErrorOr<void> send_data_connection_already_open();
    ErrorOr<void> send_data_connection_open_no_transfer_in_progress();
    ErrorOr<void> send_directory_content(String, bool, DirectoryTransferFormat);
    ErrorOr<void> send_directory_status();
    ErrorOr<void> send_entering_passive_mode(IPv4Address, u16);
    ErrorOr<void> send_exceeded_storage_allocation();
    ErrorOr<void> send_failed_security_check();
    ErrorOr<void> send_file_action_needs_additional_command();
    ErrorOr<void> send_file_action_not_taken();
    ErrorOr<void> send_file_action_ok(String data = "250 Requested file action okay, completed");
    ErrorOr<void> send_file_action_ok_start(String);
    ErrorOr<void> send_file_action_ok_stop();
    ErrorOr<void> send_file_attribute_change_ok();
    ErrorOr<void> send_file_status(String);
    ErrorOr<void> send_file_unavailable();
    ErrorOr<void> send_filename_not_allowed();
    ErrorOr<void> send_help_message();
    ErrorOr<void> send_initiating_transfer(String);
    ErrorOr<void> send_invalid_parameters();
    ErrorOr<void> send_need_account_for_login();
    ErrorOr<void> send_need_account_to_store_files();
    ErrorOr<void> send_not_logged_in();
    ErrorOr<void> send_ok();
    ErrorOr<void> send_page_type_unknown();
    ErrorOr<void> send_request_aborted_local_error();
    ErrorOr<void> send_request_aborted_not_enough_filesystem_space();
    ErrorOr<void> send_request_denied_due_to_policy();
    ErrorOr<void> send_restart_marker();
    ErrorOr<void> send_security_resource_unavailable();
    ErrorOr<void> send_service_ready_in_minutes(u32);
    ErrorOr<void> send_service_unavailable();
    ErrorOr<void> send_system_info();
    ErrorOr<void> send_system_status();
    ErrorOr<void> send_transfer_success();
    ErrorOr<void> send_unable_to_open_data_connection();
    ErrorOr<void> send_user_logged_in();
    ErrorOr<void> send_user_ok_need_password();
    ErrorOr<void> send_welcome();

    String user() { return m_username.has_value() ? m_username.value() : "[no username]"; };
    u32 id() { return m_id; };
    ErrorOr<void> initialize();

protected:
    FTPServerClient(u32 id, IPv4Address source_address, NonnullOwnPtr<Core::Stream::TCPSocket> socket, AK::JsonObject json_settings);

    ErrorOr<void> send(String);
    ErrorOr<void> handle_command(String);
    ErrorOr<void> drain_socket();
    ErrorOr<NonnullOwnPtr<Core::Stream::TCPSocket>> create_data_socket();
    ErrorOr<void> quit();

private:
    ErrorOr<void> handle_appe_command(Vector<String>);
    ErrorOr<void> handle_auth_command(Vector<String>);
    ErrorOr<void> handle_cdup_command();
    ErrorOr<void> handle_cwd_command(Vector<String>);
    ErrorOr<void> handle_dele_command(Vector<String>);
    ErrorOr<void> handle_feat_command();
    ErrorOr<void> handle_help_command();
    ErrorOr<void> handle_list_command(Vector<String>);
    ErrorOr<void> handle_mdtm_command(Vector<String>);
    ErrorOr<void> handle_mfct_command();
    ErrorOr<void> handle_mfmt_command(Vector<String>);
    ErrorOr<void> handle_mkd_command(Vector<String>);
    ErrorOr<void> handle_mlsd_command(Vector<String>);
    ErrorOr<void> handle_mlst_command(Vector<String>);
    ErrorOr<void> handle_mode_command(Vector<String>);
    ErrorOr<void> handle_nlst_command(Vector<String>);
    ErrorOr<void> handle_noop_command();
    ErrorOr<void> handle_pass_command(Vector<String>);
    ErrorOr<void> handle_pasv_command();
    ErrorOr<void> handle_pwd_command();
    ErrorOr<void> handle_quit_command();
    ErrorOr<void> handle_rein_command();
    ErrorOr<void> handle_retr_command(Vector<String>);
    ErrorOr<void> handle_rmd_command(Vector<String>);
    ErrorOr<void> handle_rnfr_command(Vector<String>);
    ErrorOr<void> handle_rnto_command(Vector<String>);
    ErrorOr<void> handle_site_command();
    ErrorOr<void> handle_size_command(Vector<String>);
    ErrorOr<void> handle_stor_command(Vector<String>);
    ErrorOr<void> handle_stou_command(Vector<String>);
    ErrorOr<void> handle_stru_command(Vector<String>);
    ErrorOr<void> handle_syst_command();
    ErrorOr<void> handle_type_command(Vector<String>);
    ErrorOr<void> handle_user_command(Vector<String>);
    ErrorOr<void> handle_xcrc_command(Vector<String>);

    ErrorOr<String> format_to_transfer_format(LexicalPath, DirectoryTransferFormat format = DirectoryTransferFormat::LS);
    ErrorOr<String> format_for_name_only(LexicalPath path);
    ErrorOr<String> format_for_ls(LexicalPath path);
    ErrorOr<String> format_for_mlsx(LexicalPath path);

    u32 m_id { 0 };
    bool m_should_die { false };
    IPv4Address m_source_address {};

    NonnullOwnPtr<Core::Stream::TCPSocket> m_control_connection;
    RefPtr<Core::TCPServer> m_data_connection;

    Optional<Core::Account> m_account {};
    Optional<String> m_username {};
    bool m_is_logged_in { false };
    String m_working_dir {};
    String m_transfer_type { "I" };
    String m_transfer_mode { "S" };
    String m_file_structure { "F" };
    String m_rename_from {};
    Optional<bool> m_is_passive {};

    AK::JsonObject m_json_settings;
};
