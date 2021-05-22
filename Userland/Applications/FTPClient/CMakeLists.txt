serenity_component(
    FTPClient
    RECOMMENDED
    TARGETS FTPClient
)

set(SOURCES
    FTPClient.cpp
    main.cpp
)

serenity_app(FTPClient ICON app-ftp-server)
target_link_libraries(FTPClient LibMain LibWeb)
