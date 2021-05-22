serenity_component(
    FTPServer
    RECOMMENDED
    TARGETS FTPServer
)

set(SOURCES
    FTPServer.cpp
    FTPServerClient.cpp
    FTPServerTransferModel.cpp
    main.cpp
)

serenity_app(FTPServer ICON app-ftp-server)
target_link_libraries(FTPServer LibMain LibWeb LibThreading)
