set(TIMEZONE_INSTALL_PATH ${CMAKE_INSTALL_DATAROOTDIR}/IANA/TimeZone)

if (EXISTS ${TIMEZONE_INSTALL_PATH})
    set(TIMEZONE_GENERATOR TimeZone/CodeGenerators/GenerateTimeZoneData)
    set(TIMEZONE_DATA_HEADER TimeZone/TimeZoneData.h)
    set(TIMEZONE_DATA_IMPLEMENTATION TimeZone/TimeZoneData.cpp)

    if (CMAKE_SOURCE_DIR MATCHES ".*/Lagom") # Lagom-only build.
        set(TIMEZONE_GENERATOR LibDateTime/TimeZone/CodeGenerators/GenerateTimeZoneData)
        set(TIMEZONE_DATA_HEADER LibDateTime/TimeZone/TimeZoneData.h)
        set(TIMEZONE_DATA_IMPLEMENTATION LibDateTime/TimeZone/TimeZoneData.cpp)
    elseif (CMAKE_CURRENT_BINARY_DIR MATCHES ".*/Lagom") # Lagom build within the main SerenityOS build.
        set(TIMEZONE_GENERATOR ../../Userland/Libraries/LibDateTime/TimeZone/CodeGenerators/GenerateTimeZoneData)
        set(TIMEZONE_DATA_HEADER LibDateTime/TimeZone/TimeZoneData.h)
        set(TIMEZONE_DATA_IMPLEMENTATION LibDateTime/TimeZone/TimeZoneData.cpp)
    endif()

    add_custom_command(
        OUTPUT ${TIMEZONE_DATA_HEADER}
        COMMAND ${write_if_different} ${TIMEZONE_DATA_HEADER} ${TIMEZONE_GENERATOR} -h -u ${TIMEZONE_INSTALL_PATH}
        VERBATIM
        DEPENDS GenerateTimeZoneData
        MAIN_DEPENDENCY ${TIMEZONE_INSTALL_PATH}
    )

    add_custom_command(
        OUTPUT ${TIMEZONE_DATA_IMPLEMENTATION}
        COMMAND ${write_if_different} ${TIMEZONE_DATA_IMPLEMENTATION} ${TIMEZONE_GENERATOR} -c -u ${TIMEZONE_INSTALL_PATH}
        VERBATIM
        DEPENDS GenerateTimeZoneData
        MAIN_DEPENDENCY ${TIMEZONE_INSTALL_PATH}
    )

    add_custom_target(generated_timezone.h ALL DEPENDS ${TIMEZONE_DATA_HEADER})
    add_custom_target(generated_timezone.cpp ALL DEPENDS ${TIMEZONE_DATA_IMPLEMENTATION})

    set(TIMEZONE_DATA_SOURCES ${TIMEZONE_DATA_HEADER} ${TIMEZONE_DATA_IMPLEMENTATION})
    add_compile_definitions(ENABLE_TIMEZONE_DATA=1)
else()
    add_compile_definitions(ENABLE_TIMEZONE_DATA=0)
endif()
