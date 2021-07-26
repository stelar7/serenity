include(TimeZone/iana_time_zone_data.cmake)

SET(SOURCES
    ${TIMEZONE_DATA_SOURCES}
    LocalDate.cpp
    LocalTime.cpp
)

serenity_lib(LibDateTime localization)
target_link_libraries(LibDateTime LibCore)

add_custom_target(generated_timelib.cpp ALL DEPENDS LibDateTime)
