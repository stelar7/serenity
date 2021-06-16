set(SOURCES
    Readers/XSV.cpp
)

serenity_test(Writers/Test/TestXSVWriter.cpp LibCSV)
serenity_test(Readers/Test/TestXSV.cpp LibCSV)

serenity_lib(LibCSV csv)
target_link_libraries(LibCSV LibC)
target_sources(TestXSV PRIVATE Readers/XSV.cpp)