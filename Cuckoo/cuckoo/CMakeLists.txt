target_sources(cuckoo 
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/aes.cpp
        ${CMAKE_CURRENT_LIST_DIR}/cuckoo.cpp
)

# Create the config file
configure_file(${CMAKE_CURRENT_LIST_DIR}/config.h.in ${CMAKE_CURRENT_LIST_DIR}/config.h)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/aes.h
        ${CMAKE_CURRENT_LIST_DIR}/config.h
        ${CMAKE_CURRENT_LIST_DIR}/cuckoo.h
        ${CMAKE_CURRENT_LIST_DIR}/common.h
        ${CMAKE_CURRENT_LIST_DIR}/locfunc.h
    DESTINATION
        ${CUCKOO_INCLUDES_INSTALL_DIR}/cuckoo
)
