include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

add_executable(test_xdr test_xdr.cpp)
target_link_libraries(test_xdr PRIVATE nfs_lib GTest::gtest_main)
add_test(NAME test_xdr COMMAND test_xdr)

add_executable(test_rpc test_rpc.cpp)
target_link_libraries(test_rpc PRIVATE nfs_lib GTest::gtest_main)
add_test(NAME test_rpc COMMAND test_rpc)

add_executable(test_nfs test_nfs.cpp)
target_link_libraries(test_nfs PRIVATE nfs_lib GTest::gtest_main)
add_test(NAME test_nfs COMMAND test_nfs)

add_executable(test_vfs test_vfs.cpp)
target_link_libraries(test_vfs PRIVATE nfs_lib GTest::gtest_main)
add_test(NAME test_vfs COMMAND test_vfs)

add_executable(test_nfs4 test_nfs4.cpp)
target_link_libraries(test_nfs4 PRIVATE nfs_lib GTest::gtest_main)
add_test(NAME test_nfs4 COMMAND test_nfs4)
