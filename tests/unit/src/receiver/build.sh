#!/bin/sh

g++ -O0 -ggdb -std=c++17 -o test -D__LINUX__ -D_AMD64_ -I../../../../common/native -I../../../../receiver/native -I../../../../thirdparty/kuku/src/src -I../../../../thirdparty/seal/src/native/src -I../../../../thirdparty/seal/src/thirdparty/msgsl/src/include -I../../../../thirdparty/fourq/src/FourQ_64bit_and_portable receiver.cpp ../unit_tests_runner.cpp -L../../../../lib -L../../../../thirdparty/fourq/src/FourQ_64bit_and_portable -lapsi_receiver-1.0 -lapsi_common-1.0 -lflatbuffers -llog4cplus -lseal-3.5 -lFourQ -lzmqpp -lzmq -lgtest -pthread -lkuku
