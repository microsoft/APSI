CXX = g++
CFLAGS = -g -Ofast -march=native -std=c++17  -maes -msse2 -msse4.1 -mpclmul -DNDEBUG

SRCS = receiver.cpp
INCLUDES = -I. -I../APSI -I../../SEAL-dev/SEAL -I../../cryptoTools -I../../cryptoTools/thirdparty/miracl -I/usr/include/flint -I../../Cuckoo/Cuckoo
LIB_DIRS = -L../bin -L../../SEAL-dev/lib -L../../cryptoTools/lib -L../../cryptoTools/thirdparty/linux/boost/stage/lib -L../../cryptoTools/thirdparty/miracl/lib -L/usr/lib -L../../Cuckoo/lib -L../../FourQlib/FourQ_64bit_and_portable
LIBS = -lapsi -lcuckoo -lseal -lcryptoTools -lmiracl -lboost_system -pthread -lgmp -lflint -lFourQ -lcryptopp -lzmq -lzmqpp

all:
	$(CXX) -o receiver $(SRCS) $(CFLAGS) $(INCLUDES) $(LIB_DIRS) $(LIBS)
