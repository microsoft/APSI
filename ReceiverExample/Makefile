CXX = g++
CFLAGS = -g -Ofast -march=native -std=c++17  -maes -msse2 -msse4.1 -mpclmul -DNDEBUG

SRCS = receiver.cpp $(wildcard tests/*.cpp)
INCLUDES = -I. -I../APSI -I../../SEAL-dev/SEAL -I../../cryptoTools -I../../cryptoTools/thirdparty/linux/miracl -I/usr/include/flint -I../../Cuckoo/Cuckoo
LIB_DIRS = -L../bin -L../../SEAL-dev/lib -L../../cryptoTools/lib -L../../cryptoTools/thirdparty/linux/boost/stage/lib -L../../cryptoTools/thirdparty/linux/miracl/miracl/source -L/usr/lib -L../../Cuckoo/lib -L../../FourQlib/FourQ_64bit_and_portable
LIBS = -lapsi -lcuckoo -lseal -lcryptoTools -lmiracl -lboost_system -pthread -lgmp -lflint -lFourQ

all:
	$(CXX) -o receiver $(SRCS) $(CFLAGS) $(INCLUDES) $(LIB_DIRS) $(LIBS)
