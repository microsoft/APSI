CXX = g++
CFLAGS = -DSEAL_DEBUG -g -O0 -march=native -std=c++14  -maes -msse2 -msse4.1 -mpclmul -DNDEBUG

SRCS = receiver.cpp $(wildcard tests/*.cpp)
INCLUDES = -I. -I../APSI -I../../SEAL-dev/SEAL -I../../Cuckoo/Cuckoo -I../../cryptoTools -I../../cryptoTools/thirdparty/linux/miracl -I/usr/include/flint
LIB_DIRS = -L../bin -L../../SEAL-dev/bin -L../../Cuckoo/bin -L../../cryptoTools/lib -L../../cryptoTools/thirdparty/linux/boost/stage/lib -L../../cryptoTools/thirdparty/linux/miracl/miracl/source -L/usr/lib
LIBS = -lapsi -lseal -lcuckoo -lcryptoTools -lmiracl -lboost_system -lpthread -lflint -lgmp

all:
	$(CXX) -o receiver $(SRCS) $(CFLAGS) $(INCLUDES) $(LIB_DIRS) $(LIBS)
