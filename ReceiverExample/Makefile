CXX = g++
CFLAGS = -g -Ofast -march=native -std=c++17  -maes -msse2 -msse4.1 -mpclmul -DNDEBUG

SRCS = receiver.cpp
INCLUDES = -I. -I../APSI -I../../SEAL-dev/SEAL -I/usr/include/flint -I../../Cuckoo/Cuckoo
LIB_DIRS = -L../bin -L../../SEAL-dev/lib -L/usr/lib -L../../Cuckoo/lib -L../../FourQlib/FourQ_64bit_and_portable
LIBS = -lapsi -lcuckoo -lseal -lboost_system -pthread -lgmp -lflint -lFourQ -lcryptopp -lzmq -lzmqpp

all:
	$(CXX) -o receiver $(SRCS) $(CFLAGS) $(INCLUDES) $(LIB_DIRS) $(LIBS)
