CXX = g++
CFLAGS = -g -Ofast -march=native -std=c++17  -maes -msse2 -msse4.1 -mpclmul -DNDEBUG -Wno-ignored-attributes

SRCS = sender.cpp
INCLUDES = -I. -I../APSI -I../CommonCode -I../../SEAL-dev/SEAL -I/usr/include/flint -I../../Cuckoo/Cuckoo
LIB_DIRS = -L../bin -L../../SEAL-dev/lib -L/usr/lib -L../../Cuckoo/lib -L../../FourQlib/FourQ_64bit_and_portable
LIBS = -lapsi -lcommoncode -lcuckoo -lseal -pthread -lgmp -lflint -lFourQ -lcryptopp -lzmq -lzmqpp -llog4cplus -lstdc++fs

all:
	$(CXX) -o sender $(SRCS) $(CFLAGS) $(INCLUDES) $(LIB_DIRS) $(LIBS)
