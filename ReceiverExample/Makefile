CXX = g++
CFLAGS = -g -O3 -march=native -std=c++14  -maes -msse2 -msse4.1 -mpclmul

INCLUDES = -I../APSI -I../../SEAL-dev/SEAL -I../../Cuckoo/Cuckoo -I../../cryptoTools -I../../cryptoTools/thirdparty/linux/miracl
LIB_DIRS = -L../bin -L../../SEAL-dev/bin -L../../Cuckoo/bin -L../../cryptoTools/lib -L../../cryptoTools/thirdparty/linux/boost/stage/lib -L../../cryptoTools/thirdparty/linux/miracl/miracl/source 
LIBS = -lapsi -lseal -lcuckoo -lcryptoTools -lmiracl -lboost_system -lpthread

all:
	$(CXX) -o receiver receiver.cpp  $(CFLAGS) $(INCLUDES) $(LIB_DIRS) $(LIBS)
