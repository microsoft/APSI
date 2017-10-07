CXX = g++
CFLAGS = -g  -march=native -std=c++11  -maes -msse2 -msse4.1 -mpclmul

INCLUDES =  -I../APSI/include/ -I../../Cuckoo/Cuckoo/include  -I../../SEAL-dev-new/SEAL/include/
LIB_DIRS = -L../bin/ -L../../SEAL-dev-new/bin/ -L../../Cuckoo/Cuckoo/src/ -L../../../libOTe/libs  -L../../../libOTe/cryptoTools/thirdparty/linux/boost/stage/lib/ -L../../../libOTe/cryptoTools/thirdparty/linux/miracl/miracl/source/
LIBS =  -lapsi -lseal -lcuckoo  -lcryptoTools -lmiracl -lboost_system -lboost_thread -pthread  

all:
	$(CXX)  receiver.cpp  $(CFLAGS) $(INCLUDES) $(LIB_DIRS) $(LIBS)
