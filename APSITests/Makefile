# Makefile for APSI tests
SRC_DIRS=
BIN_DIR=../bin
OBJ_DIR=obj
INCLUDE_DIRS=. ../APSI ../../SEAL-dev/SEAL /usr/include/flint ../../cryptoTools ../../Cuckoo/Cuckoo
SRCS=$(wildcard *.cpp) $(foreach d,$(SRC_DIRS),$(wildcard $d/*.cpp))
OBJS=$(SRCS:%.cpp=$(OBJ_DIR)/%.o)
DEPS=$(OBJS:.o=.d)
APSITESTEXE=unit_tests
CXX=g++
CXXFLAGS=-O0 -g -DHAVE_CONFIG -march=native -std=c++17  -maes -msse2 -msse4.1 -mpclmul -DNDEBUG -D_AMD64_ -D_AVX2_ -D_ASM_ -D__LINUX__
LDFLAGS=-lapsi -lseal -lcryptoTools -lflint -lpthread -lcppunit
LIBRARY_PATHS=-L../bin -L../../SEAL-dev/lib -L../../cryptoTools/lib

.PHONY : all clean

all : $(BIN_DIR)/$(APSITESTEXE)

$(OBJ_DIR)/%.d : %.cpp
	@-mkdir -p $(dir $@)
	@set -e; \
	rm -f $@; \
	$(CXX) -MM $< $(CXXFLAGS) -I. $(addprefix -I,$(INCLUDE_DIRS)) $(LIBRARY_PATHS)  $(LDFLAGS) > $@.temp; \
	SUBDIR_NAME=`echo $@|sed -e 's,\.,,' -e 's,$(SRC_DIRS),$(SRC_DIRS)/,'`; \
	sed 's,\($(*F)\)\.o[ :]*,$(OBJ_DIR)/$(SUBDIR_NAME)\1.o $@ : ,g' < $@.temp > $@; \
	rm -f $@.temp

$(OBJ_DIR)/%.o : %.cpp
	@-mkdir -p $(dir $@)
	$(CXX) -c $< $(CXXFLAGS) -I. $(addprefix -I,$(INCLUDE_DIRS)) $(LIBRARY_PATHS)  $(LDFLAGS) -o $@

$(BIN_DIR)/$(APSITESTEXE) : $(OBJS)
	@-mkdir -p $(dir $@)
	$(CXX) -o $(BIN_DIR)/$(APSITESTEXE) $(OBJS) $(LIBRARY_PATHS) $(LDFLAGS)

clean :
	@-rm -f $(BIN_DIR)/$(APSITESTEXE)
	@-rm -rf $(OBJ_DIR)

-include $(DEPS)
