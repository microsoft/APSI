# Makefile for the APSI library
SRC_DIRS=apsi apsi/network apsi/receiver apsi/sender apsi/tools apsi/ffield apsi/logging
BIN_DIR=../bin
OBJ_DIR=obj
INCLUDE_DIRS=. ../../SEAL-dev/SEAL /usr/include/flint ../../Cuckoo/Cuckoo ../../FourQlib/FourQ_64bit_and_portable
SRCS=$(wildcard *.cpp) $(foreach d,$(SRC_DIRS),$(wildcard $d/*.cpp))
OBJS=$(SRCS:%.cpp=$(OBJ_DIR)/%.o)
DEPS=$(OBJS:.o=.d)
INSTALL_DIR=APSI
APSILIB=libapsi.a
CXX=g++
CXXFLAGS=-O0 -g -DHAVE_CONFIG -DUSE_SECURE_SEED -march=native -std=c++17  -maes -msse2 -msse4.1 -mpclmul -DNDEBUG -D_AMD64_ -D_AVX2_ -D_ASM_ -D__LINUX__ -Wno-ignored-attributes
PREFIX=/usr/local
LDFLAGS=-lseal -lcuckoo -lpthread -lflint -lgmp -lFourQ
LIBRARY_PATHS=../../SEAL-dev/bin /usr/lib ../../FourQlib/FourQ_64bit_and_portable

.PHONY : all clean install uninstall

all : $(BIN_DIR)/$(APSILIB)

$(OBJ_DIR)/%.d : %.cpp
	@-mkdir -p $(dir $@)
	@set -e; \
	rm -f $@; \
	$(CXX) -MM $< $(CXXFLAGS) -I. $(addprefix -I,$(INCLUDE_DIRS)) $(addprefix -L,$(LIBRARY_PATHS))  $(LDFLAGS) > $@.temp; \
	SUBDIR_NAME=`echo $@|sed -e 's,\.,,' -e 's,$(SRC_DIRS),$(SRC_DIRS)/,'`; \
	sed 's,\($(*F)\)\.o[ :]*,$(OBJ_DIR)/$(SUBDIR_NAME)\1.o $@ : ,g' < $@.temp > $@; \
	rm -f $@.temp

$(OBJ_DIR)/%.o : %.cpp
	@-mkdir -p $(dir $@)
	$(CXX) -c $< $(CXXFLAGS) -I. $(addprefix -I,$(INCLUDE_DIRS)) $(addprefix -L,$(LIBRARY_PATHS))  $(LDFLAGS) -o $@

$(BIN_DIR)/$(APSILIB) : $(OBJS)
	@-mkdir -p $(dir $@)
	ar rcs $(BIN_DIR)/$(APSILIB) $(OBJS)

clean :
	@-rm -f $(BIN_DIR)/$(APSILIB)
	@-rm -rf $(OBJ_DIR)

install : $(BIN_DIR)/$(APSILIB)
	@-mkdir -p $(PREFIX)/lib/$(INSTALL_DIR)
	@-mkdir -p $(PREFIX)/include/$(INSTALL_DIR)/util
	cp -f $(BIN_DIR)/$(APSILIB) $(PREFIX)/lib/$(INSTALL_DIR)/$(APSILIB)
	cp -f *.h $(PREFIX)/include/$(INSTALL_DIR)
	cp -f $(SRC_DIRS)/*.h $(PREFIX)/include/$(INSTALL_DIR)/$(SRC_DIRS)

uninstall :
	rm -rf $(PREFIX)/lib/$(INSTALL_DIR)
	rm -rf $(PREFIX)/include/$(INSTALL_DIR)

-include $(DEPS)
