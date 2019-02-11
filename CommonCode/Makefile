# Makefile for the APSI library
SRC_DIRS=
BIN_DIR=../bin
OBJ_DIR=obj
INCLUDE_DIRS=. ../APSI ../../SEAL/native/src /usr/include/flint ../../Cuckoo/Cuckoo ../../FourQlib/FourQ_64bit_and_portable
SRCS=$(wildcard *.cpp) $(foreach d,$(SRC_DIRS),$(wildcard $d/*.cpp))
OBJS=$(SRCS:%.cpp=$(OBJ_DIR)/%.o)
DEPS=$(OBJS:.o=.d)
INSTALL_DIR=APSI
BASELIB=libcommoncode.a
CXX=g++
CXXFLAGS=-O0 -g -DHAVE_CONFIG -DUSE_SECURE_SEED -march=native -std=c++17  -maes -msse2 -msse4.1 -mpclmul -DNDEBUG -D_AMD64_ -D_AVX2_ -D_ASM_ -D__LINUX__ -Wno-ignored-attributes
PREFIX=/usr/local
LDFLAGS=-lapsi
LIBRARY_PATHS=../bin

.PHONY : all clean install uninstall

all : $(BIN_DIR)/$(BASELIB)

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

$(BIN_DIR)/$(BASELIB) : $(OBJS)
	@-mkdir -p $(dir $@)
	ar rcs $(BIN_DIR)/$(BASELIB) $(OBJS)

clean :
	@-rm -f $(BIN_DIR)/$(BASELIB)
	@-rm -rf $(OBJ_DIR)

install : $(BIN_DIR)/$(BASELIB)
	@-mkdir -p $(PREFIX)/lib/$(INSTALL_DIR)
	@-mkdir -p $(PREFIX)/include/$(INSTALL_DIR)/util
	cp -f $(BIN_DIR)/$(BASELIB) $(PREFIX)/lib/$(INSTALL_DIR)/$(BASELIB)
	cp -f *.h $(PREFIX)/include/$(INSTALL_DIR)
	cp -f $(SRC_DIRS)/*.h $(PREFIX)/include/$(INSTALL_DIR)/$(SRC_DIRS)

uninstall :
	rm -rf $(PREFIX)/lib/$(INSTALL_DIR)
	rm -rf $(PREFIX)/include/$(INSTALL_DIR)

-include $(DEPS)
