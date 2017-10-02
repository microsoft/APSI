# Makefile for the SEAL library
UTIL_DIR=src src/Network src/Receiver src/Sender src/Tools
BIN_DIR=../bin
OBJ_DIR=obj
INCLUDE_DIRS=include ../thirdparty/boost ../../Cuckoo/Cuckoo/include ../../SEAL-dev-new/SEAL/include 
SRCS=$(wildcard *.cpp) $(foreach d,$(UTIL_DIR),$(wildcard $d/*.cpp))
OBJS=$(SRCS:%.cpp=$(OBJ_DIR)/%.o)
DEPS=$(OBJS:.o=.d)
INSTALL_DIR=APSI
APSILIB=libapsi.a
CXX=g++
CXXFLAGS=-O3 -DHAVE_CONFIG -march=native -std=c++11
PREFIX=/usr/local
LDFLAGS=-lseal -lboost_system -lcuckoo -lpthread
LIBRARY_PATHS=../../SEAL-dev-new/bin ../../Cuckoo/bin ../thirdparty/boost/stage/lib

.PHONY : all clean install uninstall

all : $(BIN_DIR)/$(APSILIB)

$(OBJ_DIR)/%.d : %.cpp
	@-mkdir -p $(dir $@)
	@set -e; \
	rm -f $@; \
	$(CXX) -MM $< $(CXXFLAGS) -I. $(addprefix -I,$(INCLUDE_DIRS)) $(addprefix -L,$(LIBRARY_PATHS))  $(LDFLAGS) > $@.temp; \
	SUBDIR_NAME=`echo $@|sed -e 's,\.,,' -e 's,$(UTIL_DIR),$(UTIL_DIR)/,'`; \
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
	cp -f $(UTIL_DIR)/*.h $(PREFIX)/include/$(INSTALL_DIR)/$(UTIL_DIR)

uninstall :
	rm -rf $(PREFIX)/lib/$(INSTALL_DIR)
	rm -rf $(PREFIX)/include/$(INSTALL_DIR)

-include $(DEPS)
