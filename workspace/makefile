CC      = g++
CFLAGS  = -Wall 
LDFLAGS = -lcrypto

BUILD_DIR    = bin/lnx/
INC_DIR      = ../common/inc
OPENSSL_DIR  =/usr/include/openssl


.PHONY: all clean install

all: set_1 set_2

set_1: challenge01 challenge02 challenge03 challenge04 challenge05 challenge06 challenge07 challenge08

set_2: challenge09 challenge10 challenge11 challenge12 challenge13 challenge14 challenge15 challenge16

challenge01: $(shell find ../01/ -name '*.cpp')
	$(CC) $(shell find ../01/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge01 

challenge02: $(shell find ../02/ -name '*.cpp')
	$(CC) $(shell find ../02/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge02

challenge03: $(shell find ../03/ -name '*.cpp')
	$(CC) $(shell find ../03/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge03

challenge04: $(shell find ../04/ -name '*.cpp')
	$(CC) $(shell find ../04/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge04

challenge05: $(shell find ../05/ -name '*.cpp')
	$(CC) $(shell find ../05/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge05

challenge06: $(shell find ../06/ -name '*.cpp')
	$(CC) $(shell find ../06/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge06

challenge07: $(shell find ../07/ -name '*.cpp')
	$(CC) $(shell find ../07/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge07

challenge08: $(shell find ../08/ -name '*.cpp')
	$(CC) $(shell find ../08/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge08 		

challenge09: $(shell find ../09/ -name '*.cpp')
	$(CC) $(shell find ../09/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge09 

challenge10: $(shell find ../10/ -name '*.cpp')
	$(CC) $(shell find ../10/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge10

challenge11: $(shell find ../11/ -name '*.cpp')
	$(CC) $(shell find ../11/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge11

challenge12: $(shell find ../12/ -name '*.cpp')
	$(CC) $(shell find ../12/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge12

challenge13: $(shell find ../13/ -name '*.cpp')
	$(CC) $(shell find ../13/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge13

challenge14: $(shell find ../14/ -name '*.cpp')
	$(CC) $(shell find ../14/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge14

challenge15: $(shell find ../15/ -name '*.cpp')
	$(CC) $(shell find ../15/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge15

challenge16: $(shell find ../16/ -name '*.cpp')
	$(CC) $(shell find ../16/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge16
    
challenge17: $(shell find ../17/ -name '*.cpp')
	$(CC) $(shell find ../17/ -name '*.cpp') $(CFLAGS) $(LDFLAGS) -I$(INC_DIR) -I$(OPENSSL_DIR) -o $(BUILD_DIR)challenge17		

clean: 
	rm -f $(BUILD_DIR)*

install:
	cp $(shell find ../ -name '*.txt') $(BUILD_DIR)
	cp $(shell find ../ -name '11.jpg') $(BUILD_DIR)
