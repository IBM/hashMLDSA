#
# Copyright 2025 IBM
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

OPENSSL_INSTALL_DIR=/opt/openssl
CC = gcc
CFLAGS = -fPIC
LDFLAGS = -shared
SRC = hashMLDSA.c
OBJ = hashMLDSA.o
TARGET_LIB = libhashmldsa.so
TEST_EXE = test_actions
TEST_EXE_2 = test_validation
TEST_SRC = test_actions.c testcases.h testutils.c testutils.h
TEST_SRC_2 = test_validation.c testutils.c testutils.h
INCLUDES = -I. -I$(OPENSSL_INSTALL_DIR)/include

# Required for aarch64 (arm) on linux
UNAME_M := $(shell uname -m)
LIBDIR := lib64
ifeq ($(UNAME_M), aarch64)
    LIBDIR := lib
endif

.PHONY: all clean

all: $(TARGET_LIB) $(TEST_EXE) $(TEST_EXE_2)

$(TARGET_LIB): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJ): $(SRC)
	$(CC) -g $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TEST_EXE): $(TEST_SRC) $(TARGET_LIB)
	$(CC) -g -L. -L$(OPENSSL_INSTALL_DIR)/${LIBDIR} -Wl,-rpath,. -Wl,-rpath,$(OPENSSL_INSTALL_DIR)/${LIBDIR} $(INCLUDES) -o $@ $(TEST_SRC) -lhashmldsa -lssl -lcrypto

$(TEST_EXE_2): $(TEST_SRC_2) $(TARGET_LIB)
	$(CC) -g -L. -L$(OPENSSL_INSTALL_DIR)/${LIBDIR} -Wl,-rpath,. -Wl,-rpath,$(OPENSSL_INSTALL_DIR)/${LIBDIR} $(INCLUDES) -o $@ $(TEST_SRC_2) -lhashmldsa -lssl -lcrypto

clean:
	rm -f $(OBJ) $(TARGET_LIB) $(TEST_EXE) $(TEST_EXE_2) test_actions.o test_validation.o hashMLDSA.o
