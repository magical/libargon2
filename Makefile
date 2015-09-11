#
# Argon2 source code package
# 
# This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
# 
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
#


REF_CFLAGS = -std=c99 -pthread -O3
OPT_CFLAGS = -std=c99 -pthread -O3 -m64 -mavx


ARGON2_DIR = Source/Argon2
CORE_DIR = Source/Core
BLAKE2_DIR = Source/Blake2
TEST_DIR = Source/Test
COMMON_DIR = Source/Common

ARGON2_SOURCES = argon2.c
CORE_SOURCES = argon2-core.c kat.c
BLAKE2_SOURCES = blake2b-ref.c
TEST_SOURCES = argon2-test.c

REF_CORE_SOURCE = argon2-ref-core.c
OPT_CORE_SOURCE = argon2-opt-core.c


BUILD_DIR = Build


LIBNAME=argon2


ARGON2_BUILD_SOURCES = $(addprefix $(ARGON2_DIR)/,$(ARGON2_SOURCES))
CORE_BUILD_SOURCES = $(addprefix $(CORE_DIR)/,$(CORE_SOURCES))
BLAKE2_BUILD_SOURCES = $(addprefix $(BLAKE2_DIR)/,$(BLAKE2_SOURCES))
TEST_BUILD_SOURCES = $(addprefix $(TEST_DIR)/,$(TEST_SOURCES))


#OPT=TRUE
ifeq ($(OPT), TRUE)
    CFLAGS=$(OPT_CFLAGS)
    CORE_BUILD_SOURCES += $(CORE_DIR)/$(OPT_CORE_SOURCE)
else
    CFLAGS=$(REF_CFLAGS)
    CORE_BUILD_SOURCES += $(CORE_DIR)/$(REF_CORE_SOURCE)
endif


ARGON2_OBJECTS = $(ARGON2_BUILD_SOURCES:.c=.o)
CORE_OBJECTS =  $(CORE_BUILD_SOURCES:.c=.o)
BLAKE2_OBJECTS = $(BLAKE2_BUILD_SOURCES:.c=.o)
TEST_OBJECTS = $(TEST_BUILD_SOURCES:.c=.o)

INCLUDES= -I$(ARGON2_DIR) -I$(CORE_DIR) -I$(BLAKE2_DIR) -I$(TEST_DIR) -I$(COMMON_DIR)

.PHONY: all
all: argon2 argon2-tv argon2-lib argon2-lib-test
argon2: $(BUILD_DIR)/argon2
argon2-tv: $(BUILD_DIR)/argon2-tv
argon2-lib: $(BUILD_DIR)/lib$(LIBNAME).so
argon2-lib-test: $(BUILD_DIR)/argon2-lib-test

%.o: %.c
	@echo CC $@
	@$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(BUILD_DIR)/argon2: $(ARGON2_OBJECTS) $(CORE_OBJECTS) $(BLAKE2_OBJECTS) $(TEST_OBJECTS)
	$(CC) $(CFLAGS) \
		$(INCLUDES) \
		-o $@ $^


$(BUILD_DIR)/argon2-tv: $(ARGON2_OBJECTS) $(CORE_OBJECTS) $(BLAKE2_OBJECTS) $(TEST_OBJECTS)
	$(CC) $(CFLAGS) \
		-DKAT -DKAT_INTERNAL \
		$(INCLUDES) \
		-o $@ $^


$(BUILD_DIR)/libargon2.so: $(ARGON2_BUILD_SOURCES) $(CORE_BUILD_SOURCES) $(BLAKE2_BUILD_SOURCES)
	$(CC) $(CFLAGS) \
		-shared -fPIC \
		$(INCLUDES) \
		$(ARGON2_BUILD_SOURCES) \
		$(CORE_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		-o $@


$(BUILD_DIR)/argon2-lib-test: $(TEST_OBJECTS) argon2-lib
	$(CC) $(CFLAGS) \
		-I$(ARGON2_DIR) \
		-I$(TEST_DIR) \
		-L$(BUILD_DIR) \
		-Wl,-rpath=$(BUILD_DIR) \
		-l$(LIBNAME) \
		-o $@ \
		$(TEST_OBJECTS)


.PHONY: clean
clean:
	rm -f $(BUILD_DIR)/*
