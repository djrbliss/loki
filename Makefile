SRC_FLASH := loki_flash.c
OBJ_FLASH = $(SRC_FLASH:.c=.o)
MODULE_FLASH := loki_flash

SRC_PATCH := loki_patch.c
OBJ_PATCH = $(SRC_PATCH:.c=.o)
MODULE_PATCH := loki_patch

SRC_FIND := loki_find.c
OBJ_FIND = $(SRC_FIND:.c=.o)
MODULE_FIND := loki_find

ALL_MODULES := $(MODULE_FLASH) $(MODULE_PATCH) $(MODULE_FIND)

CC := arm-linux-androideabi-gcc
CC_STRIP := arm-linux-androideabi-strip

CFLAGS += -g -static -Wall
#$(LDFLAGS) +=


all: $(ALL_MODULES)

$(MODULE_FLASH): $(OBJ_FLASH)
	$(CC) $(CFLAGS) $(OBJ_FLASH) -o $(MODULE_FLASH) $(LDFLAGS)

$(MODULE_PATCH): $(OBJ_PATCH)
	$(CC) $(CFLAGS) -o $(MODULE_PATCH) $(OBJ_PATCH) $(LDFLAGS)

$(MODULE_FIND): $(OBJ_FIND)
	$(CC) $(CFLAGS) -o $(MODULE_FIND) $(OBJ_FIND) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

strip:
	$(CC_STRIP) --strip-unneeded $(ALL_MODULES)
	$(CC_STRIP) --strip-debug $(ALL_MODULES)

clean:
	rm -f *.o
	rm -f loki_flash loki_patch
