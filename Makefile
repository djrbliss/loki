MODULES_FLASH := loki_flash.o
MODULES_PATCH := loki_patch.o
MODULES := $(MODULES_FLASH) $(MODULES_PATCH)

CC := /root/Desktop/build_cm10/ndk_toolchain_r9/bin/arm-linux-androideabi-gcc
CFLAGS += -g -static -Wall
#$(LDFLAGS) := 

MAKEARCH := $(CC) $(CFLAGS)

all: loki_flash loki_patch

loki_flash: $(MODULES_FLASH)
	$(MAKEARCH) $(MODULES_FLASH) -o loki_flash $(LDFLAGS)

loki_patch: $(MODULES_PATCH)
	$(MAKEARCH) $(MODULES_PATCH) -o loki_patch $(LDFLAGS)

clean:
	rm -f *.o
	rm -f loki_flash loki_patch
