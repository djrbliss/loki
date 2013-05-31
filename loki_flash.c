/*
 * loki_flash
 *
 * A sample utility to validate and flash .lok files
 *
 * by Dan Rosenberg (@djrbliss)
 *
 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define VERSION "1.2"

#define BOOT_MAGIC_SIZE 8
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512

struct boot_img_hdr
{
	unsigned char magic[BOOT_MAGIC_SIZE];
	unsigned kernel_size;	/* size in bytes */
	unsigned kernel_addr;	/* physical load addr */
	unsigned ramdisk_size;	/* size in bytes */
	unsigned ramdisk_addr;	/* physical load addr */
	unsigned second_size;	/* size in bytes */
	unsigned second_addr;	/* physical load addr */
	unsigned tags_addr;		/* physical addr for kernel tags */
	unsigned page_size;		/* flash page size we assume */
	unsigned dt_size;		/* device_tree in bytes */
	unsigned unused;		/* future expansion: should be 0 */
	unsigned char name[BOOT_NAME_SIZE];	/* asciiz product name */
	unsigned char cmdline[BOOT_ARGS_SIZE];
	unsigned id[8];			/* timestamp / checksum / sha1 / etc */
};

struct loki_hdr
{
	unsigned char magic[4];		/* 0x494b4f4c */
	unsigned int recovery;		/* 0 = boot.img, 1 = recovery.img */
	unsigned char build[128];	/* Build number */
};

#define PATTERN1 "\xf0\xb5\x8f\xb0\x06\x46\xf0\xf7"
#define PATTERN2 "\xf0\xb5\x8f\xb0\x07\x46\xf0\xf7"
#define PATTERN3 "\x2d\xe9\xf0\x41\x86\xb0\xf1\xf7"
#define ABOOT_BASE 0x88dfffd8

int main(int argc, char **argv)
{

	int ifd, aboot_fd, ofd, recovery, offs, match;
	void *orig, *aboot, *patch;
	struct stat st;
	struct boot_img_hdr *hdr;
	struct loki_hdr *loki_hdr;
	char prop[256], outfile[1024], buf[4096];

	if (argc != 3) {
		printf("[+] Usage: %s [boot|recovery] [in.lok]\n", argv[0]);
		return 1;
	}

	printf("[+] loki_flash v%s\n", VERSION);

	if (!strcmp(argv[1], "boot")) {
		recovery = 0;
	} else if (!strcmp(argv[1], "recovery")) {
		recovery = 1;
	} else {
		printf("[+] First argument must be \"boot\" or \"recovery\".\n");
		return 1;
	}

	/* Verify input file */
	aboot_fd = open("/dev/block/platform/msm_sdcc.1/by-name/aboot", O_RDONLY);
	if (aboot_fd < 0) {
		printf("[-] Failed to open aboot for reading.\n");
		return 1;
	}

	ifd = open(argv[2], O_RDONLY);
	if (ifd < 0) {
		printf("[-] Failed to open %s for reading.\n", argv[2]);
		return 1;
	}

	/* Map the image to be flashed */
	if (fstat(ifd, &st)) {
		printf("[-] fstat() failed.\n");
		return 1;
	}

	orig = mmap(0, (st.st_size + 0x2000 + 0xfff) & ~0xfff, PROT_READ, MAP_PRIVATE, ifd, 0);
	if (orig == MAP_FAILED) {
		printf("[-] Failed to mmap Loki image.\n");
		return 1;
	}

	hdr = orig;
	loki_hdr = orig + 0x400;

	/* Verify this is a Loki image */
	if (memcmp(loki_hdr->magic, "LOKI", 4)) {
		printf("[-] Input file is not a Loki image.\n");
		return 1;
	}

	/* Verify this is the right type of image */
	if (loki_hdr->recovery != recovery) {
		printf("[-] Loki image is not a %s image.\n", recovery ? "recovery" : "boot");
		return 1;
	}

	/* Verify the to-be-patched address matches the known code pattern */
	aboot = mmap(0, 0x10000, PROT_READ, MAP_PRIVATE, aboot_fd, 0);
	if (aboot == MAP_FAILED) {
		printf("[-] Failed to mmap aboot.\n");
		return 1;
	}

	match = 0;

	for (offs = 0; offs < 0x10; offs += 0x4) {

		patch = hdr->ramdisk_addr - ABOOT_BASE + aboot + offs;

		if (!memcmp(patch, PATTERN1, 8) ||
			!memcmp(patch, PATTERN2, 8) ||
			!memcmp(patch, PATTERN3, 8)) {

			match = 1;
			break;
		}
	}

	if (!match) {
		printf("[-] Loki aboot version does not match device.\n");
		return 1;
	}

	printf("[+] Loki validation passed, flashing image.\n");

	snprintf(outfile, sizeof(outfile),
			 "/dev/block/platform/msm_sdcc.1/by-name/%s",
			 recovery ? "recovery" : "boot");

	ofd = open(outfile, O_WRONLY);
	if (ofd < 0) {
		printf("[-] Failed to open output block device.\n");
		return 1;
	}

	if (write(ofd, orig, st.st_size) != st.st_size) {
		printf("[-] Failed to write to block device.\n");
		return 1;
	}

	printf("[+] Loki flashing complete!\n");

	close(ifd);
	close(aboot_fd);
	close(ofd);

	return 0;
}
