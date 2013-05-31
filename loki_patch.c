/*
 * loki_patch
 *
 * A utility to patch unsigned boot and recovery images to make
 * them suitable for booting on the AT&T and Verizon Samsung
 * Galaxy S4
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

#define VERSION "1.3"

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

struct target {
	char *vendor;
	char *build;
	unsigned long check_sigs;
	unsigned long hdr;
};

struct target targets[] = {
	{
		.vendor = "AT&T",
		.build = "JDQ39.I337UCUAMDB or JDQ39.I337UCUAMDL",
		.check_sigs = 0x88e0ff98,
		.hdr = 0x88f3bafc,
	},
	{
		.vendor = "Verizon",
		.build = "JDQ39.I545VRUAMDK",
		.check_sigs = 0x88e0fe98,
		.hdr = 0x88f372fc,
	},
	{
		.vendor = "DoCoMo",
		.build = "JDQ39.SC04EOMUAMDI",
		.check_sigs = 0x88e0fcd8,
		.hdr = 0x88f0b2fc,
	},
	{
		.vendor = "Verizon",
		.build = "IMM76D.I200VRALH2",
		.check_sigs = 0x88e0f5c0,
		.hdr = 0x88ed32e0,
	},
	{
		.vendor = "Verizon",
		.build = "JZO54K.I200VRBMA1",
		.check_sigs = 0x88e101ac,
		.hdr = 0x88ed72e0,
	}
};

#define PATTERN1 "\xf0\xb5\x8f\xb0\x06\x46\xf0\xf7"
#define PATTERN2 "\xf0\xb5\x8f\xb0\x07\x46\xf0\xf7"
#define PATTERN3 "\x2d\xe9\xf0\x41\x86\xb0\xf1\xf7"
#define ABOOT_BASE 0x88dfffd8

unsigned char patch[] =
"\xfe\xb5"
"\x0b\x4d"
"\xa8\x6a"
"\xab\x68"
"\x98\x42"
"\x0e\xd0"
"\xee\x69"
"\x09\x4c"
"\xef\x6a"
"\x07\xf5\x80\x57"
"\x0f\xce"
"\x0f\xc4"
"\x10\x3f"
"\xfb\xdc"
"\xa8\x6a"
"\x04\x49"
"\xea\x6a"
"\xa8\x60"
"\x69\x61"
"\x2a\x61"
"\x00\x20"
"\xfe\xbd"
"\x00\x00"
"\xff\xff\xff\xff"		/* Replace with header address */
"\x00\x00\x20\x82";

int patch_shellcode(unsigned int addr)
{

	int i;
	unsigned int *ptr;

	for (i = 0; i < sizeof(patch); i++) {
		ptr = (unsigned int *)&patch[i];
		if (*ptr == 0xffffffff) {
			*ptr = addr;
			return 0;
		}
	}

	return -1;
}

int main(int argc, char **argv)
{

	int ifd, ofd, aboot_fd, pos, i, recovery, offset;
	unsigned int orig_ramdisk_size, orig_kernel_size, page_kernel_size, page_ramdisk_size, page_size, page_mask;
	unsigned long target;
	void *orig, *aboot, *ptr;
	struct target *tgt;
	struct stat st;
	struct boot_img_hdr *hdr;
	struct loki_hdr *loki_hdr;
	char *buf;

	if (argc != 5) {
		printf("Usage: %s [boot|recovery] [aboot.img] [in.img] [out.lok]\n", argv[0]);
		return 1;
	}

	printf("[+] loki_patch v%s\n", VERSION);

	if (!strcmp(argv[1], "boot")) {
		recovery = 0;
	} else if (!strcmp(argv[1], "recovery")) {
		recovery = 1;
	} else {
		printf("[+] First argument must be \"boot\" or \"recovery\".\n");
		return 1;
	}

	/* Open input files */
	aboot_fd = open(argv[2], O_RDONLY);
	if (aboot_fd < 0) {
		printf("[-] Failed to open %s for reading.\n", argv[2]);
		return 1;
	}

	ifd = open(argv[3], O_RDONLY);
	if (ifd < 0) {
		printf("[-] Failed to open %s for reading.\n", argv[3]);
		return 1;
	}

	ofd = open(argv[4], O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (ofd < 0) {
		printf("[-] Failed to open %s for writing.\n", argv[4]);
		return 1;
	}

	/* Find the signature checking function via pattern matching */
	if (fstat(aboot_fd, &st)) {
		printf("[-] fstat() failed.\n");
		return 1;
	}

	aboot = mmap(0, (st.st_size + 0xfff) & ~0xfff, PROT_READ, MAP_PRIVATE, aboot_fd, 0);
	if (aboot == MAP_FAILED) {
		printf("[-] Failed to mmap aboot.\n");
		return 1;
	}

	target = 0;

	for (ptr = aboot; ptr < aboot + st.st_size - 0x1000; ptr++) {
		if (!memcmp(ptr, PATTERN1, 8) ||
			!memcmp(ptr, PATTERN2, 8) ||
			!memcmp(ptr, PATTERN3, 8)) {
			target = (unsigned long)ptr - (unsigned long)aboot + ABOOT_BASE;
			break;
		}
	}

	if (!target) {
		printf("[-] Failed to find function to patch.\n");
		return 1;
	}

	tgt = NULL;

	for (i = 0; i < (sizeof(targets)/sizeof(targets[0])); i++) {
		if (targets[i].check_sigs == target) {
			tgt = &targets[i];
			break;
		}
	}

	if (!tgt) {
		printf("[-] Unsupported aboot image.\n");
		return 1;
	}

	printf("[+] Detected target %s build %s\n", tgt->vendor, tgt->build);

	if (patch_shellcode(tgt->hdr) < 0) {
		printf("[-] Failed to patch shellcode.\n");
		return 1;
	}

	/* Map the original boot/recovery image */
	if (fstat(ifd, &st)) {
		printf("[-] fstat() failed.\n");
		return 1;
	}

	orig = mmap(0, (st.st_size + 0x2000 + 0xfff) & ~0xfff, PROT_READ|PROT_WRITE, MAP_PRIVATE, ifd, 0);
	if (orig == MAP_FAILED) {
		printf("[-] Failed to mmap input file.\n");
		return 1;
	}

	hdr = orig;
	loki_hdr = orig + 0x400;

	if (!memcmp(loki_hdr->magic, "LOKI", 4)) {
		printf("[-] Input file is already a Loki image.\n");

		/* Copy the entire file to the output transparently */
		if (write(ofd, orig, st.st_size) != st.st_size) {
			printf("[-] Failed to copy Loki image.\n");
			return 1;
		}

		printf("[+] Copied Loki image to %s.\n", argv[4]);

		return 0;
	}

	/* Set the Loki header */
	memcpy(loki_hdr->magic, "LOKI", 4);
	loki_hdr->recovery = recovery;
	strncpy(loki_hdr->build, tgt->build, sizeof(loki_hdr->build) - 1);

	page_size = hdr->page_size;
	page_mask = hdr->page_size - 1;

	orig_kernel_size = hdr->kernel_size;
	orig_ramdisk_size = hdr->ramdisk_size;

	/* Store the original values in uses fields of the header */
	hdr->dt_size = orig_kernel_size;
	hdr->unused = orig_ramdisk_size;
	hdr->second_addr = hdr->kernel_addr + ((hdr->kernel_size + page_mask) & ~page_mask);

	/* Ramdisk must be aligned to a page boundary */
	hdr->kernel_size = ((hdr->kernel_size + page_mask) & ~page_mask) + hdr->ramdisk_size;

	/* Guarantee 16-byte alignment */
	offset = tgt->check_sigs & 0xf;

	hdr->ramdisk_addr = tgt->check_sigs - offset;
	hdr->ramdisk_size = 0;

	/* Write the image header */
	if (write(ofd, orig, page_size) != page_size) {
		printf("[-] Failed to write header to output file.\n");
		return 1;
	}

	page_kernel_size = (orig_kernel_size + page_mask) & ~page_mask;

	/* Write the kernel */
	if (write(ofd, orig + page_size, page_kernel_size) != page_kernel_size) {
		printf("[-] Failed to write kernel to output file.\n");
		return 1;
	}

	page_ramdisk_size = (orig_ramdisk_size + page_mask) & ~page_mask;

	/* Write the ramdisk */
	if (write(ofd, orig + page_size + page_kernel_size, page_ramdisk_size) != page_ramdisk_size) {
		printf("[-] Failed to write ramdisk to output file.\n");
		return 1;
	}

	/* Write 0x800 bytes of original code to the output */
	buf = malloc(0x200);
	if (!buf) {
		printf("[-] Out of memory.\n");
		return 1;
	}

	lseek(aboot_fd, tgt->check_sigs - ABOOT_BASE - offset, SEEK_SET);
	read(aboot_fd, buf, 0x200);

	if (write(ofd, buf, 0x200) != 0x200) {
		printf("[-] Failed to write original aboot code to output file.\n");
		return 1;
	}

	pos = lseek(ofd, 0, SEEK_CUR);
	lseek(ofd, pos - (0x200 - offset), SEEK_SET);

	/* Write the patch */
	if (write(ofd, patch, sizeof(patch)) != sizeof(patch)) {
		printf("[-] Failed to write patch to output file.\n");
		return 1;
	}

	close(ifd);
	close(ofd);
	close(aboot_fd);

	printf("[+] Output file written to %s\n", argv[4]);

	return 0;
}
