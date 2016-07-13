/* NOBS-IPS: A No-BS IPS patching tool */
/* by GreaseMonkey, 2016 - Public Domain */
/* usage: ./nobs-ips target.rom patch.ips */
/* compiling: cc -o nobs-ips nobs-ips.c */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define FAIL_CLOSE_ROM_FREAD \
	{ \
		if(errno != 0) { \
			perror("error: fread(patch)"); \
		} else { \
			fprintf(stderr, "error: premature EOF in patch\n"); \
		} \
		goto fail_close_rom; \
	}

#define FAIL_CLOSE_ROM_FGETC \
	{ \
		if(errno != 0) { \
			perror("error: fgetc(patch)"); \
		} else { \
			fprintf(stderr, "error: premature EOF in patch\n"); \
		} \
		goto fail_close_rom; \
	}

int main(int argc, char *argv[])
{
	long i;
	int v;
	long offset, size;
	char buf[8];
	const char *rom_fname;
	const char *patch_fname;
	FILE *rom_fp;
	FILE *patch_fp;

	/* Check arguments */
	if(argc-1 != 2) {
		fprintf(stderr,
			"usage:\n\t%s target.rom patch.ips\n",
			argv[0]);

		return 1;
	}

	/* Use nicer names for arguments */
	rom_fname = argv[1];
	patch_fname = argv[2];

	/* Open patch RO */
	patch_fp = fopen(patch_fname, "rb");
	if(patch_fp == NULL) {
		perror("error: fopen(patch)");
		goto fail_return;
	}

	/* Open ROM R/W */
	rom_fp = fopen(rom_fname, "r+b");
	if(rom_fp == NULL) {
		perror("error: fopen(rom)");
		goto fail_close_patch;
	}

	/* Read patch header */
	if(fread(buf, 5, 1, patch_fp) != 1 || memcmp(buf, "PATCH", 5)) {
		fprintf(stderr, "error: not a valid IPS patch\n");
		goto fail_close_rom;
	}

	/* Loop through patch records */
	for(;;) {
		/* Read start of patch */
		if(fread(buf, 3, 1, patch_fp) != 1) {
			FAIL_CLOSE_ROM_FREAD
		}

		/* If "EOF", stop here */
		if(!memcmp(buf, "EOF", 3)) {
			break;
		}

		/* Parse offset */
		offset = 0;
		offset |= (0xFF & (long)buf[0])<<16;
		offset |= (0xFF & (long)buf[1])<<8;
		offset |= (0xFF & (long)buf[2]);

		/* Read size */
		if(fread(buf, 2, 1, patch_fp) != 1) {
			FAIL_CLOSE_ROM_FREAD
		}

		/* Parse size */
		size = 0;
		size |= (0xFF & (long)buf[0])<<8;
		size |= (0xFF & (long)buf[1]);

		/* Seek */
		if(fseek(rom_fp, offset, SEEK_SET) != 0) {
			perror("fseek(rom)");
			goto fail_close_rom;
		}

		/* Check patch type */
		if(size != 0) {
			/* Raw patch */
			for(i = 0; i < size; i++) {
				v = fgetc(patch_fp);
				if(v < 0) {
					FAIL_CLOSE_ROM_FGETC
				}
				if(fputc(v, rom_fp) == EOF) {
					perror("error: fputc(rom)");
					goto fail_close_rom;
				}
			}

		} else {
			/* Fill patch (RLE) */
			/* Read rest of header */
			if(fread(buf, 3, 1, patch_fp) != 1) {
				FAIL_CLOSE_ROM_FREAD
			}

			/* Parse real size */
			size = 0;
			size |= (0xFF & (long)buf[0])<<8;
			size |= (0xFF & (long)buf[1]);

			/* Get byte to fill */
			v = buf[2];

			/* Apply patch */
			for(i = 0; i < size; i++) {
				if(fputc(v, rom_fp) == EOF) {
					perror("error: fputc(rom)");
					goto fail_close_rom;
				}
			}
		}
	}

	/* Success state cleanup code */
	fclose(rom_fp);
	fclose(patch_fp);
	return 0;

	/* Fail state cleanup code */
fail_close_rom:
	fclose(rom_fp);
fail_close_patch:
	fclose(patch_fp);
fail_return:
	return 1;
}

