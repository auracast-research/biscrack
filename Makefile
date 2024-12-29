CC=gcc
CFLAGS=-I. -g -O0 -msse2 -msse -march=native -maes -l popt
SRC_FILES=main.c bt_bis.c bt_crypto.c ccm_mode.c cmac_mode.c util.c utils.c

main: $(SRC_FILES)
	$(CC) $(CFLAGS) $(SRC_FILES) -o biscrack

clean:
	rm -f biscrack
