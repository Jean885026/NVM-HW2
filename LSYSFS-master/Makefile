COMPILER = gcc
FILESYSTEM_FILES = lsysfs.c
LIBS = -lcrypto -lssl

build: $(FILESYSTEM_FILES)
	$(COMPILER) $(FILESYSTEM_FILES) -o lsysfs $(LIBS) `pkg-config fuse --cflags --libs`
	echo 'To Mount: ./lsysfs -f [mount point]'

clean:
	rm lsysfs

