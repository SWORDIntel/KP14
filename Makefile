CC = gcc
CFLAGS = -Wall -Wextra -g -std=c99
LDFLAGS = -lm

# It's important to use the exact filenames as they appear in the filesystem.
# However, make has issues with colons in filenames.
# This Makefile assumes the files will be renamed or symlinked
# to versions without colons before compilation.
# For example:
# "JPEG Parser in C - Phase 1: Marker Parsing.c" -> "jpeg_parser_phase1.c"
# "JPEG Parser in C - Phase 2: Huffman Decoding.c" -> "jpeg_parser_phase2.c"
# "JPEG Parser in C - Phase 3: DCT Reconstruction.c" -> "jpeg_parser_phase3.c"
# "JPEG Parser in C - Phase 4: DCT Encoding & Writing.c" -> "jpeg_parser_phase4.c"
#
# The user will need to perform this renaming/symlinking step manually.

RENAMED_SOURCES = jpeg_parser_phase1.c jpeg_parser_phase2.c jpeg_parser_phase3.c jpeg_parser_phase4.c
# OBJECTS = $(RENAMED_SOURCES:.c=.o) # Not needed if we compile one executable per source
TARGETS = $(RENAMED_SOURCES:.c=)

all: $(TARGETS)

# Rule to create an executable from a .c file
# Example: jpeg_parser_phase1 from jpeg_parser_phase1.c
%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# This rule is now more specific if we keep .o files for some reason,
# but the rule above is sufficient for one executable per .c file.
# %.o: %.c
#	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGETS) *.o # Also remove any stray .o files

.PHONY: all clean
