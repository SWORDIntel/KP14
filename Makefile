CC = gcc
CFLAGS = -Wall -Wextra -g -std=c99
LDFLAGS = -lm

# Source files for the unified parser
SOURCES = jpeg_parser_phase1.c jpeg_parser_phase2.c jpeg_parser_phase3.c jpeg_parser_phase4.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = jpeg_parser_unified

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
