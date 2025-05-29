CC = gcc
CFLAGS = -Wall -Wextra -g -I./include
LDFLAGS = -lm

# Source files
SOURCES = src/keyplug_crypto.c src/keyplug_stego.c src/keyplug_autoexec.c src/keyplug_main.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = keyplug

# Default target
all: $(TARGET)

# Linking
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compiling
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Create samples directory
samples:
	mkdir -p samples

# Clean
clean:
	rm -f $(OBJECTS) $(TARGET)

# Install (for testing purposes only)
install: $(TARGET)
	mkdir -p $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/

.PHONY: all clean install samples
