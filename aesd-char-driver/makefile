CC ?= gcc
CFLAGS ?= -Wall -Wextra -g

TARGET := circular-buffer-dev
OBJS := circular-buffer-dev.o aesd-circular-buffer.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

circular-buffer-dev.o: circular-buffer-dev.c aesd-circular-buffer.h
	$(CC) $(CFLAGS) -c $< -o $@

aesd-circular-buffer.o: aesd-circular-buffer.c aesd-circular-buffer.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean