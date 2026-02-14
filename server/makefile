CC       ?= gcc
CFLAGS   ?= -O2 -Wall
LDFLAGS  ?=

TARGET   := aesdsocket
SRCS     := aesdsocket.c
OBJS     := $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(OBJS) $(TARGET)