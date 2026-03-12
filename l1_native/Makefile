# Feature Extractor (with -MMD for .h dependency tracking)
CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -O2 -std=c11 -I.. -I../sentinel_core -MMD -MP -D_FORTIFY_SOURCE=2 -fstack-protector-strong
AR      = ar
TARGET  = libfeatureextractor.a

SRCS    = feature_extractor.c
OBJS    = $(SRCS:.c=.o)
DEPS    = $(SRCS:.c=.d)
.DEFAULT_GOAL := all

-include $(DEPS)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)

.PHONY: all clean
