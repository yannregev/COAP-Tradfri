TARGET   = tradfri.exe
LINKER   = gcc
CFLAGS	 = -Wall -g -Iinclude
LFLAGS   = -Wall -I. -lcrypto -lssl -lws2_32
CC	 = gcc

SRCDIR   = src
OBJDIR   = obj
BINDIR   = bin

SOURCES  := $(wildcard $(SRCDIR)/*.c)
INCLUDES := $(wildcard $(SRCDIR)/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
rm 	 := /bin/rm -f

$(BINDIR)/$(TARGET): $(OBJECTS)
	@$(LINKER) $(OBJECTS) $(LFLAGS) -o $@
	@echo "Linking complete!"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully!"

.PHONY: clean
clean:
	@${rm} -f $(OBJECTS)
	@$(rm) $(BINDIR)/$(TARGET)