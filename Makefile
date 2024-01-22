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
RM 	 := /bin/rm -f
MKDIR := /bin/mkdir -p


$(BINDIR)/$(TARGET): $(OBJECTS)
	@${MKDIR} $(@D)
	@$(LINKER) $(OBJECTS) $(LFLAGS) -o $@
	@echo "Linking complete!"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@${MKDIR} $(@D)
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully!"

.PHONY: build
build: $(OBJECTS)

.PHONY: all
all: build
all: $(BINDIR)/$(TARGET)

.PHONY: debug
debug: CFLAGS += -g -fno-inline -fno-omit-frame-pointer
debug: $(OBJECTS)
debug: $(BINDIR)/$(TARGET)

.PHONY: clean
clean:
	@${RM} -f $(OBJECTS)
	@$(RM) $(BINDIR)/$(TARGET)