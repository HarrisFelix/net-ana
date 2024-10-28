CFLAGS=-Wall
OBJ=$(patsubst %.c,%.o,$(wildcard *.c))
TARGET=analyzer

all: main

main: $(OBJ)
	$(CC) $(CFLAGS) -lpcap -o $(TARGET) $(OBJ)

debug: $(OBJ)
	$(CC) -g $(CFLAGS) -lpcap -o $(TARGET) $(OBJ)

clean:
	rm $(OBJ) main

test: main
	 ./$(TARGET) -i en0 -v 1

# si un .h ou le Makefile change tout recompiler :
$(OBJ): $(wildcard *.h) Makefile
