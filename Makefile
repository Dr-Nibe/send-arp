CC = gcc
CFLAGS = -lpcap
TARGET = send-arp

all: $(TARGET)

$(TARGET): send-arp.c
		$(CC) -o $(TARGET) send-arp.c $(CFLAGS)

clean:
		rm $(TARGET)