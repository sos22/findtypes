CFLAGS+=-Wall -g
CPPFLAGS+=-Wall -g

all: ft ft.so

ft: main.o util.o ptrace.o emulate.o
	gcc -lstdc++ -o ft $^ /usr/local/lib/libVEX.a 

ft.so: dso.po
	gcc -shared -o $@ $^

dso.po: dso.c
	gcc -fPIC -c $(CFLAGS) -o $@ $^
