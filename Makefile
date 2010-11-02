CFLAGS+=-Wall -g

all: ft ft.so

ft: main.o util.o ptrace.o
	gcc -o ft $^

ft.so: dso.po
	gcc -shared -o $@ $^

dso.po: dso.c
	gcc -fPIC -c $(CFLAGS) -o $@ $^
