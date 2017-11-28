all: compile

compile: libksmforce.so

libksmforce.so: libksmforce.c
	gcc -ggdb3 libksmforce.c -ldl -shared -fno-builtin-malloc -fPIC -o libksmforce.so
