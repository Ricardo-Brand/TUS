.PHONY: all build exec clean create-dir test

all: clean create-dir format exec

build/headers.o: ./src/utils/headers.c ./include/headers.h
	@gcc -I/opt/homebrew/include -I./include -c ./src/utils/headers.c -o ./build/headers.o

build/tus-upload.o: ./src/middlewares/tus-upload.c ./include/tus-upload.h ./include/libbase58.h ./include/headers.h
	@gcc -I/opt/homebrew/include -I./include -c ./src/middlewares/tus-upload.c -o ./build/tus-upload.o

build/libbase58.o: ./src/base58.c ./include/libbase58.h
	@gcc -I/opt/homebrew/include -I./include -c ./src/base58.c -o ./build/libbase58.o

build/timer.o: ./src/utils/timer.c ./include/timer.h
	@gcc -I/opt/homebrew/include -I./include -c ./src/utils/timer.c -o ./build/timer.o

build/server: ./src/server.c build/headers.o build/tus-upload.o build/libbase58.o build/timer.o
	@gcc -I/opt/homebrew/include -I./include ./src/server.c ./build/timer.o ./build/headers.o ./build/tus-upload.o ./build/libbase58.o -L/opt/homebrew/lib -lssl -lcrypto -lmongoose -lblake3 -o ./build/server

create-dir: 
	@mkdir -p ./build ./tmp

clean: 
	@rm -rf ./build ./tmp

format: 
	@clang-format -i ./src/*.c ./src/middlewares/*.c ./tests/*.c ./src/utils/*.c

exec: build/server
	@./build/server

test: build/libbase58.o
	@gcc -I/opt/homebrew/include -I./include -L/opt/homebrew/lib ./build/libbase58.o ./tests/tests.c -lssl -lcrypto -lblake3 -ljansson -lmongoose  -o ./build/tests