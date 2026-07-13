default:
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -o keyhunt keyhunt.cpp ripemd160.cpp ripemd160_sse.cpp sha256.cpp sha256_sse.cpp Int.cpp Point.cpp SECP256K1.cpp IntMod.cpp
clean:
	rm -f keyhunt
run:
	./keyhunt
