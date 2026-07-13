default:
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c secp256k1/Int.cpp -o Int.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c secp256k1/Point.cpp -o Point.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c secp256k1/SECP256K1.cpp -o SECP256K1.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c secp256k1/IntMod.cpp -o IntMod.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c hash/ripemd160.cpp -o ripemd160.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c hash/sha256.cpp -o sha256.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c hash/ripemd160_sse.cpp -o ripemd160_sse.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c hash/sha256_sse.cpp -o sha256_sse.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -o keyhunt keyhunt.cpp ripemd160.o ripemd160_sse.o sha256.o sha256_sse.o Int.o Point.o SECP256K1.o IntMod.o
	rm -r *.o
clean:
	rm -f keyhunt
run:
	./keyhunt
