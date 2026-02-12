default:
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c secp256k1/Int.cpp -o Int.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c secp256k1/Point.cpp -o Point.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c secp256k1/SECP256K1.cpp -o SECP256K1.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c secp256k1/IntMod.cpp -o IntMod.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c secp256k1/Random.cpp -o Random.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c hash/ripemd160.cpp -o hash/ripemd160.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c hash/sha256.cpp -o hash/sha256.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c hash/ripemd160_sse.cpp -o hash/ripemd160_sse.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c hash/sha256_sse.cpp -o hash/sha256_sse.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -o keyhunt keyhunt.cpp hash/ripemd160.o hash/ripemd160_sse.o hash/sha256.o hash/sha256_sse.o Int.o Point.o SECP256K1.o IntMod.o Random.o
	rm -r *.o */*.o
clean:
	rm -f keyhunt
run:
	./keyhunt
