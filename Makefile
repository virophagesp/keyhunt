default:
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c Int.cpp -o Int.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c Point.cpp -o Point.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c SECP256K1.cpp -o SECP256K1.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c IntMod.cpp -o IntMod.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c ripemd160.cpp -o ripemd160.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c sha256.cpp -o sha256.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c ripemd160_sse.cpp -o ripemd160_sse.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c sha256_sse.cpp -o sha256_sse.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -o keyhunt keyhunt.cpp ripemd160.o ripemd160_sse.o sha256.o sha256_sse.o Int.o Point.o SECP256K1.o IntMod.o
	rm -r *.o
clean:
	rm -f keyhunt
run:
	./keyhunt
