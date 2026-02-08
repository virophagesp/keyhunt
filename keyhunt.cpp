/*
Develop by Alberto
email: albertobsd@gmail.com
*/

#include <math.h>
#include <inttypes.h>
#include "base58/libbase58.h"
#include "bloom/bloom.h"
#include "util.h"

#include "secp256k1/SECP256k1.h"
#include "secp256k1/IntGroup.h"

#include "hash/sha256.h"

#include <pthread.h>
#include <sys/random.h>

#define IMPORTANT "small_test"
//#define IMPORTANT "medium_test"
//#define IMPORTANT "big_test"
//#define IMPORTANT "money"

struct address_value	{
	uint8_t value[20];
};

struct tothread {
	int nt;     //Number thread
	char *rs;   //range start
	char *rpt;  //rng per thread
};

std::vector<Point> Gn;
Point _2Gn;

void init_generator();

void sleep_ms(int milliseconds);

void _sort(struct address_value *arr,int64_t N);
void _insertionsort(struct address_value *arr, int64_t n);
void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n);
int64_t _partition(struct address_value *arr, int64_t n);
void _myheapsort(struct address_value	*arr, int64_t n);

void writekey(bool compressed,Int *key);

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line);

void writeFileIfNeeded();

void *thread_process(void *vargp);

pthread_t *tid = NULL;

struct bloom bloom;

uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;

uint64_t N_SEQUENTIAL_MAX;

Int OUTPUTSECONDS;

Int stride;

uint64_t bytes;
struct address_value *addressTable;

const char *str_limits_prefixs[7] = {"Mkeys/s","Gkeys/s","Tkeys/s","Pkeys/s","Ekeys/s","Zkeys/s","Ykeys/s"};
const char *str_limits[7] = {"1000000","1000000000","1000000000000","1000000000000000","1000000000000000000","1000000000000000000000","1000000000000000000000000"};
Int int_limits[7];

Int ZERO;
Int MPZAUX;

Int n_range_start;
Int n_range_end;

Secp256K1 *secp;

int main()	{
	char buffer[2048];
	struct tothread *tt;	//tothread
	char *str_seconds = NULL;
	char *str_total = NULL;
	char *str_pretotal = NULL;
	char *str_divpretotal = NULL;
	uint64_t i;
	int continue_flag,check_flag,salir,j;
	Int total,pretotal,debugcount_mpz,seconds,div_pretotal,int_aux,int_r,int_q,int58;

	int s;

	size_t raw_value_length;
	uint8_t rawvalue[50];
	char aux[100];

	srand(time(NULL));

	secp = new Secp256K1();
	secp->Init();
	OUTPUTSECONDS.SetInt32(30);
	ZERO.SetInt32(0);

	unsigned long rseedvalue;
	getrandom(&rseedvalue, sizeof(unsigned long), GRND_NONBLOCK);
	rseed(rseedvalue);

	printf("[+] Version 0.5 bitcoin hunt, developed by virophagesp based upon 0.2.230519 Satoshi Quest by AlbertoBSD\n");

	stride.SetInt32(1);
	init_generator();

	printf("[+] Setting search for btc adddress\n");

	// sequential number option (putting this IMPORTANT here for easy finding )
	N_SEQUENTIAL_MAX = strtol("0x100000",NULL,16);
	printf("[+] N = %p\n",(void*)N_SEQUENTIAL_MAX);
	printf("[+] Range \n");

	// range
	if (IMPORTANT == "small_test") {
		n_range_start.SetBase16((char *)"8000");
		n_range_end.SetBase16((char *)"ffff");

		printf("[+] -- from : 0x8000\n");
		printf("[+] -- to   : 0xffff\n");
	} else if (IMPORTANT == "medium_test") {
		n_range_start.SetBase16((char *)"200000000");
		n_range_end.SetBase16((char *)"3ffffffff");

		printf("[+] -- from : 0x200000000\n");
		printf("[+] -- to   : 0x3ffffffff\n");
	} else if (IMPORTANT == "big_test") {
		n_range_start.SetBase16((char *)"100000000000000000");
		n_range_end.SetBase16((char *)"1fffffffffffffffff");

		printf("[+] -- from : 0x100000000000000000\n");
		printf("[+] -- to   : 0x1fffffffffffffffff\n");
	} else if (IMPORTANT == "money") {
		n_range_start.SetBase16((char *)"200000000000000000000");
		n_range_end.SetBase16((char *)"3ffffffffffffffffffff");

		printf("[+] -- from : 0x200000000000000000000\n");
		printf("[+] -- to   : 0x3ffffffffffffffffffff\n");
	}

	printf("[+] Allocating memory for 1 element: 0.00 MB\n");
	addressTable = (struct address_value*) malloc(20);
	if((void *)addressTable == NULL)	{
		fprintf(stderr,"[E] error in file %s, malloc pointer addressTable on line %i\n",__FILE__,__LINE__ -1 ); 
		exit(EXIT_FAILURE);
	}
	printf("[+] Bloom filter for 1 elements.\n");
	if(bloom_init2(&bloom) == 1){
		fprintf(stderr,"[E] error bloom_init for 10000 elements.\n");
		printf("[+] Loading data to the bloomfilter total: %.2f MB\n",(double)(((double) (&bloom)->bytes)/(double)1048576));
		fprintf(stderr,"[E] Unenexpected error\n");
		exit(EXIT_FAILURE);
	}
	printf("[+] Loading data to the bloomfilter total: %.2f MB\n",(double)(((double) (&bloom)->bytes)/(double)1048576));
	memset(aux,0,100);
	memset(addressTable[0].value,0,20);

	// address
	if (IMPORTANT == "small_test") {
		aux[0] = '1';
		aux[1] = 'B';
		aux[2] = 'D';
		aux[3] = 'y';
		aux[4] = 'r';
		aux[5] = 'Q';
		aux[6] = '6';
		aux[7] = 'W';
		aux[8] = 'o';
		aux[9] = 'F';
		aux[10] = '8';
		aux[11] = 'V';
		aux[12] = 'N';
		aux[13] = '3';
		aux[14] = 'g';
		aux[15] = '9';
		aux[16] = 'S';
		aux[17] = 'A';
		aux[18] = 'S';
		aux[19] = '1';
		aux[20] = 'i';
		aux[21] = 'K';
		aux[22] = 'Z';
		aux[23] = 'c';
		aux[24] = 'P';
		aux[25] = 'z';
		aux[26] = 'F';
		aux[27] = 'f';
		aux[28] = 'n';
		aux[29] = 'D';
		aux[30] = 'V';
		aux[31] = 'i';
		aux[32] = 'e';
		aux[33] = 'Y';
		aux[34] = '\0';
	} else if (IMPORTANT == "medium_test") {
		aux[0] = '1';
		aux[1] = 'P';
		aux[2] = 'W';
		aux[3] = 'A';
		aux[4] = 'B';
		aux[5] = 'E';
		aux[6] = '7';
		aux[7] = 'o';
		aux[8] = 'U';
		aux[9] = 'a';
		aux[10] = 'h';
		aux[11] = 'G';
		aux[12] = '2';
		aux[13] = 'A';
		aux[14] = 'F';
		aux[15] = 'F';
		aux[16] = 'Q';
		aux[17] = 'h';
		aux[18] = 'h';
		aux[19] = 'v';
		aux[20] = 'V';
		aux[21] = 'i';
		aux[22] = 'Q';
		aux[23] = 'o';
		aux[24] = 'v';
		aux[25] = 'n';
		aux[26] = 'C';
		aux[27] = 'r';
		aux[28] = '4';
		aux[29] = 'r';
		aux[30] = 'E';
		aux[31] = 'v';
		aux[32] = '7';
		aux[33] = 'Q';
		aux[34] = '\0';
	} else if (IMPORTANT == "big_test") {
		aux[0] = '1';
		aux[1] = '9';
		aux[2] = 'v';
		aux[3] = 'k';
		aux[4] = 'i';
		aux[5] = 'E';
		aux[6] = 'a';
		aux[7] = 'j';
		aux[8] = 'f';
		aux[9] = 'h';
		aux[10] = 'u';
		aux[11] = 'Z';
		aux[12] = '8';
		aux[13] = 'b';
		aux[14] = 's';
		aux[15] = '8';
		aux[16] = 'Z';
		aux[17] = 'u';
		aux[18] = '2';
		aux[19] = 'j';
		aux[20] = 'g';
		aux[21] = 'm';
		aux[22] = 'C';
		aux[23] = '6';
		aux[24] = 'o';
		aux[25] = 'q';
		aux[26] = 'Z';
		aux[27] = 'b';
		aux[28] = 'W';
		aux[29] = 'q';
		aux[30] = 'h';
		aux[31] = 'x';
		aux[32] = 'h';
		aux[33] = 'G';
		aux[34] = '\0';
	} else if (IMPORTANT == "money") {
		aux[0] = '1';
		aux[1] = '3';
		aux[2] = 'z';
		aux[3] = 'Y';
		aux[4] = 'r';
		aux[5] = 'Y';
		aux[6] = 'h';
		aux[7] = 'h';
		aux[8] = 'J';
		aux[9] = 'x';
		aux[10] = 'p';
		aux[11] = '6';
		aux[12] = 'U';
		aux[13] = 'i';
		aux[14] = '1';
		aux[15] = 'V';
		aux[16] = 'V';
		aux[17] = '7';
		aux[18] = 'p';
		aux[19] = 'q';
		aux[20] = 'a';
		aux[21] = '5';
		aux[22] = 'W';
		aux[23] = 'D';
		aux[24] = 'h';
		aux[25] = 'N';
		aux[26] = 'W';
		aux[27] = 'M';
		aux[28] = '4';
		aux[29] = '5';
		aux[30] = 'A';
		aux[31] = 'R';
		aux[32] = 'A';
		aux[33] = 'C';
		aux[34] = '\0';
	}
	raw_value_length = 25;
	b58tobin(rawvalue,&raw_value_length,aux);
	if(raw_value_length == 25)	{
		bloom_add(&bloom, rawvalue+1);
		memcpy(addressTable[0].value,rawvalue+1,20);
	}
	N = 1;
	printf("[+] Sorting data ...");
	_sort(addressTable,N);
	printf(" done! %" PRIu64 " values were loaded and sorted\n",N);
	writeFileIfNeeded();

	steps = (uint64_t *) calloc(1,sizeof(uint64_t));
	checkpointer((void *)steps,__FILE__,"calloc","steps" ,__LINE__ -1 );
	ends = (unsigned int *) calloc(1,sizeof(int));
	checkpointer((void *)ends,__FILE__,"calloc","ends" ,__LINE__ -1 );
	tid = (pthread_t *) calloc(1,sizeof(pthread_t));
	checkpointer((void *)tid,__FILE__,"calloc","tid" ,__LINE__ -1 );
	tt = (tothread*) malloc(sizeof(struct tothread));
	checkpointer((void *)tt,__FILE__,"malloc","tt" ,__LINE__ -1 );
	tt->nt = 0;
	steps[0] = 0;
	s = pthread_create(&tid[0],NULL,thread_process,(void *)tt);
	if(s != 0)	{
		fprintf(stderr,"[E] pthread_create thread_process\n");
		exit(EXIT_FAILURE);
	}

	for(j =0; j < 7; j++)	{
		int_limits[j].SetBase10((char*)str_limits[j]);
	}

	continue_flag = 1;
	total.SetInt32(0);
	pretotal.SetInt32(0);
	debugcount_mpz.SetInt32(0x400);
	seconds.SetInt32(0);
	do	{
		sleep_ms(1000);
		seconds.AddOne();
		check_flag = 1 & ends[0];
		if(check_flag)	{
			continue_flag = 0;
		}
		if(OUTPUTSECONDS.IsGreater(&ZERO) ){
			MPZAUX.Set(&seconds);
			MPZAUX.Mod(&OUTPUTSECONDS);
			if(MPZAUX.IsZero()) {
				total.SetInt32(0);

				pretotal.Set(&debugcount_mpz);
				pretotal.Mult(steps[0]);
				total.Add(&pretotal);

				total.Mult(2);

				pretotal.Set(&total);
				pretotal.Div(&seconds);
				str_seconds = seconds.GetBase10();
				str_pretotal = pretotal.GetBase10();
				str_total = total.GetBase10();

				if(pretotal.IsLower(&int_limits[0]))	{
					sprintf(buffer,"\r[+] Total %s keys in %s seconds: %s keys/s\r",str_total,str_seconds,str_pretotal);
				}
				else	{
					i = 0;
					salir = 0;
					while( i < 6 && !salir)	{
						if(pretotal.IsLower(&int_limits[i+1]))	{
							salir = 1;
						}
						else	{
							i++;
						}
					}

					div_pretotal.Set(&pretotal);
					div_pretotal.Div(&int_limits[salir ? i : i-1]);
					str_divpretotal = div_pretotal.GetBase10();
					sprintf(buffer,"\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)\r",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
					free(str_divpretotal);

				}
				printf("%s",buffer);
				fflush(stdout);

				free(str_seconds);
				free(str_pretotal);
				free(str_total);
			}
		}
	}while(continue_flag);
	printf("\nEnd\n");
}

void rmd160toaddress_dst(char *rmd,char *dst){
	char digest[60];
	digest[0] = 0x00;
	memcpy(digest+1,rmd,20);
	sha256((uint8_t*)digest, 21,(uint8_t*) digest+21);
	sha256((uint8_t*)digest+21, 32,(uint8_t*) digest+21);
	if(!b58enc(dst,digest)){
		fprintf(stderr,"error b58enc\n");
	}
}

int searchbinary(struct address_value *buffer,char *data,int64_t array_length) {
	int64_t half,min,max,current;
	int r = 0,rcmp;
	min = 0;
	current = 0;
	max = array_length;
	half = array_length;
	while(!r && half >= 1) {
		half = (max - min)/2;
		rcmp = memcmp(data,buffer[current+half].value,20);
		if(rcmp == 0)	{
			r = 1;	//Found!!
		}
		else	{
			if(rcmp < 0) { //data < temp_read
				max = (max-half);
			}
			else	{ // data > temp_read
				min = (min+half);
			}
			current = min;
		}
	}
	return r;
}

void *thread_process(void *vargp)	{
	struct tothread *tt;
	Point pts[1024];
	Point endomorphism_beta[1024];
	Point endomorphism_beta2[1024];
	Point endomorphism_negeted_point[4];

	Int dx[513];
	IntGroup *grp = new IntGroup(513);
	Point startP;
	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Point pp;
	Point pn;
	int i,l,pp_offset,pn_offset,hLength = (511);
	uint64_t j,count;
	Point R,temporal,publickey;
	int r,thread_number,continue_flag = 1,k;
	char *hextemp = NULL;

	char publickeyhashrmd160[20];

	char publickeyhashrmd160_endomorphism[12][4][20];

	Int key_mpz,keyfound,temp_stride;
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);
	grp->Set(dx);

	do {
		if(n_range_start.IsLower(&n_range_end))	{
			key_mpz.Set(&n_range_start);
			n_range_start.Add(N_SEQUENTIAL_MAX);
		}
		else	{
			continue_flag = 0;
		}
		if(continue_flag)	{
			count = 0;
			hextemp = key_mpz.GetBase16();
			printf("\rBase key: %s     \r",hextemp);
			fflush(stdout);
			free(hextemp);
			do {
				temp_stride.SetInt32(512);
				temp_stride.Mult(&stride);
				key_mpz.Add(&temp_stride);
	 			startP = secp->ComputePublicKey(&key_mpz);
				key_mpz.Sub(&temp_stride);

				for(i = 0; i < hLength; i++) {
					dx[i].ModSub(&Gn[i].x,&startP.x);
				}

				dx[i].ModSub(&Gn[i].x,&startP.x);  // For the first point
				dx[i + 1].ModSub(&_2Gn.x,&startP.x); // For the next center point
				grp->ModInv();

				pts[512] = startP;

				for(i = 0; i<hLength; i++) {
					pp = startP;
					pn = startP;

					// P = startP + i*G
					dy.ModSub(&Gn[i].y,&pp.y);

					_s.ModMulK1(&dy,&dx[i]);        // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
					_p.ModSquareK1(&_s);            // _p = pow2(s)

					pp.x.ModNeg();
					pp.x.ModAdd(&_p);
					pp.x.ModSub(&Gn[i].x);           // rx = pow2(s) - p1.x - p2.x;

					// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
					dyn.Set(&Gn[i].y);
					dyn.ModNeg();
					dyn.ModSub(&pn.y);

					_s.ModMulK1(&dyn,&dx[i]);      // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
					_p.ModSquareK1(&_s);            // _p = pow2(s)
					pn.x.ModNeg();
					pn.x.ModAdd(&_p);
					pn.x.ModSub(&Gn[i].x);          // rx = pow2(s) - p1.x - p2.x;

					pp_offset = 512 + (i + 1);
					pn_offset = 512 - (i + 1);

					pts[pp_offset] = pp;
					pts[pn_offset] = pn;
				}

				// First point (startP - (GRP_SZIE/2)*G)
				pn = startP;
				dyn.Set(&Gn[i].y);
				dyn.ModNeg();
				dyn.ModSub(&pn.y);

				_s.ModMulK1(&dyn,&dx[i]);
				_p.ModSquareK1(&_s);

				pn.x.ModNeg();
				pn.x.ModAdd(&_p);
				pn.x.ModSub(&Gn[i].x);

				pts[0] = pn;

				for(j = 0; j < 256;j++){
					secp->GetHash160_fromX(P2PKH,0x02,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[0][0],(uint8_t*)publickeyhashrmd160_endomorphism[0][1],(uint8_t*)publickeyhashrmd160_endomorphism[0][2],(uint8_t*)publickeyhashrmd160_endomorphism[0][3]);
					secp->GetHash160_fromX(P2PKH,0x03,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[1][0],(uint8_t*)publickeyhashrmd160_endomorphism[1][1],(uint8_t*)publickeyhashrmd160_endomorphism[1][2],(uint8_t*)publickeyhashrmd160_endomorphism[1][3]);

					for(k = 0; k < 4;k++)	{
						for(l = 0;l < 2; l++)	{
							r = bloom_check(&bloom,publickeyhashrmd160_endomorphism[l][k]);
							if(r) {
								r = searchbinary(addressTable,publickeyhashrmd160_endomorphism[l][k],N);
								if(r) {
									keyfound.SetInt32(k);
									keyfound.Mult(&stride);
									keyfound.Add(&key_mpz);

									publickey = secp->ComputePublicKey(&keyfound);
									secp->GetHash160(P2PKH,true,publickey,(uint8_t*)publickeyhashrmd160);
									if(memcmp(publickeyhashrmd160_endomorphism[l][k],publickeyhashrmd160,20) != 0)	{
										keyfound.Neg();
										keyfound.Add(&secp->order);
									}
									writekey(true,&keyfound);
								}
							}
						}
					}
					count+=4;
					temp_stride.SetInt32(4);
					temp_stride.Mult(&stride);
					key_mpz.Add(&temp_stride);
				}

				steps[thread_number]++;

				// Next start point (startP + GRP_SIZE*G)
				pp = startP;
				dy.ModSub(&_2Gn.y,&pp.y);

				_s.ModMulK1(&dy,&dx[i + 1]);
				_p.ModSquareK1(&_s);

				pp.x.ModNeg();
				pp.x.ModAdd(&_p);
				pp.x.ModSub(&_2Gn.x);

				//The Y value for the next start point always need to be calculated
				pp.y.ModSub(&_2Gn.x,&pp.x);
				pp.y.ModMulK1(&_s);
				pp.y.ModSub(&_2Gn.y);
				startP = pp;
			}while(count < N_SEQUENTIAL_MAX && continue_flag);
		}
	} while(continue_flag);
	ends[thread_number] = 1;
	return NULL;
}

void _swap(struct address_value *a,struct address_value *b)	{
	struct address_value t;
	t  = *a;
	*a = *b;
	*b =  t;
}

void _sort(struct address_value *arr,int64_t n)	{
	uint32_t depthLimit = ((uint32_t) ceil(log(n))) * 2;
	_introsort(arr,depthLimit,n);
}

void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n) {
	int64_t p;
	if(n > 1)	{
		if(n <= 16) {
			_insertionsort(arr,n);
		}
		else	{
			if(depthLimit == 0) {
				_myheapsort(arr,n);
			}
			else	{
				p = _partition(arr,n);
				if(p > 0) _introsort(arr , depthLimit-1 , p);
				if(p < n) _introsort(&arr[p+1],depthLimit-1,n-(p+1));
			}
		}
	}
}

void _insertionsort(struct address_value *arr, int64_t n) {
	int64_t j;
	int64_t i;
	struct address_value key;
	for(i = 1; i < n ; i++ ) {
		key = arr[i];
		j= i-1;
		while(j >= 0 && memcmp(arr[j].value,key.value,20) > 0) {
			arr[j+1] = arr[j];
			j--;
		}
		arr[j+1] = key;
	}
}

int64_t _partition(struct address_value *arr, int64_t n)	{
	struct address_value pivot;
	int64_t r,left,right;
	r = n/2;
	pivot = arr[r];
	left = 0;
	right = n-1;
	do {
		while(left	< right && memcmp(arr[left].value,pivot.value,20) <= 0 )	{
			left++;
		}
		while(right >= left && memcmp(arr[right].value,pivot.value,20) > 0)	{
			right--;
		}
		if(left < right)	{
			if(left == r || right == r)	{
				if(left == r)	{
					r = right;
				}
				if(right == r)	{
					r = left;
				}
			}
			_swap(&arr[right],&arr[left]);
		}
	}while(left < right);
	if(right != r)	{
		_swap(&arr[right],&arr[r]);
	}
	return right;
}

void _heapify(struct address_value *arr, int64_t n, int64_t i) {
	int64_t largest = i;
	int64_t l = 2 * i + 1;
	int64_t r = 2 * i + 2;
	if (l < n && memcmp(arr[l].value,arr[largest].value,20) > 0)
		largest = l;
	if (r < n && memcmp(arr[r].value,arr[largest].value,20) > 0)
		largest = r;
	if (largest != i) {
		_swap(&arr[i],&arr[largest]);
		_heapify(arr, n, largest);
	}
}

void _myheapsort(struct address_value	*arr, int64_t n)	{
	int64_t i;
	for ( i = (n / 2) - 1; i >=	0; i--)	{
		_heapify(arr, n, i);
	}
	for ( i = n - 1; i > 0; i--) {
		_swap(&arr[0] , &arr[i]);
		_heapify(arr, i, 0);
	}
}

void sleep_ms(int milliseconds)	{ // cross-platform sleep function
#if _POSIX_C_SOURCE >= 199309L
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
#else
    if (milliseconds >= 1000)
      sleep(milliseconds / 1000);
    usleep((milliseconds % 1000) * 1000);
#endif
}

void init_generator()	{
	Point G = secp->ComputePublicKey(&stride);
	Point g;
	g.Set(G);
	Gn.reserve(512);
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for(int i = 2; i < 512; i++) {
		g = secp->AddDirect(g,G);
		Gn[i] = g;
	}
	_2Gn = secp->DoubleDirect(Gn[511]);
}

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line)	{
	if(ptr == NULL)	{
		fprintf(stderr,"[E] error in file %s, %s pointer %s on line %i\n",file,function,name,line); 
		exit(EXIT_FAILURE);
	}
}

void writekey(bool compressed,Int *key)	{
	Point publickey;
	FILE *keys;
	char *hextemp,*hexrmd,public_key_hex[132],address[50],rmdhash[20];
	memset(address,0,50);
	memset(public_key_hex,0,132);
	hextemp = key->GetBase16();
	publickey = secp->ComputePublicKey(key);
	secp->GetPublicKeyHex(compressed,publickey,public_key_hex);
	secp->GetHash160(P2PKH,compressed,publickey,(uint8_t*)rmdhash);
	hexrmd = tohex(rmdhash,20);
	rmd160toaddress_dst(rmdhash,address);

	keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
	if(keys != NULL)	{
		fprintf(keys,"Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);
		fclose(keys);
	}
	printf("\nHit! Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);

	free(hextemp);
	free(hexrmd);
}

void writeFileIfNeeded()	{
	FILE *fileDescriptor;
	char fileBloomName[30];
	char dataChecksum[32],bloomChecksum[32];
	size_t bytesWrite;
	uint64_t dataSize;
	// file bloom name
	if (IMPORTANT == "small_test") {
		fileBloomName[0] = 'd';
		fileBloomName[1] = 'a';
		fileBloomName[2] = 't';
		fileBloomName[3] = 'a';
		fileBloomName[4] = '_';
		fileBloomName[5] = '5';
		fileBloomName[6] = '9';
		fileBloomName[7] = '6';
		fileBloomName[8] = 'd';
		fileBloomName[9] = '6';
		fileBloomName[10] = 'f';
		fileBloomName[11] = '1';
		fileBloomName[12] = '2';
		fileBloomName[13] = '.';
		fileBloomName[14] = 'd';
		fileBloomName[15] = 'a';
		fileBloomName[16] = 't';
		fileBloomName[17] = '\0';
	} else if (IMPORTANT == "medium_test") {
		fileBloomName[0] = 'd';
		fileBloomName[1] = 'a';
		fileBloomName[2] = 't';
		fileBloomName[3] = 'a';
		fileBloomName[4] = '_';
		fileBloomName[5] = '2';
		fileBloomName[6] = '4';
		fileBloomName[7] = 'f';
		fileBloomName[8] = '4';
		fileBloomName[9] = '0';
		fileBloomName[10] = '4';
		fileBloomName[11] = '9';
		fileBloomName[12] = 'c';
		fileBloomName[13] = '.';
		fileBloomName[14] = 'd';
		fileBloomName[15] = 'a';
		fileBloomName[16] = 't';
		fileBloomName[17] = '\0';
	} else if (IMPORTANT == "big_test") {
		fileBloomName[0] =  'd';
		fileBloomName[1] =  'a';
		fileBloomName[2] =  't';
		fileBloomName[3] =  'a';
		fileBloomName[4] =  '_';
		fileBloomName[5] =  '9';
		fileBloomName[6] =  '5';
		fileBloomName[7] =  'a';
		fileBloomName[8] =  '7';
		fileBloomName[9] =  'd';
		fileBloomName[10] = '8';
		fileBloomName[11] = '6';
		fileBloomName[12] = '1';
		fileBloomName[13] = '.';
		fileBloomName[14] = 'd';
		fileBloomName[15] = 'a';
		fileBloomName[16] = 't';
		fileBloomName[17] = '\0';
	} else if (IMPORTANT == "money") {
		fileBloomName[0] =  'd';
		fileBloomName[1] =  'a';
		fileBloomName[2] =  't';
		fileBloomName[3] =  'a';
		fileBloomName[4] =  '_';
		fileBloomName[5] =  '6';
		fileBloomName[6] =  'f';
		fileBloomName[7] =  '6';
		fileBloomName[8] =  'e';
		fileBloomName[9] =  '6';
		fileBloomName[10] = 'e';
		fileBloomName[11] = 'a';
		fileBloomName[12] = '2';
		fileBloomName[13] = '.';
		fileBloomName[14] = 'd';
		fileBloomName[15] = 'a';
		fileBloomName[16] = 't';
		fileBloomName[17] = '\0';
	}
	fileDescriptor = fopen(fileBloomName,"wb");
	dataSize = N * 20;
	printf("[D] size data %li\n",dataSize);
	if(fileDescriptor != NULL)	{
		printf("[+] Writing file %s ",fileBloomName);

		//calculate bloom checksum
		//write bloom checksum (expected value to be checked)
		//write bloom filter structure
		//write bloom filter data

		//calculate dataChecksum
		//write data checksum (expected value to be checked)
		//write data size
		//write data

		sha256((uint8_t*)bloom.bf,bloom.bytes,(uint8_t*)bloomChecksum);
		printf(".");
		bytesWrite = fwrite(bloomChecksum,1,32,fileDescriptor);
		if(bytesWrite != 32)	{
			fprintf(stderr,"[E] Errore writing file, code line %i\n",__LINE__ - 2);
			exit(EXIT_FAILURE);
		}
		printf(".");

		bytesWrite = fwrite(&bloom,1,sizeof(struct bloom),fileDescriptor);
		if(bytesWrite != sizeof(struct bloom))	{
			fprintf(stderr,"[E] Error writing file, code line %i\n",__LINE__ - 2);
			exit(EXIT_FAILURE);
		}
		printf(".");

		bytesWrite = fwrite(bloom.bf,1,bloom.bytes,fileDescriptor);
		if(bytesWrite != bloom.bytes)	{
			fprintf(stderr,"[E] Error writing file, code line %i\n",__LINE__ - 2);
			fclose(fileDescriptor);
			exit(EXIT_FAILURE);
		}
		printf(".");

		sha256((uint8_t*)addressTable,dataSize,(uint8_t*)dataChecksum);
		printf(".");

		bytesWrite = fwrite(dataChecksum,1,32,fileDescriptor);
		if(bytesWrite != 32)	{
			fprintf(stderr,"[E] Errore writing file, code line %i\n",__LINE__ - 2);
			exit(EXIT_FAILURE);
		}
		printf(".");

		bytesWrite = fwrite(&dataSize,1,sizeof(uint64_t),fileDescriptor);
		if(bytesWrite != sizeof(uint64_t))	{
			fprintf(stderr,"[E] Errore writing file, code line %i\n",__LINE__ - 2);
			exit(EXIT_FAILURE);
		}
		printf(".");

		bytesWrite = fwrite(addressTable,1,dataSize,fileDescriptor);
		if(bytesWrite != dataSize)	{
			fprintf(stderr,"[E] Error writing file, code line %i\n",__LINE__ - 2);
			exit(EXIT_FAILURE);
		}
		printf(".");

		fclose(fileDescriptor);
		printf("\n");
	}
}
