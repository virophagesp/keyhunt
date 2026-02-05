/*
Develop by Alberto
email: albertobsd@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
#include "base58/libbase58.h"
#include "bloom/bloom.h"
#include "sha3/sha3.h"
#include "util.h"

#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "secp256k1/IntGroup.h"
#include "secp256k1/Random.h"

#include "hash/sha256.h"
#include "hash/ripemd160.h"

#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>

#include <linux/random.h>

struct checksumsha256	{
	char data[32];
	char backup[32];
};

struct address_value	{
	uint8_t value[20];
};

struct tothread {
	int nt;     //Number thread
	char *rs;   //range start
	char *rpt;  //rng per thread
};

struct __attribute__((__packed__)) publickey {
  uint8_t parity;
	union	{
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
};

const char *version = "0.2.230519 Satoshi Quest";

#define CPU_GRP_SIZE 1024

std::vector<Point> Gn;
Point _2Gn;

std::vector<Point> GSn;
Point _2GSn;

void init_generator();

int searchbinary(struct address_value *buffer,char *data,int64_t array_length);
void sleep_ms(int milliseconds);

void _sort(struct address_value *arr,int64_t N);
void _insertionsort(struct address_value *arr, int64_t n);
void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n);
void _swap(struct address_value *a,struct address_value *b);
int64_t _partition(struct address_value *arr, int64_t n);
void _myheapsort(struct address_value	*arr, int64_t n);
void _heapify(struct address_value *arr, int64_t n, int64_t i);

void writekey(bool compressed,Int *key);

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line);

bool isBase58(char c);
bool isValidBase58String(char *str);

bool readFileAddress(char *fileName);
bool forceReadFileAddress(char *fileName);

bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom);

void writeFileIfNeeded(const char *fileName);

void calcualteindex(int i,Int *key);

void *thread_process(void *vargp);

void rmd160toaddress_dst(char *rmd,char *dst);

void KECCAK_256(uint8_t *source, size_t size,uint8_t *dst);

int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *cryptos[3] = {"btc","all"};
const char *publicsearch[3] = {"uncompress","compress","both"};
const char *default_fileName = "addresses.txt";

pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
pthread_mutex_t bsgs_thread;

uint8_t byte_encode_crypto = 0x00;		/* Bitcoin  */

struct bloom bloom;

uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;

uint64_t N_SEQUENTIAL_MAX = 0x100000000;
uint64_t DEBUGCOUNT = 0x400;

Int OUTPUTSECONDS;

int FLAGBLOOMMULTIPLIER = 1;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;

int FLAGREADEDFILE1 = 0;

int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGFILE = 0;
int FLAG_N = 0;

int bitrange;
char *str_N;
char *range_start;
char *range_end;
Int stride;

uint64_t bytes;
struct address_value *addressTable;

const char *str_limits_prefixs[7] = {"Mkeys/s","Gkeys/s","Tkeys/s","Pkeys/s","Ekeys/s","Zkeys/s","Ykeys/s"};
const char *str_limits[7] = {"1000000","1000000000","1000000000000","1000000000000000","1000000000000000000","1000000000000000000000","1000000000000000000000000"};
Int int_limits[7];

Int BSGS_GROUP_SIZE;
Int BSGS_N;
Int BSGS_M3;				//M3 is M2/32
Int BSGS_M3_double;			//M3_double is M3 * 2

Int ONE;
Int ZERO;
Int MPZAUX;

Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int n_range_aux;

Secp256K1 *secp;

int main(int argc, char **argv)	{
	char buffer[2048];
	struct tothread *tt;	//tothread
	Tokenizer t;	//tokenizer
	char *fileName = NULL;
	char *hextemp = NULL;
	char *str_seconds = NULL;
	char *str_total = NULL;
	char *str_pretotal = NULL;
	char *str_divpretotal = NULL;
	uint64_t i;
	int continue_flag,check_flag,c,salir,j;
	Int total,pretotal,debugcount_mpz,seconds,div_pretotal,int_aux,int_r,int_q,int58;

	pthread_mutex_init(&write_keys,NULL);
	pthread_mutex_init(&write_random,NULL);
	pthread_mutex_init(&bsgs_thread,NULL);
	int s;

	srand(time(NULL));

	secp = new Secp256K1();
	secp->Init();
	OUTPUTSECONDS.SetInt32(30);
	ZERO.SetInt32(0);
	ONE.SetInt32(1);
	BSGS_GROUP_SIZE.SetInt32(CPU_GRP_SIZE);

	unsigned long rseedvalue;
	int bytes_read = getrandom(&rseedvalue, sizeof(unsigned long), GRND_NONBLOCK);
	if(bytes_read > 0)	{
		rseed(rseedvalue);
		/*
		In any case that seed is for a failsafe RNG, the default source on linux is getrandom function
		See https://www.2uo.de/myths-about-urandom/
		*/
	}
	else	{
		/*
			what year is??
			WTF linux without RNG ? 
		*/
		fprintf(stderr,"[E] Error getrandom() ?\n");
		exit(EXIT_FAILURE);
		rseed(clock() + time(NULL) + rand()*rand());
	}

	printf("[+] Version %s, developed by AlbertoBSD\n",version);

	while ((c = getopt(argc, argv, "b:E:f:N:n:p:r:s:")) != -1) {
		switch(c) {
			case 'b':
				bitrange = strtol(optarg,NULL,10);
				if(bitrange > 0 && bitrange <=256 )	{
					MPZAUX.Set(&ONE);
					MPZAUX.ShiftL(bitrange-1);
					bit_range_str_min = MPZAUX.GetBase16();
					checkpointer((void *)bit_range_str_min,__FILE__,"malloc","bit_range_str_min" ,__LINE__ -1);
					MPZAUX.Set(&ONE);
					MPZAUX.ShiftL(bitrange);
					if(MPZAUX.IsGreater(&secp->order))	{
						MPZAUX.Set(&secp->order);
					}
					bit_range_str_max = MPZAUX.GetBase16();
					checkpointer((void *)bit_range_str_max,__FILE__,"malloc","bit_range_str_min" ,__LINE__ -1);
					FLAGBITRANGE = 1;
				}
				else	{
					fprintf(stderr,"[E] invalid bits param: %s.\n",optarg);
				}
			break;
			case 'f':
				FLAGFILE = 1;
				fileName = optarg;
			break;

			case 'n':
				FLAG_N = 1;
				str_N = optarg;
			break;
			case 'r':
				if(optarg != NULL)	{
					stringtokenizer(optarg,&t);
					switch(t.n)	{
						case 1:
							range_start = nextToken(&t);
							if(isValidHex(range_start)) {
								FLAGRANGE = 1;
								range_end = secp->order.GetBase16();
							}
							else	{
								fprintf(stderr,"[E] Invalid hexstring : %s.\n",range_start);
							}
						break;
						case 2:
							range_start = nextToken(&t);
							range_end	 = nextToken(&t);
							if(isValidHex(range_start) && isValidHex(range_end)) {
									FLAGRANGE = 1;
							}
							else	{
								if(isValidHex(range_start)) {
									fprintf(stderr,"[E] Invalid hexstring : %s\n",range_start);
								}
								else	{
									fprintf(stderr,"[E] Invalid hexstring : %s\n",range_end);
								}
							}
						break;
						default:
							printf("[E] Unknow number of Range Params: %i\n",t.n);
						break;
					}
				}
			break;
			case 's':
				OUTPUTSECONDS.SetBase10(optarg);
				if(OUTPUTSECONDS.IsLower(&ZERO))	{
					OUTPUTSECONDS.SetInt32(30);
				}
				if(OUTPUTSECONDS.IsZero())	{
					printf("[+] Turn off stats output\n");
				}
				else	{
					hextemp = OUTPUTSECONDS.GetBase10();
					printf("[+] Stats output every %s seconds\n",hextemp);
					free(hextemp);
				}
			break;
			default:
				fprintf(stderr,"[E] Unknow opcion -%c\n",c);
				exit(EXIT_FAILURE);
			break;
		}
	}

	stride.Set(&ONE);
	init_generator();

	if(FLAGFILE == 0) {
		fileName =(char*) default_fileName;
	}

	printf("[+] Setting search for btc adddress\n");
	if(FLAGRANGE) {
		n_range_start.SetBase16(range_start);
		if(n_range_start.IsZero())	{
			n_range_start.AddOne();
		}
		n_range_end.SetBase16(range_end);
		if(n_range_start.IsEqual(&n_range_end) == false ) {
			if(  n_range_start.IsLower(&secp->order) &&  n_range_end.IsLowerOrEqual(&secp->order) )	{
				if( n_range_start.IsGreater(&n_range_end)) {
					fprintf(stderr,"[W] Opps, start range can't be great than end range. Swapping them\n");
					n_range_aux.Set(&n_range_start);
					n_range_start.Set(&n_range_end);
					n_range_end.Set(&n_range_aux);
				}
				n_range_diff.Set(&n_range_end);
				n_range_diff.Sub(&n_range_start);
			}
			else	{
				fprintf(stderr,"[E] Start and End range can't be great than N\nFallback to random mode!\n");
				FLAGRANGE = 0;
			}
		}
		else	{
			fprintf(stderr,"[E] Start and End range can't be the same\nFallback to random mode!\n");
			FLAGRANGE = 0;
		}
	}
	BSGS_N.SetInt32(DEBUGCOUNT);
	if(FLAGRANGE == 0 && FLAGBITRANGE == 0)	{
		n_range_start.SetInt32(1);
		n_range_end.Set(&secp->order);
		n_range_diff.Set(&n_range_end);
		n_range_diff.Sub(&n_range_start);
	}
	else	{
		if(FLAGBITRANGE)	{
			n_range_start.SetBase16(bit_range_str_min);
			n_range_end.SetBase16(bit_range_str_max);
			n_range_diff.Set(&n_range_end);
			n_range_diff.Sub(&n_range_start);
		}
		else	{
			if(FLAGRANGE == 0)	{
				fprintf(stderr,"[W] WTF!\n");
			}
		}
	}
	N = 0;

	if(FLAG_N){
		if(str_N[0] == '0' && str_N[1] == 'x')	{
			N_SEQUENTIAL_MAX =strtol(str_N,NULL,16);
		}
		else	{
			N_SEQUENTIAL_MAX =strtol(str_N,NULL,10);
		}

		if(N_SEQUENTIAL_MAX < 1024)	{
			fprintf(stderr,"[I] n value need to be equal or great than 1024, back to defaults\n");
			FLAG_N = 0;
			N_SEQUENTIAL_MAX = 0x100000000;
		}
		if(N_SEQUENTIAL_MAX % 1024 != 0)	{
			fprintf(stderr,"[I] n value need to be multiplier of  1024\n");
			FLAG_N = 0;
			N_SEQUENTIAL_MAX = 0x100000000;
		}
	}
	printf("[+] N = %p\n",(void*)N_SEQUENTIAL_MAX);
	if(FLAGBITRANGE)	{	// Bit Range
		printf("[+] Bit Range %i\n",bitrange);
	}
	else	{
		printf("[+] Range \n");
	}
	hextemp = n_range_start.GetBase16();
	printf("[+] -- from : 0x%s\n",hextemp);
	free(hextemp);
	hextemp = n_range_end.GetBase16();
	printf("[+] -- to   : 0x%s\n",hextemp);
	free(hextemp);

	if(!readFileAddress(fileName))	{
		fprintf(stderr,"[E] Unenexpected error\n");
		exit(EXIT_FAILURE);
	}

	if(!FLAGREADEDFILE1)	{
		printf("[+] Sorting data ...");
		_sort(addressTable,N);
		printf(" done! %" PRIu64 " values were loaded and sorted\n",N);
		writeFileIfNeeded(fileName);
	}

	steps = (uint64_t *) calloc(NTHREADS,sizeof(uint64_t));
	checkpointer((void *)steps,__FILE__,"calloc","steps" ,__LINE__ -1 );
	ends = (unsigned int *) calloc(NTHREADS,sizeof(int));
	checkpointer((void *)ends,__FILE__,"calloc","ends" ,__LINE__ -1 );
	tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
	checkpointer((void *)tid,__FILE__,"calloc","tid" ,__LINE__ -1 );
	for(j= 0;j < NTHREADS; j++)	{
		tt = (tothread*) malloc(sizeof(struct tothread));
		checkpointer((void *)tt,__FILE__,"malloc","tt" ,__LINE__ -1 );
		tt->nt = j;
		steps[j] = 0;
		s = pthread_create(&tid[j],NULL,thread_process,(void *)tt);
		if(s != 0)	{
			fprintf(stderr,"[E] pthread_create thread_process\n");
			exit(EXIT_FAILURE);
		}
	}

	for(j =0; j < 7; j++)	{
		int_limits[j].SetBase10((char*)str_limits[j]);
	}

	continue_flag = 1;
	total.SetInt32(0);
	pretotal.SetInt32(0);
	debugcount_mpz.Set(&BSGS_N);
	seconds.SetInt32(0);
	do	{
		sleep_ms(1000);
		seconds.AddOne();
		check_flag = 1;
		for(j = 0; j <NTHREADS && check_flag; j++) {
			check_flag &= ends[j];
		}
		if(check_flag)	{
			continue_flag = 0;
		}
		if(OUTPUTSECONDS.IsGreater(&ZERO) ){
			MPZAUX.Set(&seconds);
			MPZAUX.Mod(&OUTPUTSECONDS);
			if(MPZAUX.IsZero()) {
				total.SetInt32(0);
				for(j = 0; j < NTHREADS; j++) {
					pretotal.Set(&debugcount_mpz);
					pretotal.Mult(steps[j]);
					total.Add(&pretotal);
				}

				total.Mult(2);

				pthread_mutex_lock(&bsgs_thread);
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
					if(THREADOUTPUT == 1)	{
						sprintf(buffer,"\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)\r",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
					}
					else	{
						sprintf(buffer,"\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)\r",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
					}
					free(str_divpretotal);

				}
				printf("%s",buffer);
				fflush(stdout);
				THREADOUTPUT = 0;
				pthread_mutex_unlock(&bsgs_thread);

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
	size_t pubaddress_size = 40;
	digest[0] = byte_encode_crypto;
	memcpy(digest+1,rmd,20);
	sha256((uint8_t*)digest, 21,(uint8_t*) digest+21);
	sha256((uint8_t*)digest+21, 32,(uint8_t*) digest+21);
	if(!b58enc(dst,&pubaddress_size,digest,25)){
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
	Point pts[CPU_GRP_SIZE];
	Point endomorphism_beta[CPU_GRP_SIZE];
	Point endomorphism_beta2[CPU_GRP_SIZE];
	Point endomorphism_negeted_point[4];

	Int dx[CPU_GRP_SIZE / 2 + 1];
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Point pp;
	Point pn;
	int i,l,pp_offset,pn_offset,hLength = (CPU_GRP_SIZE / 2 - 1);
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
			pthread_mutex_lock(&write_random);
			key_mpz.Set(&n_range_start);
			n_range_start.Add(N_SEQUENTIAL_MAX);
			pthread_mutex_unlock(&write_random);
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
			THREADOUTPUT = 1;
			do {
				temp_stride.SetInt32(CPU_GRP_SIZE / 2);
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

				pts[CPU_GRP_SIZE / 2] = startP;

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

					pp_offset = CPU_GRP_SIZE / 2 + (i + 1);
					pn_offset = CPU_GRP_SIZE / 2 - (i + 1);

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

				for(j = 0; j < CPU_GRP_SIZE/4;j++){
					secp->GetHash160_fromX(P2PKH,0x02,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[0][0],(uint8_t*)publickeyhashrmd160_endomorphism[0][1],(uint8_t*)publickeyhashrmd160_endomorphism[0][2],(uint8_t*)publickeyhashrmd160_endomorphism[0][3]);
					secp->GetHash160_fromX(P2PKH,0x03,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[1][0],(uint8_t*)publickeyhashrmd160_endomorphism[1][1],(uint8_t*)publickeyhashrmd160_endomorphism[1][2],(uint8_t*)publickeyhashrmd160_endomorphism[1][3]);

					for(k = 0; k < 4;k++)	{
						for(l = 0;l < 2; l++)	{
							r = bloom_check(&bloom,publickeyhashrmd160_endomorphism[l][k],MAXLENGTHADDRESS);
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
	Gn.reserve(CPU_GRP_SIZE / 2);
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g,G);
		Gn[i] = g;
	}
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
}

/* This function perform the KECCAK Opetation*/
void KECCAK_256(uint8_t *source, size_t size,uint8_t *dst)	{
	SHA3_256_CTX ctx;
	SHA3_256_Init(&ctx);
	SHA3_256_Update(&ctx,source,size);
	KECCAK_256_Final(dst,&ctx);
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

	pthread_mutex_lock(&write_keys);
	keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
	if(keys != NULL)	{
		fprintf(keys,"Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);
		fclose(keys);
	}
	printf("\nHit! Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);

	pthread_mutex_unlock(&write_keys);
	free(hextemp);
	free(hexrmd);
}

bool isBase58(char c) {
    // Define the base58 set
    const char base58Set[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Check if the character is in the base58 set
    return strchr(base58Set, c) != NULL;
}

bool isValidBase58String(char *str)	{
	int len = strlen(str);
	bool continuar = true;
	for (int i = 0; i < len && continuar; i++) {
		continuar = isBase58(str[i]);
	}
	return continuar;
}

bool readFileAddress(char *fileName)	{
	if(!FLAGREADEDFILE1)	{
		/*
			if the data_ file doesn't exist we need read it first:
		*/
		return forceReadFileAddress(fileName);
	}
	return true;
}

bool forceReadFileAddress(char *fileName)	{
	/* Here we read the original file as usual */
	FILE *fileDescriptor;
	bool validAddress;
	uint64_t numberItems,i;
	size_t r,raw_value_length;
	uint8_t rawvalue[50];
	char aux[100],*hextemp;
	fileDescriptor = fopen(fileName,"r");
	if(fileDescriptor == NULL)	{
		fprintf(stderr,"[E] Error opening the file %s, line %i\n",fileName,__LINE__ - 2);
		return false;
	}

	/*Count lines in the file*/
	numberItems = 0;
	while(!feof(fileDescriptor))	{
		hextemp = fgets(aux,100,fileDescriptor);
		trim(aux," \t\n\r");
		if(hextemp == aux)	{
			r = strlen(aux);
			if(r > 20)	{ 
				numberItems++;
			}
		}
	}
	fseek(fileDescriptor,0,SEEK_SET);
	MAXLENGTHADDRESS = 20;		/*20 bytes beacuase we only need the data in binary*/

	printf("[+] Allocating memory for %" PRIu64 " elements: %.2f MB\n",numberItems,(double)(((double) sizeof(struct address_value)*numberItems)/(double)1048576));
	addressTable = (struct address_value*) malloc(sizeof(struct address_value)*numberItems);
	checkpointer((void *)addressTable,__FILE__,"malloc","addressTable" ,__LINE__ -1 );

	if(!initBloomFilter(&bloom,numberItems))
		return false;

	i = 0;
	while(i < numberItems)	{
		validAddress = false;
		memset(aux,0,100);
		memset(addressTable[i].value,0,sizeof(struct address_value));
		hextemp = fgets(aux,100,fileDescriptor);
		trim(aux," \t\n\r");
		r = strlen(aux);
		if(r > 0 && r <= 40)	{
			if(r<40 && isValidBase58String(aux))	{	//Address
				raw_value_length = 25;
				b58tobin(rawvalue,&raw_value_length,aux,r);
				if(raw_value_length == 25)	{
					//hextemp = tohex((char*)rawvalue+1,20);
					bloom_add(&bloom, rawvalue+1 ,sizeof(struct address_value));
					memcpy(addressTable[i].value,rawvalue+1,sizeof(struct address_value));
					i++;
					validAddress = true;
				}
			}
			if(r == 40 && isValidHex(aux))	{	//RMD
				hexs2bin(aux,rawvalue);
				bloom_add(&bloom, rawvalue ,sizeof(struct address_value));
				memcpy(addressTable[i].value,rawvalue,sizeof(struct address_value));
				i++;
				validAddress = true;
			}
		}
		if(!validAddress)	{
			fprintf(stderr,"[I] Ommiting invalid line %s\n",aux);
			numberItems--;
		}
	}
	N = numberItems;
	return true;
}

/*
	I write this as a function because i have the same segment of code in 3 different functions
*/

bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom)	{
	bool r = true;
	printf("[+] Bloom filter for %" PRIu64 " elements.\n",items_bloom);
	if(items_bloom <= 10000)	{
		if(bloom_init2(bloom_arg,10000,0.000001) == 1){
			fprintf(stderr,"[E] error bloom_init for 10000 elements.\n");
			r = false;
		}
	}
	else	{
		if(bloom_init2(bloom_arg,FLAGBLOOMMULTIPLIER*items_bloom,0.000001)	== 1){
			fprintf(stderr,"[E] error bloom_init for %" PRIu64 " elements.\n",items_bloom);
			r = false;
		}
	}
	printf("[+] Loading data to the bloomfilter total: %.2f MB\n",(double)(((double) bloom_arg->bytes)/(double)1048576));
	return r;
}

void writeFileIfNeeded(const char *fileName)	{
	if(!FLAGREADEDFILE1)	{
		FILE *fileDescriptor;
		char fileBloomName[30];
		uint8_t checksum[32],hexPrefix[9];
		char dataChecksum[32],bloomChecksum[32];
		size_t bytesWrite;
		uint64_t dataSize;
		if(!sha256_file((const char*)fileName,checksum)){
			fprintf(stderr,"[E] sha256_file error line %i\n",__LINE__ - 1);
			exit(EXIT_FAILURE);
		}
		tohex_dst((char*)checksum,4,(char*)hexPrefix); // we save the prefix (last fourt bytes) hexadecimal value
		snprintf(fileBloomName,30,"data_%s.dat",hexPrefix);
		fileDescriptor = fopen(fileBloomName,"wb");
		dataSize = N * (sizeof(struct address_value));
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

			FLAGREADEDFILE1 = 1;
			fclose(fileDescriptor);
			printf("\n");
		}
	}
}

void calcualteindex(int i,Int *key)	{
	if(i == 0)	{
		key->Set(&BSGS_M3);
	}
	else	{
		key->SetInt32(i);
		key->Mult(&BSGS_M3_double);
		key->Add(&BSGS_M3);
	}
}
