/* udptimer.c - simple udp server which collects latency information.
 *
 * This is based on the simple udp server found in the 4.3BSD IPC tutorial.
 * This version receives datagrams from multiple senders, and compiles
 * some statistics about their latency. It assumes the datagrams have
 * timestamps at the beginning of the data portion. The timestamps
 * themselves are just struct timeval, in host byte order, as produced by
 * gettimeofday().
 *
 * Packets that contain these timestamps can be produced by sendip.
 * Sample call:
 * 	sendip -l 2000 -p ipv4 -is 10.1.2.0/24 -id 10.2.3.4 \
 * 		-p udp -us r2 -ud 5000 -d t72 10.2.3.4
 * This will produce 2000 udp packets, with random 10.1.2.0/24 source
 * addresses and random source ports, and send them to 10.2.3.4:5000.
 * The packets will have 72-byte payloads, with the timestamp at the
 * beginning of the payload. The size of the timestamp is system
 * dependent; on 64-bit Linux systems, it's 16 bytes (2 8-bit integers).
 *
 * Usage: udptimer <port>
 *
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <memory.h>
#include <math.h>

/* We store delay time entries indexed by IPv4 address. For convenience,
 * and to avoid too much unused allocation, everything is accessed via
 * a tree, basically a series of 256-entry tables, each of which are only
 * created as needed. So, address 10.1.2.3, delay time 23 gets accessed as:
 *
 * table 1: 	0
 * 		1
 * 		...
 * 		10 -> table 2:	0
 * 				1 -> table 3:	0
 * 						1
 * 						2 -> table 4:	0
 * 								1
 * 								2
 * 								3 -> times
 * The times are also stored in a series of 256 tables, each of which
 * can hold up to 4095 entries. (Position 0 stores the number of entries
 * in use for that table.)
 * Say the times table already has 5123 entries. Then 23 goes in
 * the 1028th slot (index 1027) of the second table:
 * times:	0 (first 4095 entries)
 * 		1 (next 4095):	0
 * 				1
 * 				...
 * 				1027 -> 23
 * This structure allows around 1 million (1048320) entries per address,
 * which is way more than enough for statistics. 
 */

/* 4096 - 1  - I keep these allocations at 8K each, as I have some
 * vague ideas about making a faster allocator for them.
 */
#define TIMENTRYSIZE	4095
typedef struct timentry {
	u_int16_t used;
	u_int16_t times[TIMENTRYSIZE];
} Timentry;

/* The union accommodates either table type. Not really necessary to do
 * it this way, but it just seemed convenient.
 */
#define TABLESIZE	256
typedef union _addrtime {
	union _addrtime *p[TABLESIZE];
	Timentry *t[TABLESIZE];
} AddrTime;

AddrTime tstore;


AddrTime *newprefix(void)
{
	AddrTime *answer;

	answer = (AddrTime *)malloc(sizeof(AddrTime));
	memset((void *)answer, 0, sizeof(AddrTime));
	return answer;
}

Timentry *newtimentry(void)
{
	Timentry *answer;

	answer = (Timentry *)malloc(sizeof(struct timentry));
	answer->used = 0;
	return answer;
}

AddrTime *
getaddrtime(AddrTime *at, int slot)
{
	if (!at->p[slot]) {
		at->p[slot] = newprefix();
	}
	return at->p[slot];
}


Timentry **gettimentry(struct in_addr *from)
{
	union {
		u_int8_t bytes[4];
		u_int32_t word[1];
	} ipv4addr;
	AddrTime *at;

	ipv4addr.word[0] = from->s_addr;
	at = getaddrtime(&tstore, ipv4addr.bytes[0]);
	at = getaddrtime(at, ipv4addr.bytes[1]);
	at = getaddrtime(at, ipv4addr.bytes[2]);
	at = getaddrtime(at, ipv4addr.bytes[3]);
	return at->t;
}

void
storetimentry(Timentry **t, int delaytime)
{
	int i;

	for (i=0; i < TABLESIZE; ++i) {
		if (!t[i])
			t[i] = newtimentry();
		if (t[i]->used == TIMENTRYSIZE)
			continue;
		t[i]->times[t[i]->used] = delaytime;
		++t[i]->used;
		return;
	}
	/* If we fall off the end, we just ignore the entry */
}

void
storetime(struct in_addr *from, int delaytime)
{
	char dst[INET_ADDRSTRLEN];
	Timentry **t;

	/* from->s_addr is 32-bit address */
#ifdef DEBUG
	printf("store %s %d\n", 
		inet_ntop(AF_INET, from,
				dst, INET_ADDRSTRLEN), delaytime);
#endif
	
	t = gettimentry(from);
	storetimentry(t, delaytime);
}

void
timestats(Timentry **t, double *mu, double *sigma, double *rho)
{
	int i, j;
	int n=0;
	double sumsquare=0.0, sum=0.0, top=0.0;
	double sigma2=0.0;
	double prev;

	if (!t) return;
	for (i=0; i < TABLESIZE; ++i) {
		if (!t[i] || t[i]->used == 0)
			break;
		n += t[i]->used;
		for (j=0; j < t[i]->used; ++j) {
			sumsquare += (double)t[i]->times[j]*t[i]->times[j];
			sum += (double)t[i]->times[j];
		}
	}
	*mu = sum/(double)n;
	*sigma = sqrt((sumsquare - (double)n*(*mu)*(*mu))/(double)(n-1));

	prev = *mu;
	for (i=0; i < TABLESIZE; ++i) {
		if (!t[i] || t[i]->used == 0)
			break;
		for (j=0; j < t[i]->used; ++j) {
			top += ((double)t[i]->times[j] - *mu)*
				(prev - *mu);
			sigma2 += (prev - *mu) * (prev - *mu);
			prev = (double)t[i]->times[j];
		}
	}
	*rho = top/sigma2;
}

int
printtime(Timentry **t, double *mu)
{
	int m;
	int numused;
	double sigma, rho;

	numused = 0;
	if (!t) return 0;
	for (m=0; t[m] && t[m]->used > 0; ++m) {
#ifdef DEBUG
		int n;

		/* Dump only for debug */
		for (n=0; n < t[m]->used; ++n) {
		    printf(" %d", t[m]->times[n]);
		}
#endif
		numused += t[m]->used;
	}
	printf(" %d: ", numused);
	timestats(t, mu, &sigma, &rho);
	printf("mu %6.4f sigma %6.4f rho %6.4f", *mu, sigma, rho);

	printf("\n");
	return numused;
}

void
printtimes(void)
{
    int i, j, k, l;
    AddrTime *at1, *at2, *at3;
    Timentry **t;
    int used, totalused = 0;
    double mu, totalmu = 0.0;

    for (i=0; i < TABLESIZE; ++i) {
	if (tstore.p[i]) {
	    at1 = tstore.p[i];
	    for (j=0; j < TABLESIZE; ++j) {
		if (at1->p[j]) {
		    at2 = at1->p[j];
		    for (k=0; k < TABLESIZE; ++k) {
			if (at2->p[k]) {
			    at3 = at2->p[k];
			    for (l=0; l < TABLESIZE; ++l) {
				if (at3->p[l]) {
				    t = at3->p[l]->t;
				    printf("%d.%d.%d.%d:", i, j, k, l);
				    used = printtime(t, &mu);
				    totalused += used;
				    totalmu += mu*used;
				}
			    }
			}
		    }
		}
	    }
	}
    }
    printf("total entries: %d, overall average %6.4f\n",
    	totalused, totalmu/totalused);
}

main(int argc, char **argv)
{
	int sock, length;
	struct sockaddr_in name, from;
	struct timeval t, now, waittime;
	int cc, pnum, lastpnum;
	fd_set dset;
	uint16_t port;

	/* Create socket from which to read. */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("opening datagram socket");
		exit(1);
	}
	/* Create name with wildcards. */
	name.sin_family = AF_INET;
	name.sin_addr.s_addr = INADDR_ANY;
	if (argc > 1)
		port = atoi(argv[1]);
	else
		port = 5000;
	name.sin_port = htons(port);
	if (bind(sock, (struct sockaddr *)&name, sizeof(name))) {
		perror("binding datagram socket");
		exit(1);
	}
	length = sizeof(struct sockaddr_in);

	/* We sit in a loop, waiting for datagrams. Every ten seconds,
	 * we wake up and print out statistics.
	 */
	lastpnum=1;
	for (pnum=1; ;) {
		FD_ZERO(&dset);
		FD_SET(sock, &dset);
		waittime.tv_sec = 10;
		if (select(sock+1, &dset, 0, 0, &waittime) < 0) {
			perror("select");
			continue;
		}
		if (FD_ISSET(sock, &dset)) {
			/* Read from the socket. We expect a timestamp in the
			* initial data portion
			*/
			cc = recvfrom(sock, (void *)&t, sizeof(t), 0,
				(struct sockaddr *)&from, &length);
			if (cc <= 0) {
				perror("receiving datagram packet");
				break;
			}
			gettimeofday(&now, NULL);
			storetime(&from.sin_addr,
				1000000*(now.tv_sec-t.tv_sec)+now.tv_usec-t.tv_usec);
			++pnum;
		} else {
			/* timeout; dump data if new */
			if (pnum != lastpnum)
				printtimes();
			lastpnum = pnum;
		}
	}
	close(sock);
}
