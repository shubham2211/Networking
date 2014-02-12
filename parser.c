/* Demonstration program of reading packet trace files recorded by pcap
 * (used by tshark and tcpdump) and dumping out some corresponding information
 * in a human-readable form.
 *
 * Note, this program is limited to processing trace files that contains
 * TCP or UDP packets. 
 */
#define __USE_BSD         /* Using BSD IP header           */ 
#include <netinet/ip.h>   /* Internet Protocol             */ 
#define __FAVOR_BSD       /* Using BSD TCP header          */ 
#include <netinet/tcp.h>  /* Transmission Control Protocol */ 
#include <pcap.h>         /* Libpcap                       */ 
#include <string.h>       /* String operations             */ 
#include <stdlib.h>       /* Standard library definitions  */ 

#include <stdio.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include<assert.h>
#define NUM_PACKETS 100
/* We've included the UDP header struct .
 */
struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);

/* Report a problem with dumping the packet with the given timestamp. */
void problem_pkt(struct timeval ts, const char *reason);

/* Report the specific problem of a packet being too short. */
void too_short(struct timeval ts, const char *truncated_hdr);

int packetid=0;
char srcipfield0[NUM_PACKETS][257];


char srcipfield1[NUM_PACKETS][257];
char srcipfield2[NUM_PACKETS][257];
char srcipfield3[NUM_PACKETS][257];


char dstipfield0[NUM_PACKETS][257];
char dstipfield1[NUM_PACKETS][257];
char dstipfield2[NUM_PACKETS][257];
char dstipfield3[NUM_PACKETS][257];

char srcport[NUM_PACKETS][65537];
char dstport[NUM_PACKETS][65537];
char protocol_type[NUM_PACKETS];
int indirection_array[NUM_PACKETS];

/*
	srcipplugin() takes in the packet id as pid  along with ip field identifier as field num and field value as pch .
	
	ex. 192.23.45.67
	
	then 192 is in field 0 with field value(pch) = 192
	then 23  is in field 1 with field value(pch) = 	23
		and so on.....

	this function initializes the arrays srcipfield0,srcipfield1,srcipfield2,srcipfield3 with 1 for the row identified by pid and 		column by pch.

*/
void srcipplugin(int pid,int fieldnum,char *pch)
{

	int final=0,i=0;
	int length=strlen(pch);
		for (i=0;i<length;i++)
		{
			char ch=pch[i];
			int num=ch-48;
			final=final*10+num;
		}
		
		//printf("num\t%d\n",final);
	if(fieldnum==0)
		srcipfield0[pid][final]='1';

	else	if(fieldnum==1)
		srcipfield1[pid][final]='1';
	
	else	if(fieldnum==2)
		srcipfield2[pid][final]='1';
	
	else	if(fieldnum==3)
		srcipfield3[pid][final]='1';
}	



/*
	dstipplugin() takes in the packet id as pid  along with ip field identifier as field num and field value as pch .
	
	ex. 192.23.45.67
	
	then 192 is in field 0 with field value(pch) = 192
	then 23  is in field 1 with field value(pch) = 	23
		and so on.....

	this function initializes the arrays dstipfield0,dstipfield1,dstipfield2,dstipfield3 with 1 for the row identified by pid and 		column by pch.

*/

void dstipplugin(int pid,int fieldnum,char *pch)
{

	int final=0,i=0;
	int length=strlen(pch);
		for (i=0;i<length;i++)
		{
			char ch=pch[i];
			int num=ch-48;
			final=final*10+num;
		}
		
		//printf("num\t%d\n",final);
	if(fieldnum==0)
		dstipfield0[pid][final]='1';

	else	if(fieldnum==1)
		dstipfield1[pid][final]='1';
	
	else	if(fieldnum==2)
		dstipfield2[pid][final]='1';
	
	else	if(fieldnum==3)
		dstipfield3[pid][final]='1';
}	

/*
	srcportplugin() takes in the packet id as pid  along with port number .

	this function initializes the arrays srcport with 1 for the row identified by pid and column by port.

*/

void srcportplugin(int pid,int port)
{
	srcport[pid][port]='1';	
}


/*
	dstportplugin() takes in the packet id as pid  along with port number .

	this function initializes the arrays dstport with 1 for the row identified by pid and column by port.
*/

void dstportplugin(int pid,int port)
{
	dstport[pid][port]='1';	
}

/*
	protocolplugin() takes in the packet id as pid  along with protocol type .
	this function initializes the arrays protocol_type with 'u' or 't' for udp or tcp repectively ,for the packet identified by pid.
*/
void protocolplugin(int pid,char proto)
{
	protocol_type[pid]=proto;

}


/* dump_UDP_packet()
 *
 * This routine parses a packet, expecting Ethernet, IP, and UDP or TCP headers.
 * It extracts the UDP or TCP source and destination port numbers along with the UDP or TCP
 * packet length by casting structs over a pointer that we move through
 * the packet.  We can do this sort of casting safely because libpcap
 * guarantees that the pointer will be aligned.
 *
 * The "ts" argument is the timestamp associated with the packet.
 *
 * Note that "capture_len" is the length of the packet *as captured by the
 * tracing program*, and thus might be less than the full length of the
 * packet.  However, the packet pointer only holds that much data, so
 * we have to be careful not to read beyond it.
 */



void dump_UDP_packet(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len)
{
	struct ip *ip;
	struct UDP_hdr *udp;
	struct IP_hdr *iphdr;
	struct tcphdr *tcphdr;
	unsigned int IP_header_length;

	/* For simplicity, we assume Ethernet encapsulation. */

	if (capture_len < sizeof(struct ether_header))
		{
		/* We didn't even capture a full Ethernet header, so we
		 * can't analyze this any further.
		 */
		too_short(ts, "Ethernet header");
		return;
		}

	/* Skip over the Ethernet header. */
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);

	if (capture_len < sizeof(struct ip))
		{ /* Didn't capture a full IP header */
		too_short(ts, "IP header");
		return;
		}

	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */

	if (capture_len < IP_header_length)
		{ 
		/* didn't capture the full IP header including options */
		too_short(ts, "IP header with options");
		return;
		}

	char *str = (char *)inet_ntoa(ip->ip_src);	// convert ip address to string for processing

	char *pch = strtok(str, ".");	
	int fieldnum=0;
	while(pch != NULL)
	{
		srcipplugin(packetid,fieldnum,pch);	
		fieldnum++;
		pch = strtok (NULL, "."); 

	}

	str = (char *)inet_ntoa(ip->ip_dst);

	char *dsttok = strtok(str, ".");
	fieldnum=0;
	while(dsttok != NULL)
	{
		dstipplugin(packetid,fieldnum,dsttok);
		fieldnum++;
		dsttok = strtok (NULL, "."); 

	}

	if (ip->ip_p == IPPROTO_UDP)		// check if transport layer protocol is UDP
		{

		packet += IP_header_length;
		capture_len -= IP_header_length;
		udp = (struct UDP_hdr*) packet;
		srcportplugin(packetid,ntohs(udp->uh_sport));
		dstportplugin(packetid,ntohs(udp->uh_dport));
		protocolplugin(packetid,'u');
		
		}


	else if (ip->ip_p == IPPROTO_TCP)	// check if transport layer protocol is TCP
	{
		packet += IP_header_length;
		capture_len -= IP_header_length;
		tcphdr=(struct tcphdr*)packet;
		srcportplugin(packetid,ntohs(tcphdr->th_sport));
		dstportplugin(packetid,ntohs(tcphdr->th_dport));
		protocolplugin(packetid,'t');
		
	}	

	
	packetid++;
}
/*

	store() takes in name of file to be created as filename , which stores initialized arrays into files in compressed format.
	type indentifies whether file to be created is for IP(0) ,PORT(1) or PROTOCOL(2).
	src_dst indentifies whether file to be created is for SOURCE(0)  or DESTINATION(1)
	fieldnum applicable in case of ip  : carries the same meaning as describedc above in srcipplugin.

	the compressed format for storing is HORIZONTAL RUN-LENGTH ENCODING .
	ex. array is suppose
				0	0	0	1	0	0
				0	1	0	0	0	0
				0	0	0	0	0	1
	then in file its stored as:
				3|1|2
				1|1|4
				5|1|0

*/
void store(char *filename,int type,int src_dst,int fieldnum)
{
	int i;
	FILE *file = fopen(filename, "w+");


	switch(type)
	{
	case 0:
		switch(src_dst)
		{
		case 0:
			if(fieldnum==0){
					for(i=0;i<packetid;i++)
						{	
							int index=(int)(strchr(srcipfield0[i],'1')-srcipfield0[i]);
							fprintf(file,"%d%c%d%c%d\n",index-1,'|',1,'|',256-index);
						}
					}
			else if(fieldnum==1)
					{
					for(i=0;i<packetid;i++)
						{	
							int index=(int)(strchr(srcipfield1[i],'1')-srcipfield1[i]);
							fprintf(file,"%d%c%d%c%d\n",index-1,'|',1,'|',256-index);
						}
					}
			else if(fieldnum==2)
					{
					for(i=0;i<packetid;i++)
						{	
							int index=(int)(strchr(srcipfield2[i],'1')-srcipfield2[i]);
							fprintf(file,"%d%c%d%c%d\n",index-1,'|',1,'|',256-index);
						}
					}
			else if(fieldnum==3)
					{
					for(i=0;i<packetid;i++)
						{	
							int index=(int)(strchr(srcipfield3[i],'1')-srcipfield3[i]);
							fprintf(file,"%d%c%d%c%d\n",index-1,'|',1,'|',256-index);
						}
					}
			
			break;
		case 1:
			if(fieldnum==0){
					for(i=0;i<packetid;i++)
						{	
							int index=(int)(strchr(dstipfield0[i],'1')-dstipfield0[i]);
							fprintf(file,"%d%c%d%c%d\n",index-1,'|',1,'|',256-index);
						}
					}
			else if(fieldnum==1)
					{
					for(i=0;i<packetid;i++)
						{	
							int index=(int)(strchr(dstipfield1[i],'1')-dstipfield1[i]);
							fprintf(file,"%d%c%d%c%d\n",index-1,'|',1,'|',256-index);
						}
					}
			else if(fieldnum==2)
					{
					for(i=0;i<packetid;i++)
						{	
							int index=(int)(strchr(dstipfield2[i],'1')-dstipfield2[i]);
							fprintf(file,"%d%c%d%c%d\n",index-1,'|',1,'|',256-index);
						}
					}
			else if(fieldnum==3)
					{
					for(i=0;i<packetid;i++)
						{	
							int index=(int)(strchr(dstipfield3[i],'1')-dstipfield3[i]);
							fprintf(file,"%d%c%d%c%d\n",index-1,'|',1,'|',256-index);
						}
					}
			
						
		}

			break;
	case 1:
		{
		switch(src_dst){
			case 0:{
				for(i=0;i<packetid;i++)
						{	
							int index=(int)(strchr(srcport[i],'1')-srcport[i]);
							fprintf(file,"%d%c%d%c%d\n",index-1,'|',1,'|',65536-index);
						}
				break;		
				}
			case 1:{
				for(i=0;i<packetid;i++)
						{	
							int index=(int)(strchr(dstport[i],'1')-dstport[i]);
							fprintf(file,"%d%c%d%c%d\n",index-1,'|',1,'|',65536-index);
						}
				break;		
				}
				}
		}
		break;
	case 2:
		{
			for(i=0;i<packetid;i++)
						{	
															  							fprintf(file,"%c\n",protocol_type[i]);
		

						}
		}
		break;

	}
}

int main(int argc, char *argv[])
	{

	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	struct ip *ip;
	++argv; --argc;

	/* We expect exactly one argument, the name of the file to dump. */
	if ( argc != 1 )
		{
		fprintf(stderr, "program requires one argument, the trace file to dump\n");
		exit(1);
		}

	pcap = pcap_open_offline(argv[0], errbuf);		// open file for offline capture
	FILE* fp= pcap_file(pcap); 

	if (pcap == NULL)
		{
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
		}
	// initialize all the arrays to their default value as 0.

	memset(srcipfield0 , '0', sizeof(char) * NUM_PACKETS * 257);
	memset(srcipfield1 , '0', sizeof(char) * NUM_PACKETS * 257);
	memset(srcipfield2 , '0', sizeof(char) * NUM_PACKETS * 257);
	memset(srcipfield3 , '0', sizeof(char) * NUM_PACKETS * 257);
	memset(dstipfield0 , '0', sizeof(char) * NUM_PACKETS * 257);
	memset(dstipfield1 , '0', sizeof(char) * NUM_PACKETS * 257);
	memset(dstipfield2 , '0', sizeof(char) * NUM_PACKETS * 257);
	memset(dstipfield3 , '0', sizeof(char) * NUM_PACKETS * 257);
	memset(srcport 	   , '0', sizeof(char) * NUM_PACKETS * 65537);
	memset(dstport 	   , '0', sizeof(char) * NUM_PACKETS * 65537);
	
	
	packetid=0;
	indirection_array[packetid]=24;	// 24 bytes is the length of trace header of pcap file

	while ((packet =pcap_next(pcap, &header)) != NULL)
	{
		dump_UDP_packet(packet, header.ts, header.caplen);

		indirection_array[packetid]=header.caplen+16+indirection_array[packetid-1]; // 16 is the length of Pcap header so we skip it
		
		if(packetid==NUM_PACKETS)	break;	

	}
	

	FILE *file = fopen("indirection_arr.txt", "w+");	
	int k=0;

	// store the offsets the packets in the file so that we can initialize the indirection array

	for(;k<packetid;k++)
		fprintf(file,"%d\n",indirection_array[k]);

	store("src0.txt",0,0,0);
	store("src1.txt",0,0,1);
	store("src2.txt",0,0,2);
	store("src3.txt",0,0,3);
	store("dst0.txt",0,1,0);
	store("dst1.txt",0,1,1);
	store("dst2.txt",0,1,2);
	store("dst3.txt",0,1,3);
	store("srcport.txt",1,0,0);	
	store("dstport.txt",1,1,0);
	store("protocol.txt",2,0,0);
	return 0;
	}


const char *timestamp_string(struct timeval ts)
	{
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
	}

void problem_pkt(struct timeval ts, const char *reason)
	{
	fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
	}

void too_short(struct timeval ts, const char *truncated_hdr)
	{
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
		timestamp_string(ts), truncated_hdr);
	}
