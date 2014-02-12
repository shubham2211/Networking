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

struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

/*

   dump_UDP_packet()
 
 * This routine reads a packet, expecting Ethernet, IP, and UDP or TCP headers.
 * It extracts the UDP or TCP source and destination port numbers along with the UDP or TCP
 * packet length by casting structs over a pointer that we move through
 * the packet.  We can do this sort of casting safely because libpcap
 * guarantees that the pointer will be aligned.
 
*/
void dump_UDP_packet(const unsigned char *packet,struct timeval ts,
			unsigned int capture_len)
{
	struct ip *ip;
	struct UDP_hdr *udp;
	struct IP_hdr *iphdr;
	struct tcphdr *tcphdr;
	unsigned int IP_header_length;

	/* For simplicity, we assume Ethernet encapsulation. */

	
	/* Skip over the Ethernet header. */
	packet += sizeof(struct ether_header);

	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;

	char *str = (char *)inet_ntoa(ip->ip_src);	//reading source port number
	printf("\nsource port %s",str);
	char *str1 = (char *)inet_ntoa(ip->ip_dst);	//reading destination port number
	printf("\ndestination port %s",str1);		

	packet += IP_header_length;			// moving packet pointer to the transport layer
	capture_len -= IP_header_length;


	if (ip->ip_p == IPPROTO_UDP)
	{
		udp = (struct UDP_hdr*) packet;
		printf("\nProtocol = UDP src_port=%d dst_port=%d\n",ntohs(udp->uh_sport),ntohs(udp->uh_dport));	
	}


	else if (ip->ip_p == IPPROTO_TCP)
	{
		tcphdr=(struct tcphdr*)packet;
		printf("\nProtocol = TCP src_port=%d dst_port=%d\n",ntohs(tcphdr->th_sport),ntohs(tcphdr->th_dport));
		
	}	
}

//	creating arrays to store the values after reading them from file where they are stored in compressed format
//	in these arrays we only store the required value and not the entire bitmap

int comparisonfields[11]={};
int srcipfield0[NUM_PACKETS]={0};
int srcipfield1[NUM_PACKETS]={0};
int srcipfield2[NUM_PACKETS]={0};
int srcipfield3[NUM_PACKETS]={0};

int dstipfield0[NUM_PACKETS]={0};
int dstipfield1[NUM_PACKETS]={0};
int dstipfield2[NUM_PACKETS]={0};
int dstipfield3[NUM_PACKETS]={0};

int srcport_arr[NUM_PACKETS]={0};
int dstport_arr[NUM_PACKETS]={0};

int protocol_arr[NUM_PACKETS]={0};



//queryprocessor
void processquery(char *filename, int ip_port, int src_dst, int fieldcount ,char *queryname)
{
	// analyse the query to see what all fields are mentioned in the query
	if(ip_port == 0)
		comparisonfields[ip_port*8 + src_dst*4 + fieldcount]=1;
	else
	{
		if(src_dst == 0)
			comparisonfields[8] = 1;
		else
			comparisonfields[9] = 1;
	} 	


	int final=0,i=0;
	int length=strlen(queryname);
	
	for (i=0;i<length;i++)
	{		
		char ch=queryname[i];
		int num=ch-48;
		final=final*10+num;
	}

	int num,count=0;

	char *str=(char*)malloc(sizeof(char)*15);
	
	FILE *fp=fopen(filename,"r");

	while(!feof(fp))//!=EOF)
	{
		fscanf(fp,"%d",&num);
		fscanf(fp,"%s",str);
		if(final == num+1)
		{
			if(ip_port == 0)
			{
				     if(src_dst == 0 && fieldcount == 0)
					srcipfield0[count]=1;
				else if(src_dst == 0 && fieldcount == 1)
					srcipfield1[count]=1;
				else if(src_dst == 0 && fieldcount == 2)
					srcipfield2[count]=1;
				else if(src_dst == 0 && fieldcount == 3)
					srcipfield3[count]=1;
				else if(src_dst == 1 && fieldcount == 0)
					dstipfield0[count]=1;
				else if(src_dst == 1 && fieldcount == 1)
					dstipfield1[count]=1;
				else if(src_dst == 1 && fieldcount == 2)
					dstipfield2[count]=1;
				else if(src_dst == 1 && fieldcount == 3)
					dstipfield3[count]=1;
			}
			else
			{
				if(src_dst == 0)
					srcport_arr[count]=1;
				else
					dstport_arr[count]=1;
			}
			

		}
		count++;
	}	
				
	fclose(fp);		
}


main()
{

	char *query=(char*)malloc(sizeof(char)*100);
	printf("\tEnter Query\n");
	scanf("%s",query);
	tolower(query);

	char *srcip=(char*)malloc(sizeof(char)*100);
	char *dstip=(char*)malloc(sizeof(char)*100);
	char *srcport=(char*)malloc(sizeof(char)*100);
	char *dstport=(char*)malloc(sizeof(char)*100);
	char *protocol=(char*)malloc(sizeof(char)*100);	
	char *queryname=(char*)malloc(sizeof(char)*100);
	
	int n;
	
	int combined_bitmap[NUM_PACKETS];

	int indirection_array[NUM_PACKETS];
	int l;
	

	int qualified_packet_id[NUM_PACKETS];	

	char form[50];
	int type=-1;
	printf("%s",queryname);
	char *present=strchr(query,'&');

	if((present!=NULL || query!=NULL) && (strchr(query,'|')==NULL))
	{
		type=0;
		for(l=0;l<NUM_PACKETS;l++)
			combined_bitmap[l]=1;
	
		queryname = strtok(query,"&"); 
		while(queryname!=NULL)
		{
			if(strstr(queryname,"srcip")!=NULL)
			{
				strcpy(srcip,queryname);
			}
			else if(strstr(queryname,"dstip")!=NULL)
			{
				strcpy(dstip,queryname);
			}
			else if(strstr(queryname,"srcport")!=NULL)
			{
				strcpy(srcport,queryname);			
			}
			else if(strstr(queryname,"dstport")!=NULL)
			{
				strcpy(dstport,queryname);				
			}
			else if(strstr(queryname,"protocol")!=NULL)
			{
				strcpy(protocol,queryname);
			}
			queryname = strtok(NULL,"&"); 
		}

	}

	else if(strchr(query,'|')!=NULL)
	{
		type=1;
		for(l=0;l<NUM_PACKETS;l++)
			combined_bitmap[l]=0;
		queryname = strtok(query,"|"); 
		while(queryname!=NULL)
		{
			if(strstr(queryname,"srcip")!=NULL)
			{
				strcpy(srcip,queryname);
			}
			else if(strstr(queryname,"dstip")!=NULL)
			{
				strcpy(dstip,queryname);
			}
			else if(strstr(queryname,"srcport")!=NULL)
			{
				strcpy(srcport,queryname);			
			}
			else if(strstr(queryname,"dstport")!=NULL)
			{
				strcpy(dstport,queryname);				
			}
			else if(strstr(queryname,"protocol")!=NULL)
			{
				strcpy(protocol,queryname);
			}
			queryname = strtok(NULL,"|"); 
		}

	}

	else
	{
		printf("wrong query");
	}

	

	if(srcip[0]!=0)
	{
		char *prem=strchr(srcip,'=');
		strcpy(prem,prem+1);

		queryname = strtok(prem,".");
		int fieldcount=0;

		while(queryname!=NULL)
		{

  			if(fieldcount==0 && strcmp(queryname,"*")!=0)	
			{
				processquery("src0.txt", 0, 0, 0,queryname);
			}
			else	if(fieldcount==1 && strcmp(queryname,"*")!=0)
			{
				processquery("src1.txt", 0, 0, 1,queryname);
			}
			else	if(fieldcount==2 && strcmp(queryname,"*")!=0)
			{	
				processquery("src2.txt", 0, 0, 2,queryname);
			}
			else	if(fieldcount==3 && strcmp(queryname,"*")!=0)
			{	
				processquery("src3.txt", 0, 0, 3,queryname);
			}
	
			queryname = strtok(NULL,".");
			fieldcount++;
		}
	}

	if(dstip[0]!=0)
	{
		char *prem=strchr(dstip,'=');
		strcpy(prem,prem+1);

		queryname = strtok(prem,".");
		int fieldcount=0;
		while(queryname!=NULL)
		{
			if(fieldcount==0 && strcmp(queryname,"*")!=0)	
			{
				processquery("dst0.txt", 0, 1, 0,queryname);
			}
			else	if(fieldcount==1 && strcmp(queryname,"*")!=0)
			{	
				processquery("dst1.txt", 0, 1, 1,queryname);
			}
			else	if(fieldcount==2 && strcmp(queryname,"*")!=0)
			{
				processquery("dst2.txt", 0, 1, 2,queryname);
			}
			else	if(fieldcount==3 && strcmp(queryname,"*")!=0)
			{
				processquery("dst3.txt", 0, 1, 3,queryname);
			}

			queryname = strtok(NULL,".");
			fieldcount=fieldcount+1;
		}

	}

	if(srcport[0]!=0)
	{
		char *prem=strchr(srcport,'=');
		strcpy(prem,prem+1);

		processquery("srcport.txt", 1, 0, 0,prem);
	}

	if(dstport[0]!=0)
	{
		char *prem=strchr(dstport,'=');
		strcpy(prem,prem+1);
	
		processquery("dstport.txt", 1, 1, 0,prem);
	}


	if(protocol[0]!=0)
	{
		char *prem=strchr(protocol,'=');
		strcpy(prem,prem+1);
		printf("protocol ... %s\n",prem);
		comparisonfields[10] = 1;
		FILE *fp=fopen("protocol.txt","r");
		char ch;int count=0;
		while(!feof(fp))//!=EOF)
		{
			fscanf(fp,"%c",&ch);

			if(prem[0] == ch)
				protocol_arr[count]=1;
			count++;	
			fscanf(fp,"%c",&ch);
		}
		fclose(fp);	
	}

	int i;
	for(i=0;i<NUM_PACKETS;i++)
	{
		int j;
			for(j=0;j<11;j++)
			{
				if(comparisonfields[j]==1)
				{
					switch(j)
					{
						case 0:
							if(type==0)
								combined_bitmap[i]=combined_bitmap[i]&srcipfield0[i];			
							else
								combined_bitmap[i]=combined_bitmap[i]|srcipfield0[i];

							break;

						case 1:
							if(type==0)
								combined_bitmap[i]=combined_bitmap[i]&srcipfield1[i];
							else{
								if(comparisonfields[j-1])
									combined_bitmap[i]=combined_bitmap[i]&srcipfield1[i];
								else
									combined_bitmap[i]=combined_bitmap[i]|srcipfield1[i];
								}
							break;

						case 2:
							if(type==0)				
								combined_bitmap[i]=combined_bitmap[i]&srcipfield2[i];
							else{
								if(comparisonfields[j-1] || comparisonfields[j-2])
									combined_bitmap[i]=combined_bitmap[i]|srcipfield2[i];
								else	
									combined_bitmap[i]=combined_bitmap[i]&srcipfield2[i];

							    }
							break;

						case 3:
							if(type==0)
								combined_bitmap[i]=combined_bitmap[i]&srcipfield3[i];
							else{
							if(comparisonfields[j-1] || comparisonfields[j-2] ||  comparisonfields[j-3])
									combined_bitmap[i]=combined_bitmap[i]&srcipfield3[i];
								
								else
									combined_bitmap[i]=combined_bitmap[i]|srcipfield3[i];
									
								if(combined_bitmap[i])
									continue;
								}
							break;

						case 4:
							if(type==0)
								combined_bitmap[i]=combined_bitmap[i]&dstipfield0[i];
							else
								combined_bitmap[i]=combined_bitmap[i]|dstipfield0[i];
			
							break;

						case 5:
							if(type==0)
								combined_bitmap[i]=combined_bitmap[i]&&dstipfield1[i];
							else{
								if(comparisonfields[j-1])
									combined_bitmap[i]=combined_bitmap[i]&dstipfield1[i];
								else
									combined_bitmap[i]=combined_bitmap[i]|dstipfield1[i];
								}
							break;

						case 6:
							if(type==0)
								combined_bitmap[i]=combined_bitmap[i]&dstipfield2[i];
							else{
								if(comparisonfields[j-1] || comparisonfields[j-2])
									combined_bitmap[i]=combined_bitmap[i]|dstipfield2[i];
								else	
									combined_bitmap[i]=combined_bitmap[i]&dstipfield2[i];

							    }
							break;

						case 7:
							if(type==0)
								combined_bitmap[i]=combined_bitmap[i]&dstipfield3[i];
							else{
								if(comparisonfields[j-1] || comparisonfields[j-2] ||  comparisonfields[j-3])
									combined_bitmap[i]=combined_bitmap[i]&dstipfield3[i];
								
								else
									combined_bitmap[i]=combined_bitmap[i]|dstipfield3[i];
									
								if(combined_bitmap[i])
									continue;
								}
							break;

						case 8:
							if(type==0)
								combined_bitmap[i]=combined_bitmap[i]&srcport_arr[i];
							else
								combined_bitmap[i]=combined_bitmap[i]|srcport_arr[i];
				
							break;

						case 9:
							if(type==0)
								combined_bitmap[i]=combined_bitmap[i]&dstport_arr[i];
							else
								combined_bitmap[i]=combined_bitmap[i]|dstport_arr[i];
				
							break;
						case 10:
							if(type==0)
								combined_bitmap[i]=combined_bitmap[i]&protocol_arr[i];
							
							else
								combined_bitmap[i]=combined_bitmap[i]|protocol_arr[i];
				
							break;
					}
				}	
			}

	}	
				


	FILE *file = fopen("indirection_arr.txt", "r");	

	//read the file of indirection array to store the offsets of the packet

	int k=0;
	for(;k<NUM_PACKETS;k++)
		fscanf(file,"%d\n",&indirection_array[k]);

	fclose(file);

	int count_qualified=0;
	int offsetarray[NUM_PACKETS];

	for(i=0;i<NUM_PACKETS;i++)
	{
		if(combined_bitmap[i]==1)
		{
			qualified_packet_id[count_qualified]=i;
			offsetarray[count_qualified++]=indirection_array[i];
		}
	}

	

/*
	printf("qualified packets\n");

	for(i=0;i<count_qualified;i++)
		printf("packet id: %d\t offset: %d\n", qualified_packet_id[i]+1, offsetarray[i]);

*/
	char errbuf[PCAP_ERRBUF_SIZE];

	struct pcap_pkthdr header;
	const unsigned char *packet;
	for(i=0;i<count_qualified;i++)
	{
		int curseekpos=offsetarray[i];
		pcap_t *handler;					// create the handler to read pcap file
		handler = pcap_open_offline("cap1.dump", errbuf);	// read the cap1.dump capture file

		FILE* fp= pcap_file(handler); 	
		fseek (fp,curseekpos, SEEK_SET );			// move the file pointer to the required offset 
		packet =pcap_next(handler, &header);			// move to the head of required packet determined by offset
		printf("\nCapture Length%d",header.caplen);
		dump_UDP_packet(packet,header.ts, header.caplen);
		fclose(fp);
	}

}

