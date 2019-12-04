#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
 
void ProcessPacket(unsigned char* , int, int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void PrintData (unsigned char* , int);
 
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
char ip[50];
int main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    int flag = 0;
    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!
    
    printf("------------Welcome------------\n");
    printf("1. Http\n");
    printf("2. Dns\n");
    printf("3. E-mail\n");
    printf("4. Traceroute\n");
    printf("5. All\n");
    printf("> ");
    scanf("%d", &flag);
    
    if(flag == 1 || flag == 2){
	printf("Ip > ");
	scanf("%s", ip);
    }
    else if (flag == 4)
	printf(" Please do traceroute on you terminal after Starting...\n");
    //

    printf("Starting...\n");
     
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    //setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
     
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        ProcessPacket(buffer , data_size, flag);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}
 
void ProcessPacket(unsigned char* buffer, int size, int flag)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
	    *ip = '\0';
            if(flag == 4 || flag==5)
		 print_icmp_packet( buffer , size);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
	    if(flag == 1 || flag ==5)
            print_tcp_packet(buffer , size );
            break;
         
        case 17: //UDP Protocol
            ++udp;
	    if(flag == 2 || flag==5)
            print_udp_packet(buffer , size);
            break;
	// smtp 587
	// pop 995	    
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}
 
void print_ip_header(unsigned char* Buffer, int Size)
{
   
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));

    iph->saddr = inet_addr(ip);
    if(strcmp(ip,"")!=0)
	iph->saddr = inet_addr(ip);
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    printf( "\n");
    printf( "IP Header\n");
    printf( "   |-IP Version        : %d\n",(unsigned int)iph->version);
    printf( "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf( "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf( "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    printf( "   |-Identification    : %d\n",ntohs(iph->id));
    //printf( "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //printf( "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //printf( "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    printf( "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    printf( "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    printf( "   |-Checksum : %d\n",ntohs(iph->check));
    printf( "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    printf( "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}
 
void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    printf( "\n\n***********************TCP Packet*************************\n"); 
         
    print_ip_header(Buffer,Size);
         
    printf( "\n");
    printf( "TCP Header\n");
    printf( "   |-Source Port      : %u\n",ntohs(tcph->source));
    printf( "   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf( "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf( "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf( "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //printf( "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //printf( "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf( "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf( "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf( "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf( "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf( "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf( "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf( "   |-Window         : %d\n",ntohs(tcph->window));
    printf( "   |-Checksum       : %d\n",ntohs(tcph->check));
    printf( "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    printf( "\n");
    printf( "                        DATA Dump                         ");
    printf( "\n");
         
    printf( "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    printf( "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    printf( "Data Payload\n");   
    PrintData(Buffer + header_size , Size - header_size );
                         
    printf( "\n###########################################################");
}
 
void print_udp_packet(unsigned char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    printf( "\n\n***********************UDP Packet*************************\n");
     
    print_ip_header(Buffer,Size);          
     
    printf( "\nUDP Header\n");
    printf( "   |-Source Port      : %d\n" , ntohs(udph->source));
    printf( "   |-Destination Port : %d\n" , ntohs(udph->dest));
    printf( "   |-UDP Length       : %d\n" , ntohs(udph->len));
    printf( "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    printf( "\n");
    printf( "IP Header\n");
    PrintData(Buffer , iphdrlen);
         
    printf( "UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);
         
    printf( "Data Payload\n");   
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size);
     
    printf( "\n###########################################################");
}
 
void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    printf( "\n\n***********************ICMP Packet*************************\n");
     
    print_ip_header(Buffer , Size);
             
    printf( "\n");
         
    printf( "ICMP Header\n");
    printf( "   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        printf( "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        printf( "  (ICMP Echo Reply)\n");
    }
     
    printf( "   |-Code : %d\n",(unsigned int)(icmph->code));
    printf( "   |-Checksum : %d\n",ntohs(icmph->checksum));
    //printf( "   |-ID       : %d\n",ntohs(icmph->id));
    //printf( "   |-Sequence : %d\n",ntohs(icmph->sequence));
    printf( "\n");
 
    printf( "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    printf( "UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);
         
    printf( "Data Payload\n");   
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );
     
    printf( "\n###########################################################");
}
 
void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf( "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf( "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else printf( "."); //otherwise print a dot
            }
            printf( "\n");
        }
         
        if(i%16==0) printf( "   ");
            printf( " %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
              printf( "   "); //extra spaces
            }
             
            printf( "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  printf( "%c",(unsigned char)data[j]);
                }
                else
                {
                  printf( ".");
                }
            }
             
            printf(  "\n" );
        }
    }
}
