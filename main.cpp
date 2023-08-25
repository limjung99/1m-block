#include "pch.h"
#include "mylibnet.h"
/* banned ip */
unordered_map<const char*,bool> hash_map;
string banned_domains="top-1m.csv";

const char* get_http_host(const char* http_data) {
    const char* host_marker = "Host: ";
    const char* host_start = std::strstr(http_data, host_marker);
    
    if (host_start) {
        host_start += std::strlen(host_marker);
        const char* host_end = std::strchr(host_start, '\r'); // Find end of line
        if (host_end) {
            size_t host_length = host_end - host_start;
            char* host = new char[host_length + 1];
            strncpy(host, host_start, host_length);
            host[host_length] = '\0';
            return host;
        }
    }
    
    return nullptr;
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data); /* payload get */
	if (ret >= 0)
		printf("payload_len=%d\n", ret);

	fputc('\n', stdout);

	return id;
}

bool isbanned(struct nfq_data *tb){ /* http 프로토콜의 host name 리턴 */
    u_int8_t* pkt;
    int ret = nfq_get_payload(tb, &pkt); /* payload size */
    /* data parse */
	/* ETH */
	struct libnet_ether_hdr *eth_hdr =(struct libnet_ether_hdr*) pkt;
	u_int16_t type = ntohs(eth_hdr->type);
	if(type!=0x0800){
		cout<<"Not a ip protocol\n";
		return true;
	}
	/* IP */
    struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr*)(pkt+14);
    u_int8_t protocol = ip_hdr->ip_p;
	u_int8_t ip_vhl = ip_hdr->ip_vhl;
	u_int8_t ip_version = (ip_vhl & 0xf0)>>4;
	u_int8_t ip_header_length = ip_vhl & 0x0f;
	if(protocol!=0x6) {
		cout<<"Not a tcp protocol\n";
		return true;
	}
    /* TCP */
	struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*)(pkt+14+ip_header_length*4);
    u_int8_t th_off = (tcp_hdr->th_off)>>4;
    /* HTTP */
	cout<<"IP length: "<<ip_header_length*4<<"\n";
	cout<<"TCP length: "<<th_off*4<<"\n";
    u_int8_t *data = pkt+14+ip_header_length*4+th_off*4;
	/* strstr */
	// Find HTTP host field
    const char* http_host = get_http_host(reinterpret_cast<const char*>(data));
	 if (http_host) {
        std::cout << "HTTP Host: " << http_host << std::endl;
        delete[] http_host; // Remember to free the memory
    } else {
        std::cout << "HTTP Host not found" << std::endl;
    }
    return false;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa); /* print pkt를 통해 data 포인터에 패킷 시작주소가 담김 */
    /* http hostname get */
    bool isBan = isbanned(nfa);
    if(isBan){
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{

    /* fread to make hash hit table */
	ifstream fs;
	fs.open(banned_domains);
    if(!fs.is_open()){
		cout<<"can't open banned domains files\n";
		return -1;
	}
	string line;
	while(getline(fs,line)){
		size_t idx = line.find(',');
		line = line.substr(idx+1);
		cout<<line<<"\n";
		hash_map[line.c_str()] = true;
	}

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
