#define _GNU_SOURCE 1

#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <pwd.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>

#include <libnet.h>


#define PROG_NAME "dhcpscan"
#define PROG_VER  "0.1"
#define PROG_COPYRIGHT "Copyright (c) 2016 Ilkka Virta <itvirta@iki.fi>"

/* 
 * DHCP scanner
 * 
 * TODO:
 *   x build and send dhcp requests to fish for replies
 *        x find mac address of interface to use 
 *   - check xid and chaddr on replies ? 
 *   x clean up output and debug output
 *       (interesting packets (always), init/send/listen cycle, 
 *        all received packets + checks, packets with hexdumps)
 *   x add interface and timestamp to printed report
 *   x handle command line args properly (getopt)
 *        interface to listen, timeout?, known DHCP servers? output debuglevel
 *   - allow ignoring known DHCP servers (IP, ether, both?)
 *   x drop privileges 
 *   - settable source ethernet address?
 *   - allow saving received packets?
 *   - add switch for listening on dhcp requests, too.
 *   - add possibility to send an email or run a program on match
 */


#define UDP_PORT_BOOTP_SERVER  67
#define UDP_PORT_BOOTP_CLIENT  68

#define BOOTP_HTYPE_ETHER   1
#define BOOTP_HLEN_ETHER    6
#define BOOTP_OP_REQUEST    1
#define BOOTP_OP_REPLY      2

#define BOOTP_CHADDR_LEN   16
#define BOOTP_SNAME_LEN    64
#define BOOTP_FILE_LEN    128
#define BOOTP_OPTIONS_LEN  64

#define DHCP_MIN_LEN      (sizeof(struct bootp) - BOOTP_OPTIONS_LEN)

/* A bootp packet */
struct bootp {
	uint8_t		bootp_op;				/* opcode */
	uint8_t		bootp_htype;				/* hardware address type */
	uint8_t		bootp_hlen;				/* hardware address length */
	uint8_t		bootp_hops;				/* hop count */
	uint32_t	bootp_xid;				/* transaction ID */
	uint16_t	bootp_secs;				/* seconds elapsed since boot started */
	uint16_t	bootp_flags;				/* bit flags */
	struct in_addr	bootp_ciaddr;				/* client IP addr */
	struct in_addr	bootp_yiaddr;				/* your IP addr */
	struct in_addr	bootp_siaddr;				/* next server IP addr */
	struct in_addr	bootp_giaddr;				/* relay agent IP addr */
	unsigned char	bootp_chaddr[BOOTP_CHADDR_LEN];		/* client hardware address */
	char		bootp_sname[BOOTP_SNAME_LEN];		/* server host name */
	char		bootp_file[BOOTP_FILE_LEN];		/* boot file name */
	unsigned char	bootp_options[BOOTP_OPTIONS_LEN];	/* options */
};

/* the interesting parts of a dhcp reply for the purposes of this program */
struct dhcp_reply {
	struct in_addr yiaddr;
	struct in_addr ip_src;
	struct ether_addr ether_src;
	struct ether_addr chaddr;
	uint32_t xid;
};

/* arbitrary limit, but simplifies the memory management (the joys of C programming) */
#define MAX_KNOWN_SERVERS 6

/* global configuration */
static struct {
	char *interface;		/* interface to listen on */
	unsigned verbosity;		/* verbosity level */
	uint32_t xid;			/* DHCP transaction ID */
	struct ether_addr my_ether;	/* my ethernet hardware address */
	unsigned scantime;		/* time to listen for replies, in seconds */
	unsigned listenonly;		/* listen only, don't send any queries */
	unsigned broadcast;		/* set broadcast flag on outgoing queries */
	unsigned quiet;			/* quiet mode, don't print caught replies */
	struct ether_addr known_servers[MAX_KNOWN_SERVERS];
	unsigned known_servers_count;
					/* servers "known" to us, they will not be reported on */
//	const char *mailto;		/* email address to send a message to when a reply caught - not implemented */
//	const char *commmand;		/* command to run when a reply caught                     - not implemented */
	
} config;


/*
 * main loop timeout 
 */
static volatile sig_atomic_t stop_scanning = 0;
void sig_alarm(int x)
{
        stop_scanning = 1;
}

/* print ethernet address to buffer with leading zeroes (unlike ether_ntoa() does) */
const char *ether_to_hex(struct ether_addr *e)
{
	static char buf[20];
	uint8_t *a = e->ether_addr_octet;
	snprintf(buf, 20, "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5]);
	return buf;
}


const char *timestamp_now(void)
{
	static char buf[30];
	struct timespec tp;
	clock_gettime(CLOCK_REALTIME, &tp);
	sprintf(buf, "[%d.%06d]", (int) tp.tv_sec, (int) tp.tv_nsec / 1000);
	return buf;
}

/* struct timeval as string */
const char *tv_timestamp(struct timeval *tv, unsigned usecs)
{
	static char buf[30];
	char timebuf[30];
	
	time_t t = tv->tv_sec;
	struct tm *tmp = localtime(&t);
	strftime(timebuf, 30, "%F %T", tmp);

	if (usecs) {	
		sprintf(buf, "[%s.%06d]", timebuf, (int) tv->tv_usec);
	} else {
		sprintf(buf, "[%s]", timebuf);
	}
	
	return buf;
}


/*
 * print debugging info
 * debug message levels
 *   0 - always printed, use printf instead
 *   1 - print init/send/listen cycle
 *   2 - print all received packets with checks made on them
 *   3 - all packets with hexdumps
 */

__attribute__((format(printf, 2, 3)))
int debug(unsigned msglevel, const char *fmt, ...)
{
	if (config.verbosity < msglevel) 
		return 0;
		
	va_list args;
	
	va_start(args, fmt);
	int r = vfprintf(stdout, fmt, args);
	va_end(args);
	
	return r;
}


libnet_t *init_libnet(const char *dev)
{
        char errbuf[LIBNET_ERRBUF_SIZE];
        libnet_t *l = libnet_init(LIBNET_LINK, dev, errbuf);
        
        if (l == NULL) {
                fprintf(stderr, "libnet_init(): %s\n", errbuf);
                exit(1);
        }
        return l;
}

/* Build a DHCP request packet
 */
struct bootp *build_dhcp_request(void)
{
	/* DHCP options we send in the query
	 */
	uint8_t dhcp_options[BOOTP_OPTIONS_LEN] = 
	   "\x63\x82\x53\x63" 		// DHCP magic cookie
	   "\x35\x01\x01"		// DHCP type 1 = discover
	   "\x3d\x07\x01"		// DHCP client id
	   "\x00\x00\x00\x00\x00\x00" 	// * placeholder for actual Ethernet address *
	   "\xff";			// end of options
	
	const unsigned dhcp_options_len = sizeof(dhcp_options);


	struct in_addr zero_addr;
	inet_aton("0.0.0.0", &zero_addr);
        
        struct bootp *bp = calloc(1, sizeof(struct bootp));
        
	bp->bootp_op     = BOOTP_OP_REQUEST;
	bp->bootp_htype  = BOOTP_HTYPE_ETHER;
	bp->bootp_hlen   = BOOTP_HLEN_ETHER;
	bp->bootp_hops   = 0;
	bp->bootp_xid    = config.xid;
	bp->bootp_secs   = 0;
	bp->bootp_flags  = config.broadcast ? htons(0x8000) : 0;
	
	bp->bootp_ciaddr = zero_addr;
	bp->bootp_yiaddr = zero_addr;
	bp->bootp_siaddr = zero_addr;
	bp->bootp_giaddr = zero_addr;

	memset(bp->bootp_chaddr, 0, BOOTP_CHADDR_LEN);
	memcpy(bp->bootp_chaddr, config.my_ether.ether_addr_octet, ETH_ALEN);
	memset(bp->bootp_sname, 0, BOOTP_SNAME_LEN);
	memset(bp->bootp_file,  0, BOOTP_FILE_LEN);
	memset(bp->bootp_sname, 0, BOOTP_SNAME_LEN);
	memset(bp->bootp_options, 0, BOOTP_OPTIONS_LEN);

	/* drop out out Ethernet address in the correct position in the options */ 
	uint8_t *dhcp_opt_chaddr = memmem(dhcp_options, dhcp_options_len, "\x3d\x07\x01", 3);
	if (! dhcp_opt_chaddr) {
		fprintf(stderr, "Err, can't find the location of client hw address option, look in build_dhcp_request() and fix this\n");
		abort();
	}
	memcpy(dhcp_opt_chaddr + 3, config.my_ether.ether_addr_octet, ETH_ALEN);

	memcpy(bp->bootp_options, dhcp_options, dhcp_options_len);

	return bp;
}

/*
 * build the lower level headers (UDP, IP, Ethernet)
 * and stick the DHCP packet there
 */
void build_headers(struct bootp *bp, libnet_t *l)
{
	libnet_ptag_t t;
	
	const char *ip_src = "0.0.0.0";
	const char *ip_dst = "255.255.255.255";
	
	debug(3, "libnet_build_udp() length set to %d = %d + %d\n",
	    (unsigned) LIBNET_UDP_H + (unsigned)sizeof(struct bootp), 
	    (unsigned)LIBNET_UDP_H, (unsigned) sizeof(struct bootp));

	/* src port, dst port, packet size, checksum, payload, payload size, libnet context, libnet ptag */
	t = libnet_build_udp(68, 67, LIBNET_UDP_H + sizeof(struct bootp),
	                     0, (uint8_t *) bp, sizeof(struct bootp), l, 0);
	if (t == -1) {
		fprintf(stderr, "libnet_build_udp() returned -1\n");
		exit(1);
	}
	                 
        /* length, tos, ip id, ip frag, ttl
           proto, checksum, source, dest 
           payload, payload len, libnet handle, "packet id" */
	in_addr_t src_ip = inet_addr(ip_src);
	in_addr_t dst_ip = inet_addr(ip_dst);
	debug(3, "libnet_build_ipv4() length set to %d = %d + %d + %d\n",
	    LIBNET_IPV4_H + LIBNET_UDP_H + (unsigned) sizeof(struct bootp),
	    LIBNET_IPV4_H, LIBNET_UDP_H, (unsigned) sizeof(struct bootp));
	    
	t = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + sizeof(struct bootp), 0, 0, 0, 16,
                              IPPROTO_UDP, 0, src_ip, dst_ip,
                              NULL, 0, l, 0);
	if (t == -1) {
		fprintf(stderr, "libnet_build_ipv4() returned -1\n");
		exit(1);
	}

	struct ether_addr *ether_dst = ether_aton("ff:ff:ff:ff:ff:ff");
	t = libnet_autobuild_ethernet(ether_dst->ether_addr_octet, ETHERTYPE_IP, l);
	if (t == -1) {
		fprintf(stderr, "libnet_autobuild_ethernet() returned -1\n");
		exit(1);
	}

}

void send_dhcp_packet(libnet_t *l)
{
	struct bootp *bp;
	bp = build_dhcp_request();
	build_headers(bp, l);
	
	if (libnet_write(l) == -1) {
		fprintf(stderr, "libnet_write() returned -1\n");
		exit(1);
	}
	free(bp);
}

/*
 * Initialize pcap library
 *   dev        - network interface to read from
 *   snaplen    - length of read buffer (pcap_set_snaplen)
 *   promisc    - put interface to promiscuous mode  (pcap_set_promisc)
 *   timeout_ms - read timeout in milliseconds (pcap_set_timeout)
 *   immediate  - ask pcap for "immediate mode"
 * return value
 *   pointer to pcap handle
 * on error
 *   NULL is returned and an error message printed
 *
 */
pcap_t *init_pcap(const char *dev, int snaplen, int promisc, int timeout_ms, int immediate)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;

	pcap_t *pcap = pcap_create(dev, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_create: %s: %s\n", dev, errbuf);
		return NULL;
	}

	if ((ret = pcap_set_snaplen(pcap, snaplen))) {
		fprintf(stderr, "pcap_set_snaplen: %d: %s\n", ret, pcap_geterr(pcap));
		return NULL;
	}
	if ((ret = pcap_set_promisc(pcap, promisc))) {
		fprintf(stderr, "pcap_set_promisc: %d: %s\n", ret, pcap_geterr(pcap));
		return NULL;
	}
	if ((ret = pcap_set_timeout(pcap, timeout_ms))) {
		fprintf(stderr, "pcap_set_timeout: %d: %s\n", ret, pcap_geterr(pcap));
		return NULL;
	}
	if ((ret = pcap_set_immediate_mode(pcap, immediate))) {
		fprintf(stderr, "pcap_set_immediate_mode: %d: %s\n", ret, pcap_geterr(pcap));
		return NULL;
	}
	if ((ret = pcap_activate(pcap))) {
		fprintf(stderr, "pcap_activate: %d: %s\n", ret, pcap_geterr(pcap));
		return NULL;
	}
	if (pcap_datalink(pcap) != DLT_EN10MB) {
		fprintf(stderr, "pcap_datalink: %s is not Ethernet\n", dev);
		return NULL;
	}

	return pcap;
}

/*
 * Compile and install a pcap filter 
 * return 0 if ok, 1 on failure
 */ 
int install_filter(pcap_t *pcap, const char *filter_src)
{
	struct bpf_program filter;
	int optimize = 1;
	int netmask = 0;
	if (pcap_compile(pcap, &filter, filter_src, optimize, netmask) == -1) {
		fprintf(stderr, "pcap_compile: failed: %s\n", pcap_geterr(pcap));
		return 1;
	}
	if (pcap_setfilter(pcap, &filter) == -1) {
		fprintf(stderr, "pcap_setfilter: failed: %s\n", pcap_geterr(pcap));
		return 1;
	}
	return 0;
}

/*
 * Setup the pcap library
 * return a pointer the pcap library handle or exit on error
 */
pcap_t *setup_pcap(const char *dev)
{
	pcap_t *pcap;

	int promisc = 0;
	int snaplen = 2040;
	int timeout_ms = 1000;
	int immediate = 1;

	const char *filter_src = "udp dst port bootpc";  /* only consider bootp replies */
	// const char *filter_src = "udp port bootpc";      /* all bootp packets */


	debug(1, "Opening pcap on interface %s\n", dev);
	debug(2, "  pcap parameters: snaplen %d, promisc %d, timeout %d, immediate %d\n", 
		snaplen, promisc, timeout_ms, immediate);

	//  pcap_open_live would do everything init_pcap does, except set immediate mode
	//pcap = pcap_open_live(dev, snaplen, promisc, timeout_ms, errbuf);

	pcap = init_pcap(dev, snaplen, promisc, timeout_ms, immediate);
	if (pcap == NULL) {
		exit(1);
	}

	if (install_filter(pcap, filter_src) != 0) {
		exit(1);
	}
	
	return pcap;
}


/* Print the packet out for debugging 
 */
void dump_packet(const uint8_t *packet, unsigned packet_len)
{
        debug(3, "    Packet contents:\n    ");
        int i;
        for (i = 0 ; i < packet_len ; i++) {
                debug(3, "%02x ", packet[i]);
                if (i % 16 == 15)
                	debug(3, "\n    ");
        }
	debug(3, "\n");
}

/* Parse the captured packet (Ethernet, IP, UDP headers and DHCP packet)
 * and fill the interesting parts into *rep if it was a DHCP packet
 *
 * return 0 if a DHCP packet was detected, 1 if it wasn't a valid DHCP packet
 */
int parse_dhcp_packet(const uint8_t *packet, unsigned packet_len, struct dhcp_reply *rep)
{
	/* the pcap filter we installed should only accept valid UDP packets, 
	   but just to be sure, check the Ethernet and IP headers too. */ 
	
	/* First of all, check that the packet is long enough to contain
	 * Ethernet and IP headers
	 */
	if (packet_len < sizeof(struct ether_header) + sizeof(struct ip)) {
		debug(2, "Packet too short for an IP packet\n");
		return 1;
	}

	dump_packet(packet, packet_len);

	
	/* Find the IP header, and check actual length of it */
	struct ether_header *etherh = (struct ether_header *) packet;	
	struct ip *iph = (struct ip *) (packet + sizeof(struct ether_header));
	int ipheaderlen = iph->ip_hl * 4;

	/* save the Ether and IP addresses, we need them later if this turns out to be an interesting packet */
	struct ether_addr ether_src;
	memcpy(&ether_src, etherh->ether_shost, sizeof(struct ether_addr));
	struct ether_addr ether_dst;
	memcpy(&ether_dst, etherh->ether_dhost, sizeof(struct ether_addr));
	struct in_addr ip_src = iph->ip_src;
	struct in_addr ip_dst = iph->ip_dst;

	/* print in parts since ether_to_hex() and inet_ntoa() return pointers to static buffers... */
	debug(2, "    Ethernet src: %s", ether_to_hex(&ether_src));
	debug(2, " dst: %s type: 0x%04x\n", ether_to_hex(&ether_dst), ntohs(etherh->ether_type));
//	debug(2, "    Ethernet src: %s", ether_to_hex((struct ether_addr *) etherh->ether_shost));
//	debug(2, " dst: %s type: 0x%04x\n", ether_to_hex((struct ether_addr *) etherh->ether_dhost), ntohs(etherh->ether_type));
	debug(2, "    IP ver: %d ihl: %d proto: %d len: %d", iph->ip_v, iph->ip_hl, iph->ip_p, ntohs(iph->ip_len));
	debug(2, " src %s",   inet_ntoa(ip_src));
	debug(2, " dst %s\n", inet_ntoa(ip_dst));
	
	
	/* Check that the Ether and IP headers contain values we expect */
	if (ntohs(etherh->ether_type) != ETHERTYPE_IP) {
		debug(2, "Ethertype != IP\n");
		return 1; // Not an IP packet...
	}
	if (iph->ip_v != 4  || iph->ip_hl < 5 ||  iph->ip_p != IPPROTO_UDP) {
		debug(2, "Not UDP or invalid IP header values\n");
		return 1; // IP header has invalid values, or packet is not an UDP packet
	}
	if (iph->ip_len < ipheaderlen + sizeof(struct udphdr)) {
		debug(2, "IP packet length too short\n");
		return 1; // IP packet length (in header) too short for a valid UDP packet
	}
	if (packet_len < sizeof(struct ether_header) + ipheaderlen + sizeof(struct udphdr)) {
		debug(2, "Packet too short for an UDP packet\n");
		return 1; // Captured length of packet is too short to parse it.
	}


	/* find the UDP header */
	unsigned udph_offset = (sizeof(struct ether_header) + ipheaderlen);
	struct udphdr *udph = (struct udphdr *) (packet + udph_offset);

	debug(2, "    UDP sport: %d dport: %d len: %d\n", ntohs(udph->uh_sport), ntohs(udph->uh_dport), ntohs(udph->uh_ulen));
	
	/* Check that the UDP packet contains what we expect 
	 * and is long enough to hold a DHCP packet */
	
	//if (ntohs(udph->uh_dport) != UDP_PORT_BOOTP_CLIENT) {
	//	return 1; // not destined to a bootp client ...
	//}
	
	if (ntohs(udph->uh_ulen) < sizeof(struct udphdr) + DHCP_MIN_LEN) {
		debug(2, "UDP length too short for DHCP\n");
		return 1; 
	}
	if (packet_len < sizeof(struct ether_header) + ipheaderlen + sizeof(struct udphdr) + DHCP_MIN_LEN) {
		debug(2, "Packet too short for a DHCP packet\n");
		return 1; 
	}


	/* Check the BOOTP/DHCP header for sanity..
	 */
	unsigned bootph_offset = udph_offset + sizeof(struct udphdr);
	struct bootp *bootphdr = (struct bootp *) (packet + bootph_offset);
	uint32_t xid = bootphdr->bootp_xid;
	struct in_addr yiaddr = bootphdr->bootp_yiaddr;
	struct in_addr giaddr = bootphdr->bootp_giaddr;
	(void) giaddr;
	struct ether_addr chaddr;
	memcpy(&chaddr, bootphdr->bootp_chaddr, sizeof(struct ether_addr));

	
	debug(2, "    BOOTP op: %d htype: %d hlen: %d hops: %d\n", 
	       bootphdr->bootp_op, bootphdr->bootp_htype, bootphdr->bootp_hlen, bootphdr->bootp_hops);
	debug(2, "    xid: 0x%08x secs: %d flags: %04x\n", 
	       bootphdr->bootp_xid, ntohs(bootphdr->bootp_secs), ntohs(bootphdr->bootp_flags));
	debug(2, "    chaddr: %s yiaddr: %s\n",
	       ether_to_hex(&chaddr), inet_ntoa(bootphdr->bootp_yiaddr));

	if (bootphdr->bootp_op    != BOOTP_OP_REPLY) {
		debug(2, "    Not a BOOTP reply, maybe a request\n");
		return 1;
	}
	
	if (bootphdr->bootp_htype != BOOTP_HTYPE_ETHER ||
	    bootphdr->bootp_hlen  != BOOTP_HLEN_ETHER) {
		debug(2, "    Wrong BOOTP htype or hlen\n");
		return 1;
	}
	
	/* Collect the actually interesting parts to a struct
	 */
	rep->ether_src = ether_src;
	rep->ip_src = ip_src;
	rep->chaddr = chaddr;
	rep->yiaddr = yiaddr;
	rep->xid = xid;

	return 0;		
}

/* 
 * listen for packets and parse them
 */
int scan_loop(pcap_t *pcap)
{
	signal(SIGALRM, sig_alarm);
	alarm(config.scantime);
	struct dhcp_reply *rep = calloc(1, sizeof(struct dhcp_reply));
	
	while(! stop_scanning) {
		struct pcap_pkthdr pcaph;
		const unsigned char *packet = pcap_next(pcap, &pcaph);
		
		if (packet == NULL) {
			continue;
		}
	        
		debug(2, "%s got packet, length %d captured %d%s pointer: %p\n", 
		    tv_timestamp(&pcaph.ts, 0), pcaph.len, pcaph.caplen, pcaph.caplen < pcaph.len ? " (PARTIAL)" : "", packet);
		
		if (pcaph.caplen < pcaph.len) {
			debug(2, "  captured only a partial packet, ignoring...\n");
			continue;
		}
		
		if (parse_dhcp_packet(packet, pcaph.caplen, rep)) {
			/* packet was invalid for some reason */
			continue;
		}
		
		/* TODO: check XID against what we are supposed to send, if we send something */
		/* TODO: check CHADDR against our own, if we sent something */
		
		/* Check against known (ignored) servers, if any are given */
		unsigned known = 0;
		int i;
		for (i = 0 ; i < config.known_servers_count ; i++ ) {
			if (memcmp(&config.known_servers[i], &rep->ether_src, ETH_ALEN) == 0) {
				/* We know about this server, ignore */
				known = 1;
				break;
			}
		}
		if (known) {
			debug(2, "  packet from known server, ignoring...\n");
			continue;
		}
		
		/* print a message of received dhcp reply */
		if (! config.quiet) {
			/* print in parts so ether_to_hex() and inet_ntoa() work */
			printf("%s Got BOOTP reply on %s from ether src %s IP src %s",
			     tv_timestamp(&pcaph.ts, 0), config.interface, ether_to_hex(&rep->ether_src), inet_ntoa(rep->ip_src));
			printf(" with yiaddr %s\n", inet_ntoa(rep->yiaddr));
		}
		
		/* send emails and run external commands here, if we want to support that at some point */		

	}
	return 0;
}

void add_known_server(const char *arg)
{
	int i = config.known_servers_count;
	if (i >= MAX_KNOWN_SERVERS) {
		fprintf(stderr, "Too many known servers! (Max is %d)\n", MAX_KNOWN_SERVERS);
		exit(1);
	}
	struct ether_addr *e = ether_aton(arg);
	if (! e) {
		fprintf(stderr, "Invalid server %s\n", arg);
		exit(1);
	}
	memcpy(&config.known_servers[i], e, ETH_ALEN);
	config.known_servers_count++;
}

void print_usage(void)
{
	printf("%s version %s %s\n", PROG_NAME, PROG_VER, PROG_COPYRIGHT);
	printf("usage: %s -i <iface> [other args...]\n", PROG_NAME);
	printf("args: \n");
	printf("  -h            show help\n");
//	printf("  -e <cmd>      command to execute when receiving a reply\n");
	printf("  -i <iface>    interface to listen on (mandatory)\n");
//	printf("  -m <email>    address to send an email to when receiving a reply \n");
	printf("  -n            listen only, don't send DHCP queries\n");
	printf("  -q            quiet mode, don't print even received replies\n");
	printf("  -s <eth addr> replies from this ethernet address will be ignored\n");
	printf("  -t <time>     listen time\n");
	printf("  -v            increase verbosity level, can be used multiple times\n");
	return;
}

/*
 * Parse command line args
 */
int parse_args(int argc, char *argv[])
{
	int c;
	while ((c = getopt(argc, argv, "hi:nqs:t:v")) != -1) {
		switch(c) {
		case 'b':
			config.broadcast = 1;
			break;
		case 'e':
			// config.execute = optarg;
			break;
		case 'h':
			print_usage();
			exit(0);
			break;
		case 'i':
			config.interface = optarg;
			break;
		case 'm':
			// config.mailto = optarg;
			break;
		case 'n':
			config.listenonly = 1;
			break;
		case 'q':
			config.quiet = 1;
			break;
		case 's':
			add_known_server(optarg);
			break;
		case 't':
			config.scantime = atoi(optarg);
			break;
		case 'v':
			config.verbosity += 1;
			break;
		case '?':
		default:
			/* Invalid / unknown option */
			/* getopt prints a warning */
			exit(1);
		}
	}
	if (config.quiet && config.verbosity) {
		fprintf(stderr, "Cannot be both quiet and verbose at the same time\n");
		exit(1);
	}
	return 0;
}

/*
 * make sure we're not running as root
 */
void drop_privileges(void)
{
	if (geteuid() != 0)
		return;		

	debug(1, "Running as root, dropping privileges\n");

	/* running as root? */
	if (getuid() != 0) {
		/* real UID != effective UID -> set-uid binary, drop back to the "real" uid */
		uid_t uid = getuid();
		if (setuid(uid)) {
			fprintf(stderr, "setuid(%d): %s\n", uid, strerror(errno));
			exit(1);
		}
	} else {
		/* otherwise find the account named 'nobody' and switch to that */
		struct passwd *pwent = getpwnam("nobody");
		if (! pwent) {
			fprintf(stderr, "Cannot get passwd entry for 'nobody'\n");
			exit(1);
		}
		if (setgid(pwent->pw_gid)) {
			fprintf(stderr, "setgid(nobody): %s\n", strerror(errno));
			exit(1);
		}
		if (setuid(pwent->pw_uid)) {
			fprintf(stderr, "setuid(nobody): %s\n", strerror(errno));
			exit(1);
		}
	}
	uid_t uid = getuid(), euid = geteuid();
	if (uid == 0 || euid == 0) {
		fprintf(stderr, "couldn't drop privileges (?)\n");
		exit(1);
	}

	debug(2, "  Now running as uid %d euid %d\n", uid, euid);
}

int main(int argc, char *argv[])
{
	/* Default config values */
	srandom(time(NULL));
	config.interface = NULL;
	config.verbosity = 0;
	config.scantime = 15;
	config.xid = random();
	config.listenonly = 0;
	config.broadcast = 0;
	
	parse_args(argc, argv);

	if (config.interface == NULL) {
		print_usage();
		exit(1);
	}

	pcap_t *pcap = setup_pcap(config.interface);
	libnet_t *lnet = init_libnet(config.interface);
	
	// libnet_get_hwaddr() returns a structure that's essentially the same, but still distinct
	// from struct ether_addr. Oh well.
	memcpy(config.my_ether.ether_addr_octet, libnet_get_hwaddr(lnet)->ether_addr_octet, ETH_ALEN);
	
	drop_privileges();

	for (int i = 0 ; i < config.known_servers_count ; i++ ) {
		debug(1, "Known server #%d: %s\n", i, ether_to_hex(&config.known_servers[i]));
	}

	if (! config.listenonly) {
		debug(1, "Sending DHCP query on %s (%s)\n", config.interface, ether_to_hex(&config.my_ether));
		send_dhcp_packet(lnet);
	}

	debug(1, "Listening for replies on iface %s for %d secs\n", 
		config.interface, config.scantime);

	scan_loop(pcap);

	pcap_close(pcap);
	

	return 0;
}



