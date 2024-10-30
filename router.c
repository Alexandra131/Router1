#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define valRT 80000
#define valARP 10
#define val_arp 0x0806
#define ipv4 0x0800

int contor_arp = 0;

uint8_t *IntArp(uint32_t ip, struct arp_table_entry *tabela_arp, int tabela_arp_len) {
    for (int i = 0; i < tabela_arp_len; i++) {
        if (tabela_arp[i].ip == ip) {
            return tabela_arp[i].mac;
        }
    }
    return NULL;
}

struct route_table_entry *gasit_tabela_potrivita(uint32_t ip_dest, struct route_table_entry *tabela_router, int tabela_router_len) {
    struct route_table_entry *rez = NULL;
    ip_dest = ntohl(ip_dest);

    for (int i = 0; i < tabela_router_len; i++) {
        if ((ip_dest & ntohl(tabela_router[i].mask)) == ntohl(tabela_router[i].prefix)) {
            if (rez == NULL || ntohl(rez->mask) < ntohl(tabela_router[i].mask)) {
                rez = &tabela_router[i];
            }
        }
    }

    return rez;
}




void NtohlTabelaPrefix(struct route_table_entry *intrare_tabela)
{
    intrare_tabela->prefix = ntohl(intrare_tabela->prefix);
}

void NtohlTabelaMask(struct route_table_entry *intrare_tabela)
{
	intrare_tabela->mask = ntohl(intrare_tabela->mask);
}


void HtonlTabelaPrefix(struct route_table_entry *intrare_tabela)
{   
    intrare_tabela->prefix = htonl(intrare_tabela->prefix);
}

void HtonlTabelaMask(struct route_table_entry *intrare_tabela)
{   
	intrare_tabela->mask = htonl(intrare_tabela->mask);
}

int comparator(const void *a, const void *b)
{
	const struct route_table_entry *a_copie = (const struct route_table_entry *)a;
	const struct route_table_entry *b_copie = (const struct route_table_entry *)b;

	if (a_copie->prefix == b_copie->prefix)
        return (a_copie->mask > b_copie->mask) ? 1 : -1;
	return (a_copie->prefix > b_copie->prefix) ? 1 : -1;
	
}

void ArpReq (struct arp_header *arp_hdr, struct ether_header *eth_hdr, int interface)
{
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(ipv4);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(2);
	memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6);
	arp_hdr->spa = arp_hdr->tpa;
	memcpy(arp_hdr->tha, eth_hdr->ether_dhost, 6);
	arp_hdr->tpa = inet_addr(get_interface_ip(interface));

				
}

void ArpRepl (struct arp_table_entry *tabela_arp, struct arp_header *arp_hdr, queue coada, struct route_table_entry *tabela_router, int tabela_router_len, struct ether_header *eth_hdr) 
{
	memcpy(tabela_arp[contor_arp].mac, arp_hdr->sha, 6);
	tabela_arp[contor_arp].ip = arp_hdr->spa;
	contor_arp++;
	while (!queue_empty(coada))
	{
		struct pachet *pkt = queue_deq(coada);
		struct iphdr *iphdr = (struct iphdr *)(pkt->buf + sizeof(struct ether_header));
		struct route_table_entry *tabela_potrivita = gasit_tabela_potrivita(iphdr->daddr, tabela_router, tabela_router_len);
		send_to_link(tabela_potrivita->interface, pkt->buf, pkt->len);
	}
}




void Atribuire(char *buf, int tip, int interface)
{
	
	struct pachet pachet;
	int dim = 0;
	if (tip == 0) {
		dim = sizeof(struct iphdr) + sizeof(struct icmphdr);
	} else {
		dim = 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8;
	}
	int dim2  = sizeof(struct ether_header) + sizeof(struct iphdr);
	struct iphdr *iphdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	iphdr->ihl = 5;
	iphdr->tos = 0;
	iphdr->tot_len = htons(dim); 
	iphdr->id = htons(1);
	iphdr->frag_off = 0;
	iphdr->ttl = 64;
	iphdr->protocol = 1;
	iphdr->check = htons(checksum((uint16_t *)iphdr, sizeof(struct iphdr)));
	iphdr->saddr = inet_addr(get_interface_ip(interface));
	iphdr->daddr = ((struct iphdr *)(buf + sizeof(struct ether_header)))->saddr; 


	struct icmphdr *icmphdr = malloc(sizeof(struct icmphdr));
	icmphdr->type = tip;
	icmphdr->code = 0;
	icmphdr->un.echo.id = 1;
	icmphdr->un.echo.sequence = 1;
	icmphdr->checksum = htons(checksum((uint16_t *)icmphdr, sizeof(struct icmphdr)));

	struct ether_header *eth_hdrIcmp = (struct ether_header *)pachet.buf; 
	eth_hdrIcmp->ether_type = htons(0x0800);
	memcpy(pachet.buf, eth_hdrIcmp, sizeof(struct ether_header));
	memcpy(pachet.buf + sizeof(struct ether_header), iphdr, sizeof(struct iphdr));
	memcpy(pachet.buf + dim2, icmphdr, sizeof(struct icmphdr));
	if (tip == 0) {
		send_to_link(interface, pachet.buf, sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));
	} else {
		send_to_link(interface, pachet.buf, (sizeof(struct ether_header) + dim));
	}

}


void GenerareReq(struct route_table_entry *tabela_potrivita, unsigned char *broadcast, int interface)
{
	struct pachet pachet;

	struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	get_interface_mac(tabela_potrivita->interface, arp_hdr->sha);
	arp_hdr->spa = inet_addr(get_interface_ip(tabela_potrivita->interface));
	memcpy(arp_hdr->tha, broadcast, 6);
	arp_hdr->tpa = tabela_potrivita->next_hop;
	
	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	eth_hdr->ether_type = htons(0x0806);
	memcpy(eth_hdr->ether_dhost, broadcast, 6);
	memcpy(pachet.buf, eth_hdr, sizeof(struct ether_header));
	memcpy(pachet.buf + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));
	free (arp_hdr);
	free (eth_hdr);
	send_to_link(tabela_potrivita->interface, pachet.buf, sizeof(struct ether_header) + sizeof(struct arp_header));
}




int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	struct route_table_entry *tabela_router = (struct route_table_entry *)malloc(valRT * sizeof(struct route_table_entry));
	struct arp_table_entry *tabela_arp = (struct arp_table_entry *)malloc(valARP * sizeof(struct arp_table_entry));
	
	int tabela_router_len = read_rtable(argv[1], tabela_router);
	int tabela_arp_len = valARP;

	queue coada = queue_create();


	for (int i = 0; i < tabela_router_len ; i++) {
		NtohlTabelaMask(&tabela_router[i]);
		NtohlTabelaPrefix(&tabela_router[i]); 
	}

	qsort(tabela_router, tabela_router_len, sizeof(struct route_table_entry), comparator);

	for (int i = 0; i < tabela_router_len; i++) {
		HtonlTabelaMask(&tabela_router[i]);
		HtonlTabelaPrefix(&tabela_router[i]);
	}
	unsigned char broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1)
	{
		int interface;
		size_t len;
		interface = recv_from_any_link(buf, &len);

		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		if (ntohs(eth_hdr->ether_type) == val_arp)
		{
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			if (ntohs(arp_hdr->op) == 1)
			{
				ArpReq (arp_hdr, eth_hdr, interface);
				send_to_link(interface, buf, len);
				continue;
			}

			if (ntohs(arp_hdr->op) == 2)
			{
				ArpRepl (tabela_arp, arp_hdr, coada, tabela_router, tabela_router_len, eth_hdr); 
			}
		}

		
		struct iphdr *iphdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		uint16_t cks_valoare = checksum((uint16_t *)iphdr, sizeof(struct iphdr));
		if (ntohs(cks_valoare) != 0)
		{
			continue;
		}

		if (ntohs(eth_hdr->ether_type) == ipv4)
		{
		
			if (iphdr->ttl <= 1)
			{
				Atribuire(buf, 11, interface);
				continue;
			} else {
				iphdr->ttl--;
			}

			if (iphdr->daddr == inet_addr(get_interface_ip(interface)))
			{
				Atribuire(buf, 0, interface);
				continue;
			}

		
			iphdr->check = 0; 
			iphdr->check = htons(checksum((uint16_t *)iphdr, sizeof(struct iphdr)));
			struct route_table_entry *tabela_potrivita = gasit_tabela_potrivita(iphdr->daddr, tabela_router, tabela_router_len);
			
			if (tabela_potrivita == NULL)
			{
				Atribuire(buf,3, interface);
				continue;
			}
			uint8_t *mac_val= IntArp(tabela_potrivita->next_hop, tabela_arp, tabela_arp_len);
			if (mac_val == NULL)
			{
				struct pachet *pachet = malloc(sizeof(struct pachet));
				memcpy(pachet->buf, buf, len);
				pachet->len = len;
				queue_enq(coada, (void *)pachet);
				GenerareReq(tabela_potrivita , broadcast, interface);
				continue;
			}

			memcpy(eth_hdr->ether_dhost, mac_val, sizeof(eth_hdr->ether_dhost));
			send_to_link(tabela_potrivita->interface, buf, len);
		}
	}
}