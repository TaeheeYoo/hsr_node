/* (C) 2020 by Taehee Yoo <ap420073@gmail.com>
*
* Author: Taehee Yoo <ap420073@gmail.com>
*
* All Rights Reserved
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* Based on libgtpnl by Pablo Neira Ayuso <pablo@gnumonks.org>
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <inttypes.h>

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>

#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/hsr_netlink.h>

struct nlmsghdr *
genl_nlmsg_build_hdr(char *buf, uint16_t type, uint16_t flags, uint32_t seq,
		     uint8_t cmd)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST | flags;
	nlh->nlmsg_seq = seq;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = cmd;
	genl->version = 0;

	return nlh;
}

static int genl_ctrl_validate_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
		case CTRL_ATTR_FAMILY_ID:
			if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
				perror("mnl_attr_validate");
				return MNL_CB_ERROR;
			}
			break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int genl_ctrl_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[CTRL_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	int32_t *genl_id = data;

	mnl_attr_parse(nlh, sizeof(*genl), genl_ctrl_validate_cb, tb);
	if (tb[CTRL_ATTR_FAMILY_ID])
		*genl_id = mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
	else
		*genl_id = -1;

	return MNL_CB_OK;
}

struct mnl_socket *genl_socket_open(void)
{
	struct mnl_socket *nl;

	nl = mnl_socket_open(NETLINK_GENERIC);
	if (nl == NULL) {
		perror("mnl_socket_open");
		return NULL;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		return NULL;
	}

	return nl;
}

void genl_socket_close(struct mnl_socket *nl)
{
	mnl_socket_close(nl);
}

int genl_socket_talk(struct mnl_socket *nl, struct nlmsghdr *nlh, uint32_t seq,
		int (*cb)(const struct nlmsghdr *nlh, void *data),
		void *data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int ret;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		return -1;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, mnl_socket_get_portid(nl),
				cb, data);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}

	return ret;
}

static struct nlmsghdr *
genl_nlmsg_build_lookup(char *buf, const char *subsys_name)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = time(NULL);

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = CTRL_CMD_GETFAMILY;
	genl->version = 1;

	mnl_attr_put_u16(nlh, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL);
	mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, subsys_name);

	return nlh;
}

int genl_lookup_family(struct mnl_socket *nl, const char *family)
{
	int32_t genl_id;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = genl_nlmsg_build_lookup(buf, family);
	int err;

	err = genl_socket_talk(nl, nlh, nlh->nlmsg_seq, genl_ctrl_cb, &genl_id);
	if (err < 0)
		return -1;

	return genl_id;
}

static int genl_hsr_validate_cb(const struct nlattr *attr, void *data)
{
	int type = mnl_attr_get_type(attr);
	unsigned char addr[ETH_ALEN];
	char buf[IFNAMSIZ];
	int ifindex;

	if (mnl_attr_type_valid(attr, HSR_C_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case HSR_A_IFINDEX:
		ifindex = mnl_attr_get_u32(attr);
		if (if_indextoname(ifindex, buf) == NULL)
			snprintf(buf, IFNAMSIZ, "if%u", ifindex);
		printf("Interface: %s\n", buf);
		break;
	case HSR_A_NODE_ADDR:
		memcpy(addr, mnl_attr_get_payload(attr), ETH_ALEN);
		printf("MAC address A: %02x:%02x:%02x:%02x:%02x:%02x\n",
		       addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		break;
	case HSR_A_IF1_AGE:
		printf("Interface1 age: %ums\n", mnl_attr_get_u32(attr));
		break;
	case HSR_A_IF2_AGE:
		printf("Interface2 age: %ums\n", mnl_attr_get_u32(attr));
		break;
	case HSR_A_NODE_ADDR_B:
		memcpy(addr, mnl_attr_get_payload(attr), ETH_ALEN);
		printf("MAC address B: %02x:%02x:%02x:%02x:%02x:%02x\n",
		       addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		break;
	case HSR_A_IF1_SEQ:
		printf("Interface1 sequence: %u\n", mnl_attr_get_u16(attr));
		break;
	case HSR_A_IF2_SEQ:
		printf("Interface2 sequence: %u\n", mnl_attr_get_u16(attr));
		break;
	case HSR_A_IF1_IFINDEX:
		ifindex = mnl_attr_get_u32(attr);
		if (if_indextoname(ifindex, buf) == NULL)
			snprintf(buf, IFNAMSIZ, "if%u", ifindex);
		printf("Slave interface1: %s\n", buf);

		break;
	case HSR_A_IF2_IFINDEX:
		ifindex = mnl_attr_get_u32(attr);
		if (if_indextoname(ifindex, buf) == NULL)
			snprintf(buf, IFNAMSIZ, "if%u", ifindex);
		printf("Slave interface2: %s\n", buf);
		break;
	case HSR_A_ADDR_B_IFINDEX:
		ifindex = mnl_attr_get_u32(attr);
		printf("Address B index: %u\n", ifindex);
		break;
	default:
		printf("[TEST]%s %u type = %d \n", __func__, __LINE__, type);
		break;
	}
	return MNL_CB_OK;
}

static int genl_hsr_attr_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl;

	mnl_attr_parse(nlh, sizeof(*genl), genl_hsr_validate_cb, NULL);

	return MNL_CB_OK;
}

int hsr_list_nodes(int genl_id, int ifindex, struct mnl_socket *nl)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t seq = time(NULL);

	nlh = genl_nlmsg_build_hdr(buf, genl_id, NLM_F_EXCL | NLM_F_ACK, ++seq,
				   HSR_C_GET_NODE_LIST);

	mnl_attr_put_u32(nlh, HSR_A_IFINDEX, ifindex);

	if (genl_socket_talk(nl, nlh, seq, genl_hsr_attr_cb, NULL) < 0) {
		perror("genl_socket_talk");
		return 0;
	}

	return 0;
}

int hsr_status_node(int genl_id, int ifindex, struct mnl_socket *nl, char *lladdr)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t seq = time(NULL);

	nlh = genl_nlmsg_build_hdr(buf, genl_id, NLM_F_EXCL | NLM_F_ACK, ++seq,
				   HSR_C_GET_NODE_STATUS);

	mnl_attr_put_u32(nlh, HSR_A_IFINDEX, ifindex);

	mnl_attr_put_check(nlh, MNL_SOCKET_BUFFER_SIZE, HSR_A_NODE_ADDR, ETH_ALEN, lladdr);

	if (genl_socket_talk(nl, nlh, seq, genl_hsr_attr_cb, NULL) < 0) {
		perror("genl_socket_talk");
		return 0;
	}

	return 0;
}

int hsr_dump_nodes(int genl_id, struct mnl_socket *nl)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t seq = time(NULL);

	nlh = genl_nlmsg_build_hdr(buf, genl_id, NLM_F_DUMP, 0,
				   HSR_C_GET_NODE_LIST);

	if (genl_socket_talk(nl, nlh, seq, genl_hsr_attr_cb, NULL) < 0) {
		perror("genl_socket_talk");
		return 0;
	}

	return 0;
}

static int
list_nodes(int argc, char *argv[], int genl_id, struct mnl_socket *nl)
{
	int ifindex;

	ifindex = if_nametoindex(argv[2]);
	if (ifindex == 0) {
		perror("if_nametoindex");
		return -1;
	}

	return hsr_list_nodes(genl_id, ifindex , nl);
}

static int
status_node(int argc, char *argv[], int genl_id, struct mnl_socket *nl)
{
	int ifindex;
	char lladdr[ETH_ALEN];

	ifindex = if_nametoindex(argv[2]);
	if (ifindex == 0) {
		perror("if_nametoindex");
		return -1;
	}

	if (sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   lladdr, lladdr+1, lladdr+2, lladdr+3, lladdr+4, lladdr+5) != 6) {
		perror("Invalid mac address\n");
		return 0;
	}


	return hsr_status_node(genl_id, ifindex , nl, lladdr);
}

static int
dump_nodes(int argc, char *argv[], int genl_id, struct mnl_socket *nl)
{
	return hsr_dump_nodes(genl_id, nl);
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	int32_t genl_id;
	int ret;

	if (argc < 2) {
		printf("%s <list|dump> [<options,...>]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	nl = genl_socket_open();
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	genl_id = genl_lookup_family(nl, "HSR");
	if (genl_id < 0) {
		printf("not found hsr genl family\n");
		exit(EXIT_FAILURE);
	}

	if (strncmp(argv[1], "list", strlen(argv[1])) == 0) {
		if (argc < 3)
			exit(EXIT_FAILURE);
		ret = list_nodes(argc, argv, genl_id, nl);
	} else if (strncmp(argv[1], "status", strlen(argv[1])) == 0) {
		ret = status_node(argc, argv, genl_id, nl);
	} else if (strncmp(argv[1], "dump", strlen(argv[1])) == 0) {
		ret = dump_nodes(argc, argv, genl_id, nl);
	} else {
		printf("Unknown command `%s'\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl);

	return ret;
}
