#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <sys/socket.h>

#define BUFFER_SIZE 8192

// Simple wrapper to execute shell commands
static int run_cmd(const char *fmt, ...) {
    char cmd[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, args);
    va_end(args);
    int ret = system(cmd);
    if (ret != 0) fprintf(stderr, "[ERROR] Command failed: %s\n", cmd);
    return ret;
}

// Send netlink message and wait for ACK
static int send_nl_msg(int sock, struct nlmsghdr *nlh, const char *desc) {
    struct iovec iov = { .iov_base = nlh, .iov_len = nlh->nlmsg_len };
    struct msghdr msg = { .msg_name = NULL, .msg_namelen = 0,
                          .msg_iov = &iov, .msg_iovlen = 1 };

    if (sendmsg(sock, &msg, 0) < 0) { perror(desc); return -1; }

    char buf[BUFFER_SIZE];
    int len = recv(sock, buf, sizeof(buf), 0);
    if (len < 0) { perror(desc); return -1; }

    struct nlmsghdr *resp = (struct nlmsghdr *)buf;
    if (resp->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (err->error) {
            if (err->error == -EEXIST) { printf("[INFO] %s already exists\n", desc); return 1; }
            fprintf(stderr, "[ERROR] %s failed: %s\n", desc, strerror(-err->error));
            return -1;
        }
    }
    printf("[OK] %s succeeded\n", desc);
    return 0;
}

// Bring interface up (idempotent)
static int set_if_up(int sock, const char *ifname) {
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) { fprintf(stderr, "[ERROR] Interface '%s' does not exist\n", ifname); return -1; }

    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", ifname);
    FILE *f = fopen(path, "r");
    if (f) {
        char state[16];
        if (fgets(state, sizeof(state), f) && strncmp(state, "up", 2) == 0) {
            printf("[INFO] Interface '%s' already up\n", ifname);
            fclose(f);
            return 0;
        }
        fclose(f);
    }

    char buf[BUFFER_SIZE];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct ifinfomsg *ifi;

    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*ifi));
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();

    ifi = NLMSG_DATA(nlh);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex;
    ifi->ifi_flags = IFF_UP;
    ifi->ifi_change = IFF_UP;

    return send_nl_msg(sock, nlh, "Bring interface up");
}

// Create VRF master
static int create_vrf_master(int sock, const char *name, int table_id) {
    if (if_nametoindex(name)) { printf("[INFO] VRF master '%s' already exists\n", name); return 0; }

    char buf[BUFFER_SIZE];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct ifinfomsg *ifi;
    struct rtattr *rta, *linkinfo, *infodata, *vrf_table;

    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*ifi));
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();
    ifi = NLMSG_DATA(nlh);
    ifi->ifi_family = AF_UNSPEC;

    rta = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = IFLA_IFNAME;
    rta->rta_len = RTA_LENGTH(strlen(name)+1);
    strcpy(RTA_DATA(rta), name);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);

    linkinfo = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    linkinfo->rta_type = IFLA_LINKINFO;
    linkinfo->rta_len = RTA_LENGTH(0);
    nlh->nlmsg_len += RTA_ALIGN(linkinfo->rta_len);

    rta = (struct rtattr *)(((char *)linkinfo) + RTA_ALIGN(linkinfo->rta_len));
    rta->rta_type = IFLA_INFO_KIND;
    rta->rta_len = RTA_LENGTH(strlen("vrf")+1);
    strcpy(RTA_DATA(rta), "vrf");
    linkinfo->rta_len += RTA_ALIGN(rta->rta_len);
    nlh->nlmsg_len += RTA_ALIGN(rta->rta_len);

    infodata = (struct rtattr *)(((char *)linkinfo) + RTA_ALIGN(linkinfo->rta_len));
    infodata->rta_type = IFLA_INFO_DATA;
    infodata->rta_len = RTA_LENGTH(0);
    linkinfo->rta_len += RTA_ALIGN(infodata->rta_len);
    nlh->nlmsg_len += RTA_ALIGN(infodata->rta_len);

    vrf_table = (struct rtattr *)(((char *)infodata) + RTA_ALIGN(infodata->rta_len));
    vrf_table->rta_type = IFLA_VRF_TABLE;
    vrf_table->rta_len = RTA_LENGTH(sizeof(int));
    *(int *)RTA_DATA(vrf_table) = table_id;
    infodata->rta_len += RTA_ALIGN(vrf_table->rta_len);
    linkinfo->rta_len += RTA_ALIGN(vrf_table->rta_len);
    nlh->nlmsg_len += RTA_ALIGN(vrf_table->rta_len);

    return send_nl_msg(sock, nlh, "Create VRF master");
}

// Create veth pair
static int create_veth_pair(const char *veth1, const char *veth2) {
    if (if_nametoindex(veth1) && if_nametoindex(veth2)) {
        printf("[INFO] Veth pair '%s'<->'%s' already exists\n", veth1, veth2);
        return 0;
    }
    return run_cmd("ip link add %s type veth peer name %s", veth1, veth2);
}

// Enslave to VRF
static int enslave_to_master(int sock, const char *slave, const char *master) {
    int ifindex_slave = if_nametoindex(slave);
    int ifindex_master = if_nametoindex(master);
    if (!ifindex_slave || !ifindex_master) {
        fprintf(stderr, "[ERROR] Slave '%s' or master '%s' does not exist\n", slave, master);
        return -1;
    }

    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/master", slave);
    FILE *f = fopen(path, "r");
    int current_master = 0;
    if (f) { fscanf(f, "%d", &current_master); fclose(f); }
    if (current_master == ifindex_master) {
        printf("[INFO] Slave '%s' already enslaved to master '%s'\n", slave, master);
        return 0;
    }

    char buf[BUFFER_SIZE];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct ifinfomsg *ifi;
    struct rtattr *rta;

    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*ifi));
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();
    ifi = NLMSG_DATA(nlh);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex_slave;

    rta = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = IFLA_MASTER;
    rta->rta_len = RTA_LENGTH(sizeof(int));
    *(int *)RTA_DATA(rta) = ifindex_master;
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);

    return send_nl_msg(sock, nlh, "Enslave slave to master");
}

// Assign static IP
static int assign_ip(const char *ifname, const char *ip_with_mask) {
    return run_cmd("ip addr add %s dev %s 2>/dev/null || true", ip_with_mask, ifname);
}

// DHCP IP
static int dhcp_ip(const char *ifname) {
    return run_cmd("dhclient -v %s", ifname);
}

// Delete interface
static int delete_if(const char *ifname) { return run_cmd("ip link del %s 2>/dev/null || true", ifname); }

// Main creation function
int create_vrf_with_veth(const char *base_name, const char *ip_cidr, int use_dhcp) {
    char vrf[64], slave[64], peer[64];
    snprintf(vrf, sizeof(vrf), "%s-m", base_name);
    snprintf(slave, sizeof(slave), "%s", base_name);
    snprintf(peer, sizeof(peer), "v%s", base_name);

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) { perror("[ERROR] socket"); return -1; }

    create_vrf_master(sock, vrf, 1000);
    create_veth_pair(slave, peer);
    set_if_up(sock, vrf);
    set_if_up(sock, slave);
    set_if_up(sock, peer);
    enslave_to_master(sock, slave, vrf);

    if (use_dhcp) {
        dhcp_ip(slave);
    } else if (ip_cidr) {
        assign_ip(slave, ip_cidr);
        // Calculate peer IP for /31
        char peer_ip[32];
        unsigned int a,b,c,d;
        sscanf(ip_cidr, "%u.%u.%u.%u", &a,&b,&c,&d);
        d = d ^ 1; // flip last bit for /31 peer
        snprintf(peer_ip, sizeof(peer_ip), "%u.%u.%u.%u/%s", a,b,c,d, strchr(ip_cidr,'/')+1);
        assign_ip(peer, peer_ip);
    } else {
        // Default /31
        assign_ip(slave, "10.0.0.0/31");
        assign_ip(peer, "10.0.0.1/31");
    }

    close(sock);
    printf("[SUCCESS] VRF '%s' with veth '%s'<->'%s' created and up\n", vrf, slave, peer);
    return 0;
}

// Cleanup function
int cleanup_vrf(const char *base_name) {
    char vrf[64], slave[64], peer[64];
    snprintf(vrf, sizeof(vrf), "%s-m", base_name);
    snprintf(slave, sizeof(slave), "%s", base_name);
    snprintf(peer, sizeof(peer), "v%s", base_name);

    printf("[INFO] Cleaning up VRF '%s' and veth pair '%s'<->'%s'\n", vrf, slave, peer);
    delete_if(slave);  // deletes both ends of veth
    delete_if(vrf);    // deletes VRF
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <base_name> [--dhcp | --ip <veth_ip>/<mask>] [cleanup]\n", argv[0]); return 1; }

    const char *base = argv[1];
    int use_dhcp = 0;
    const char *ip_cidr = NULL;

    for (int i = 0; i < 100; i++) {
	    ip_cidr="10.30.40.1/31";
	    if(0 != create_vrf_with_veth(base, ip_cidr, use_dhcp)) assert(0);
	    cleanup_vrf(base);
    }
/*
    for(int i=2;i<argc;i++) {
        if(strcmp(argv[i],"--dhcp")==0) use_dhcp=1;
        else if(strcmp(argv[i],"--ip")==0 && i+1<argc) { ip_cidr=argv[++i]; }
        else if(strcmp(argv[i],"cleanup")==0) { cleanup_vrf(base); return 0; }
    }
    return create_vrf_with_veth(base, ip_cidr, use_dhcp);
*/
    return 0;
}
