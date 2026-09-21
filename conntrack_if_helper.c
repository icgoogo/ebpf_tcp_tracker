#include <unistd.h>

#include "conntrack_if_helper.h"
#include "log.h"

int set_iface_up(const char *ifname) {
    struct ifreq ifr;
    int sockfd, rv;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_error("get_iface_mac error opening socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    ifr.ifr_flags |= IFF_UP;
    rv = ioctl(sockfd, SIOCSIFFLAGS, &ifr);

    return rv;
}
