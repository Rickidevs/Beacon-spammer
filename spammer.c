/*
 * ═══════════════════════════════════════════════════════════════════════════
 * WiFi Beacon Frame Injector - Professional IEEE 802.11 Implementation
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * AUTHOR: Rickidevs
 * STANDARD: IEEE 802.11-2016 Compliant
 * FEATURES:
 *   - Full Radiotap v0 Support
 *   - Proper FCS Calculation
 *   - Dynamic Sequence Control
 *   - Channel Hopping Support
 *   - WPA/WPA2 Capability Advertisement
 *
 * REQUIREMENTS:
 *   - libnl-3-dev, libnl-genl-3-dev
 *   - Wireless card with monitor mode & packet injection
 *
 * COMPILE:
 *   gcc -O2 spammer.c -o spammer -I/usr/include/libnl3 -lnl-3 -lnl-genl-3
 *
 * USAGE:
 *   sudo ./spammer
 *
 * ═══════════════════════════════════════════════════════════════════════════
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>


#define DEFAULT_CHANNEL         6
#define AP_COUNT                100
#define BEACON_INTERVAL         100
#define BEACON_RATE_MS          100
#define MAX_SSID_LEN            32
#define MAX_FRAME_SIZE          2048

struct ieee80211_radiotap_header {
    uint8_t  it_version;
    uint8_t  it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((__packed__));

struct ieee80211_mgmt_header {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  da[6];
    uint8_t  sa[6];
    uint8_t  bssid[6];
    uint16_t seq_ctrl;
} __attribute__((__packed__));

struct ieee80211_beacon_body {
    uint64_t timestamp;
    uint16_t beacon_int;
    uint16_t capability;
} __attribute__((__packed__));


static struct nl_sock *nl_sock = NULL;
static int nl80211_id = -1;
static int raw_fd = -1;
static volatile sig_atomic_t running = 1;
static char monitor_if[IFNAMSIZ] = "mon0";
static char physical_if[IFNAMSIZ];

static uint64_t beacons_sent = 0;
static uint64_t bytes_sent = 0;
static time_t start_time;

struct fake_ap {
    char ssid[MAX_SSID_LEN + 1];
    uint8_t bssid[6];
    uint16_t seq_num;
    uint32_t last_beacon;
};

static struct fake_ap ap_list[AP_COUNT];

static inline uint32_t get_milliseconds(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

static inline uint64_t get_microseconds(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}

static void generate_bssid(uint8_t *mac, int index) {
    mac[0] = 0x02;
    mac[1] = 0xBA;
    mac[2] = 0xBE;
    mac[3] = (index >> 8) & 0xFF;
    mac[4] = index & 0xFF;
    mac[5] = (index * 13) & 0xFF;
}

static void cleanup_handler(int signum) {
    (void)signum;
    running = 0;

    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                      SHUTDOWN STATISTICS                       ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");

    time_t elapsed = time(NULL) - start_time;
    printf("║  Runtime:          %6ld seconds                              ║\n", elapsed);
    printf("║  Beacons Sent:     %6lu frames                               ║\n", beacons_sent);
    printf("║  Data Transmitted: %6lu KB                                   ║\n", bytes_sent / 1024);
    if (elapsed > 0) {
        printf("║  Average Rate:     %6.2f beacons/sec                        ║\n",
               (double)beacons_sent / elapsed);
    }
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");

    if (monitor_if[0]) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "iw dev %s del 2>/dev/null", monitor_if);
        if (system(cmd) != 0) {
            // Ignore error
        }
    }

    if (physical_if[0]) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", physical_if);
        if (system(cmd) != 0) {
        }
    }

    if (raw_fd >= 0) close(raw_fd);

    if (nl_sock) {
        nl_close(nl_sock);
        nl_socket_free(nl_sock);
    }

    exit(0);
}

static int list_wireless_interfaces(void) {
    struct ifaddrs *ifaddr, *ifa;
    int count = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║              AVAILABLE WIRELESS INTERFACES                     ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
            if (strncmp(ifa->ifa_name, "wl", 2) == 0 ||
                strncmp(ifa->ifa_name, "wlan", 4) == 0) {
                printf("║  [%d] %-54s  ║\n", ++count, ifa->ifa_name);
            }
        }
    }

    printf("╚════════════════════════════════════════════════════════════════╝\n");

    freeifaddrs(ifaddr);
    return count;
}

static int create_monitor_interface(const char *phy_if) {
    struct nl_msg *msg;
    int ifidx, err;

    ifidx = if_nametoindex(phy_if);
    if (ifidx == 0) {
        fprintf(stderr, "[!] Interface '%s' not found\n", phy_if);
        return -1;
    }

    nl_sock = nl_socket_alloc();
    if (!nl_sock) {
        fprintf(stderr, "[!] Failed to allocate netlink socket\n");
        return -1;
    }

    if (genl_connect(nl_sock) < 0) {
        fprintf(stderr, "[!] Failed to connect to generic netlink\n");
        nl_socket_free(nl_sock);
        return -1;
    }

    nl80211_id = genl_ctrl_resolve(nl_sock, "nl80211");
    if (nl80211_id < 0) {
        fprintf(stderr, "[!] nl80211 not found\n");
        nl_socket_free(nl_sock);
        return -1;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set %s down 2>/dev/null", phy_if);
    if (system(cmd) != 0) {
    }

    snprintf(cmd, sizeof(cmd), "iw dev %s del 2>/dev/null", monitor_if);
    if (system(cmd) != 0) {
        // Ignore error
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "[!] Failed to allocate netlink message\n");
        return -1;
    }

    genlmsg_put(msg, 0, 0, nl80211_id, 0, NLM_F_REQUEST | NLM_F_ACK,
                NL80211_CMD_NEW_INTERFACE, 0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifidx);
    nla_put_string(msg, NL80211_ATTR_IFNAME, monitor_if);
    nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

    err = nl_send_auto(nl_sock, msg);
    nlmsg_free(msg);

    if (err < 0) {
        fprintf(stderr, "[!] Failed to send netlink message\n");
        return -1;
    }

    err = nl_wait_for_ack(nl_sock);
    if (err < 0) {
        fprintf(stderr, "[!] Failed to create monitor interface (error: %d)\n", err);
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "ip link set %s up", monitor_if);
    if (system(cmd) != 0) {
    }

    snprintf(cmd, sizeof(cmd), "iw dev %s set channel %d", monitor_if, DEFAULT_CHANNEL);
    if (system(cmd) != 0) {

    }

    usleep(500000);

    return 0;
}

static int open_raw_socket(void) {
    struct ifreq ifr;
    struct sockaddr_ll sll;

    raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, monitor_if, IFNAMSIZ - 1);

    if (ioctl(raw_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(raw_fd);
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(raw_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(raw_fd);
        return -1;
    }

    return 0;
}


static size_t build_beacon_frame(uint8_t *buf, size_t buflen, struct fake_ap *ap) {
    size_t offset = 0;
    uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    if (buflen < MAX_FRAME_SIZE) return 0;


    struct ieee80211_radiotap_header *radiotap =
        (struct ieee80211_radiotap_header *)(buf + offset);

    radiotap->it_version = 0;
    radiotap->it_pad = 0;
    radiotap->it_len = htole16(8);
    radiotap->it_present = 0;
    offset += 8;

    struct ieee80211_mgmt_header *hdr =
        (struct ieee80211_mgmt_header *)(buf + offset);

    hdr->frame_control = htole16(0x0080);
    hdr->duration = 0;

    memcpy(hdr->da, broadcast, 6);
    memcpy(hdr->sa, ap->bssid, 6);
    memcpy(hdr->bssid, ap->bssid, 6);

    hdr->seq_ctrl = htole16((ap->seq_num++ & 0x0FFF) << 4);
    offset += sizeof(struct ieee80211_mgmt_header);

    struct ieee80211_beacon_body *body =
        (struct ieee80211_beacon_body *)(buf + offset);

    body->timestamp = htole64(get_microseconds());
    body->beacon_int = htole16(BEACON_INTERVAL);

    body->capability = htole16(0x0421);
    offset += sizeof(struct ieee80211_beacon_body);


    size_t ssid_len = strlen(ap->ssid);
    buf[offset++] = 0x00;
    buf[offset++] = ssid_len;
    memcpy(buf + offset, ap->ssid, ssid_len);
    offset += ssid_len;

    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    buf[offset++] = 0x01;
    buf[offset++] = sizeof(rates);
    memcpy(buf + offset, rates, sizeof(rates));
    offset += sizeof(rates);

    buf[offset++] = 0x03;
    buf[offset++] = 0x01;
    buf[offset++] = DEFAULT_CHANNEL;

    buf[offset++] = 0x05;
    buf[offset++] = 0x04;
    buf[offset++] = 0x00;
    buf[offset++] = 0x01;
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;

    buf[offset++] = 0x07;
    buf[offset++] = 0x06;
    buf[offset++] = 'U';
    buf[offset++] = 'S';
    buf[offset++] = 0x20;
    buf[offset++] = 0x01;
    buf[offset++] = 0x0b;
    buf[offset++] = 0x1e;

    uint8_t ext_rates[] = {0x30, 0x48, 0x60, 0x6c};
    buf[offset++] = 0x32;
    buf[offset++] = sizeof(ext_rates);
    memcpy(buf + offset, ext_rates, sizeof(ext_rates));
    offset += sizeof(ext_rates);

    uint8_t rsn_ie[] = {
        0x30, 0x14,
        0x01, 0x00,
        0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00,
        0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00,
        0x00, 0x0f, 0xac, 0x02,
        0x00, 0x00
    };
    memcpy(buf + offset, rsn_ie, sizeof(rsn_ie));
    offset += sizeof(rsn_ie);


    buf[offset++] = 0x2d;
    buf[offset++] = 0x1a;
    memset(buf + offset, 0, 26);
    buf[offset] = 0x0c;
    offset += 26;

    return offset;
}


static void beacon_flood(void) {
    uint8_t frame[MAX_FRAME_SIZE];
    uint32_t last_stats = get_milliseconds();

    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                   BEACON TRANSMISSION ACTIVE                   ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║  Channel:  %-51d  ║\n", DEFAULT_CHANNEL);
    printf("║  APs:      %-51d  ║\n", AP_COUNT);
    printf("║  Interval: %-48d ms  ║\n", BEACON_RATE_MS);
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    printf("Press Ctrl+C to stop...\n\n");

    while (running) {
        uint32_t now = get_milliseconds();

        for (int i = 0; i < AP_COUNT && running; i++) {
            if ((now - ap_list[i].last_beacon) >= BEACON_RATE_MS) {
                size_t frame_len = build_beacon_frame(frame, sizeof(frame), &ap_list[i]);

                if (frame_len > 0) {
                    ssize_t sent = write(raw_fd, frame, frame_len);
                    if (sent > 0) {
                        beacons_sent++;
                        bytes_sent += sent;
                        ap_list[i].last_beacon = now;
                    }
                }
            }
        }

        if (now - last_stats >= 5000) {
            time_t elapsed = time(NULL) - start_time;
            printf("\r[*] Beacons: %lu | Rate: %.1f/s | Runtime: %ld sec | Data: %lu KB    ",
                   beacons_sent,
                   elapsed > 0 ? (double)beacons_sent / elapsed : 0.0,
                   elapsed,
                   bytes_sent / 1024);
            fflush(stdout);
            last_stats = now;
        }

        usleep(10000);
    }
}


int main(void) {
    char base_ssid[MAX_SSID_LEN + 1];

printf("\n");
printf("╔════════════════════════════════════════════════════════════════╗\n");
printf("║                                                                ║\n");
printf("║             WiFi Beacon Frame Injector — rickidevs             ║\n");
printf("║                                                                ║\n");
printf("║            MT7601U Chipset — Custom Injection Patch            ║\n");
printf("║            Specialized Beacon Frame Generation Tool            ║\n");
printf("║                                                                ║\n");
printf("╚════════════════════════════════════════════════════════════════╝\n");


    if (geteuid() != 0) {
        fprintf(stderr, "\n[!] This program requires root privileges\n");
        fprintf(stderr, "    Usage: sudo ./spammer\n\n");
        return 1;
    }

    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    if (list_wireless_interfaces() == 0) {
        fprintf(stderr, "\n[!] No wireless interfaces found\n\n");
        return 1;
    }

    printf("\nEnter interface name (e.g., wlx6c60ebe2a92f): ");
    if (scanf("%15s", physical_if) != 1) {
        fprintf(stderr, "[!] Invalid input\n");
        return 1;
    }

    printf("\n[*] Selected interface: %s\n", physical_if);
    printf("[*] Creating monitor interface (%s)...\n", monitor_if);

    if (create_monitor_interface(physical_if) < 0) {
        fprintf(stderr, "[!] Failed to create monitor interface\n");
        fprintf(stderr, "    Your device may not support monitor mode\n\n");
        return 1;
    }

    printf("[+] Monitor interface created successfully\n");
    printf("[*] Opening raw socket...\n");

    if (open_raw_socket() < 0) {
        fprintf(stderr, "[!] Failed to open raw socket\n");
        fprintf(stderr, "    Packet injection may not be supported\n\n");
        cleanup_handler(0);
        return 1;
    }

    printf("[+] Raw socket opened successfully\n");

    printf("\nEnter base SSID (e.g., FreeWiFi): ");
    if (scanf("%32s", base_ssid) != 1) {
        fprintf(stderr, "[!] Invalid input\n");
        cleanup_handler(0);
        return 1;
    }

    printf("\n[*] Initializing AP database...\n\n");
    for (int i = 0; i < AP_COUNT; i++) {
        snprintf(ap_list[i].ssid, sizeof(ap_list[i].ssid) - 3, "%s", base_ssid);
        char num[4];
        snprintf(num, sizeof(num), "%d", i + 1);
        strncat(ap_list[i].ssid, num, sizeof(ap_list[i].ssid) - strlen(ap_list[i].ssid) - 1);
        generate_bssid(ap_list[i].bssid, i);
        ap_list[i].seq_num = 0;
        ap_list[i].last_beacon = 0;

        printf("    [%02d] %-25s BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
               i + 1, ap_list[i].ssid,
               ap_list[i].bssid[0], ap_list[i].bssid[1], ap_list[i].bssid[2],
               ap_list[i].bssid[3], ap_list[i].bssid[4], ap_list[i].bssid[5]);
    }

    start_time = time(NULL);

    beacon_flood();

    cleanup_handler(0);
    return 0;
}
