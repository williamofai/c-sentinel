/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * net_probe.c - Network state probing (cross-platform)
 *
 * This file provides network probing functionality that works on:
 *   - Linux (via /proc/net)
 *   - macOS (via netstat/lsof parsing)
 *   - BSD (via netstat/sockstat)
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "platform.h"
#include "sentinel.h"

/* ============================================================
 * Helper Functions
 * ============================================================ */

/* Safe string copy */
static void safe_strcpy(char *dest, const char *src, size_t dest_size) {
    if (dest_size == 0)
        return;
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

/* ============================================================
 * Linux Network Probing (via /proc/net)
 * ============================================================ */

#ifdef PLATFORM_LINUX

/* Convert hex IP address from /proc/net to string */
static void hex_to_ip(const char *hex, char *ip, size_t ip_len, int is_ipv6) {
    if (is_ipv6) {
        /* IPv6 - parse 32 hex chars into 8 groups */
        /* /proc/net/tcp6 stores as 4 32-bit words in network order */
        unsigned int a, b, c, d;
        if (sscanf(hex, "%8X%8X%8X%8X", &a, &b, &c, &d) == 4) {
            snprintf(ip, ip_len, "%x:%x:%x:%x:%x:%x:%x:%x", (a >> 16) & 0xFFFF,
                     a & 0xFFFF, (b >> 16) & 0xFFFF, b & 0xFFFF,
                     (c >> 16) & 0xFFFF, c & 0xFFFF, (d >> 16) & 0xFFFF,
                     d & 0xFFFF);
        } else {
            safe_strcpy(ip, hex, ip_len);
        }
    } else {
        /* IPv4 - /proc stores as little-endian hex */
        unsigned int addr;
        sscanf(hex, "%X", &addr);
        snprintf(ip, ip_len, "%u.%u.%u.%u", addr & 0xFF, (addr >> 8) & 0xFF,
                 (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);
    }
}

/* Get process name from pid via /proc */
static void get_process_name(pid_t pid, char *name, size_t name_len) {
    char path[64];
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    f = fopen(path, "r");
    if (f) {
        if (fgets(name, name_len, f)) {
            /* Remove trailing newline */
            size_t len = strlen(name);
            if (len > 0 && name[len - 1] == '\n') {
                name[len - 1] = '\0';
            }
        }
        fclose(f);
    } else {
        safe_strcpy(name, "unknown", name_len);
    }
}

/* Find pid that owns a socket inode */
static pid_t find_socket_pid(unsigned long inode) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir)
        return -1;

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        /* Skip non-numeric entries */
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
            continue;

        pid_t pid = atoi(entry->d_name);
        if (pid <= 0)
            continue;

        /* Check each fd */
        char fd_dir[64];
        snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);

        DIR *fd_dirp = opendir(fd_dir);
        if (!fd_dirp)
            continue;

        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dirp)) != NULL) {
            char link_path[512];
            char link_target[256];
            ssize_t len;

            snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir,
                     fd_entry->d_name);
            len = readlink(link_path, link_target, sizeof(link_target) - 1);
            if (len > 0) {
                link_target[len] = '\0';
                unsigned long sock_inode;
                if (sscanf(link_target, "socket:[%lu]", &sock_inode) == 1) {
                    if (sock_inode == inode) {
                        closedir(fd_dirp);
                        closedir(proc_dir);
                        return pid;
                    }
                }
            }
        }
        closedir(fd_dirp);
    }
    closedir(proc_dir);
    return -1;
}

/* Parse /proc/net/tcp or tcp6 for listeners */
static int parse_proc_net_tcp(const char *path, const char *proto,
                              net_listener_t *listeners, int max, int *count,
                              int is_ipv6) {
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[512];
    /* Skip header line */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }

    while (fgets(line, sizeof(line), f) && *count < max) {
        char local_addr[64];
        unsigned int local_port;
        unsigned int state;
        unsigned long inode;

        int parsed = sscanf(
            line,
            " %*d: %64[0-9A-Fa-f]:%X %*s %X %*X:%*X %*X:%*X %*X %*u %*d %lu",
            local_addr, &local_port, &state, &inode);

        if (parsed < 4)
            continue;

        /* State 0x0A = TCP_LISTEN */
        if (state != 0x0A)
            continue;

        net_listener_t *l = &listeners[*count];
        memset(l, 0, sizeof(*l));

        safe_strcpy(l->protocol, proto, sizeof(l->protocol));
        hex_to_ip(local_addr, l->local_addr, sizeof(l->local_addr), is_ipv6);
        l->local_port = (uint16_t)local_port;
        safe_strcpy(l->state, "LISTEN", sizeof(l->state));

        l->pid = find_socket_pid(inode);
        if (l->pid > 0) {
            get_process_name(l->pid, l->process_name, sizeof(l->process_name));
        }

        (*count)++;
    }

    fclose(f);
    return 0;
}

/* Parse /proc/net/udp or udp6 for bound sockets */
static int parse_proc_net_udp(const char *path, const char *proto,
                              net_listener_t *listeners, int max, int *count,
                              int is_ipv6) {
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[512];
    /* Skip header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }

    while (fgets(line, sizeof(line), f) && *count < max) {
        char local_addr[64];
        unsigned int local_port;
        unsigned long inode;

        int parsed = sscanf(
            line,
            " %*d: %64[0-9A-Fa-f]:%X %*s %*s %*X:%*X %*X:%*X %*X %*u %*d %lu",
            local_addr, &local_port, &inode);

        if (parsed < 3)
            continue;
        if (local_port == 0)
            continue; /* Skip unbound */

        net_listener_t *l = &listeners[*count];
        memset(l, 0, sizeof(*l));

        safe_strcpy(l->protocol, proto, sizeof(l->protocol));
        hex_to_ip(local_addr, l->local_addr, sizeof(l->local_addr), is_ipv6);
        l->local_port = (uint16_t)local_port;
        safe_strcpy(l->state, "BOUND", sizeof(l->state));

        l->pid = find_socket_pid(inode);
        if (l->pid > 0) {
            get_process_name(l->pid, l->process_name, sizeof(l->process_name));
        }

        (*count)++;
    }

    fclose(f);
    return 0;
}

int probe_network_listeners(net_listener_t *listeners, int max, int *count) {
    if (!listeners || !count)
        return -1;
    *count = 0;

    parse_proc_net_tcp("/proc/net/tcp", "tcp", listeners, max, count, 0);
    parse_proc_net_tcp("/proc/net/tcp6", "tcp6", listeners, max, count, 1);
    parse_proc_net_udp("/proc/net/udp", "udp", listeners, max, count, 0);
    parse_proc_net_udp("/proc/net/udp6", "udp6", listeners, max, count, 1);

    return 0;
}

int probe_network_connections(net_connection_t *conns, int max, int *count) {
    if (!conns || !count)
        return -1;
    *count = 0;

    /* Parse established TCP connections */
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f)
        return -1;

    char line[512];
    /* Skip header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }

    while (fgets(line, sizeof(line), f) && *count < max) {
        char local_addr[64], remote_addr[64];
        unsigned int local_port, remote_port;
        unsigned int state;
        unsigned long inode;

        int parsed = sscanf(line,
                            " %*d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X "
                            "%*X:%*X %*X:%*X %*X %*u %*d %lu",
                            local_addr, &local_port, remote_addr, &remote_port,
                            &state, &inode);

        if (parsed < 6)
            continue;

        /* Only established connections (state 0x01) */
        if (state != 0x01)
            continue;

        net_connection_t *c = &conns[*count];
        memset(c, 0, sizeof(*c));

        safe_strcpy(c->protocol, "tcp", sizeof(c->protocol));
        hex_to_ip(local_addr, c->local_addr, sizeof(c->local_addr), 0);
        c->local_port = (uint16_t)local_port;
        hex_to_ip(remote_addr, c->remote_addr, sizeof(c->remote_addr), 0);
        c->remote_port = (uint16_t)remote_port;
        safe_strcpy(c->state, "ESTABLISHED", sizeof(c->state));

        c->pid = find_socket_pid(inode);
        if (c->pid > 0) {
            get_process_name(c->pid, c->process_name, sizeof(c->process_name));
        
        if (is_ipv6) {
            if (sscanf(line, "%*d: %32[0-9A-Fa-f]:%X %32[0-9A-Fa-f]:%X %X %*s %*s %*s %*d %*d %lu",
                       local_addr_hex, &local_port,
                       remote_addr_hex, &remote_port,
                       &state, &inode) != 6) continue;
        } else {
            if (sscanf(line, "%*d: %8[0-9A-Fa-f]:%X %8[0-9A-Fa-f]:%X %X %*s %*s %*s %*d %*d %lu",
                       local_addr_hex, &local_port,
                       remote_addr_hex, &remote_port,
                       &state, &inode) != 6) continue;
        }
        
        /* UDP sockets with state 07 are listening */
        if (state == 0x07 && local_port) {
            net_listener_t *l = &net->listeners[net->listener_count];
            
            snprintf(l->protocol, sizeof(l->protocol), is_ipv6 ? "udp6" : "udp");
            hex_to_ip(local_addr_hex, l->local_addr, sizeof(l->local_addr), is_ipv6);
            l->local_port = local_port;
            snprintf(l->state, sizeof(l->state), "LISTEN");
            
            l->pid = find_pid_for_inode(inode);
            if (l->pid > 0) {
                get_process_name(l->pid, l->process_name, sizeof(l->process_name));
            } else {
                snprintf(l->process_name, sizeof(l->process_name), "[kernel]");
            }
            
            net->listener_count++;
            net->total_listening++;
            
            if (!is_common_port(local_port)) {
                net->unusual_port_count++;
            }
        }

        (*count)++;
    }

    fclose(f);
    return 0;
}

#endif /* PLATFORM_LINUX */

/* ============================================================
 * macOS Network Probing (via lsof and netstat)
 * ============================================================ */

#ifdef PLATFORM_MACOS

/*
 * macOS approach: Use lsof for network connections with process info
 * Format: lsof -i -n -P
 *
 * Alternative: netstat -anv for connections (but no process info without root)
 *
 * We use a combination approach:
 * 1. netstat for connection details
 * 2. lsof when available for process attribution
 */

/* Parse netstat -an output for listeners and connections */
static int parse_netstat_macos(net_listener_t *listeners, int max_listen,
                               int *listen_count, net_connection_t *conns,
                               int max_conn, int *conn_count) {
    FILE *fp;
    char line[512];

    /* Run netstat to get network state */
    fp = popen("netstat -an 2>/dev/null", "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        /* Skip non-tcp/udp lines */
        if (strncmp(line, "tcp", 3) != 0 && strncmp(line, "udp", 3) != 0) {
            continue;
        }

        char proto[8];
        char local[128], remote[128];
        char state[32] = "";

        /* Parse netstat output format:
         * tcp4  0  0  *.443  *.*  LISTEN
         * tcp4  0  0  192.168.1.5.54321  172.217.14.206.443  ESTABLISHED
         */
        int parsed = sscanf(line, "%7s %*d %*d %127s %127s %31s", proto, local,
                            remote, state);

        if (parsed < 3)
            continue;

        /* Extract port from address (format: addr.port or *.port) */
        char *last_dot = strrchr(local, '.');
        if (!last_dot)
            continue;

        uint16_t port = (uint16_t)atoi(last_dot + 1);
        *last_dot = '\0'; /* Terminate address at port */

        /* Handle listeners */
        if (strcmp(state, "LISTEN") == 0 && listeners && listen_count) {
            if (*listen_count < max_listen) {
                net_listener_t *l = &listeners[*listen_count];
                memset(l, 0, sizeof(*l));

                safe_strcpy(l->protocol, proto, sizeof(l->protocol));
                if (strcmp(local, "*") == 0) {
                    safe_strcpy(l->local_addr, "0.0.0.0",
                                sizeof(l->local_addr));
                } else {
                    safe_strcpy(l->local_addr, local, sizeof(l->local_addr));
                }
                l->local_port = port;
                safe_strcpy(l->state, "LISTEN", sizeof(l->state));
                l->pid = -1;

                (*listen_count)++;
            }
        }

        /* Handle established connections */
        if (strcmp(state, "ESTABLISHED") == 0 && conns && conn_count) {
            if (*conn_count < max_conn) {
                net_connection_t *c = &conns[*conn_count];
                memset(c, 0, sizeof(*c));

                safe_strcpy(c->protocol, proto, sizeof(c->protocol));
                safe_strcpy(c->local_addr, local, sizeof(c->local_addr));
                c->local_port = port;

                /* Parse remote address */
                char *remote_dot = strrchr(remote, '.');
                if (remote_dot) {
                    c->remote_port = (uint16_t)atoi(remote_dot + 1);
                    *remote_dot = '\0';
                    safe_strcpy(c->remote_addr, remote, sizeof(c->remote_addr));
                }

                safe_strcpy(c->state, "ESTABLISHED", sizeof(c->state));
                c->pid = -1;

                (*conn_count)++;
            }
        }
    }

    pclose(fp);
    return 0;
}

/* Try to enrich with process info from lsof */
static void enrich_with_lsof(net_listener_t *listeners, int listen_count,
                             net_connection_t *conns, int conn_count) {
    FILE *fp = popen("lsof -i -n -P 2>/dev/null", "r");
    if (!fp)
        return;

    char line[512];
    /* Skip header */
    if (!fgets(line, sizeof(line), fp)) {
        pclose(fp);
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char command[64];
        int pid;
        char type[16];
        char name[256];

        /* Parse lsof output - format varies, but generally:
         * COMMAND  PID  USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME
         */
        if (sscanf(line, "%63s %d %*s %*s %15s %*s %*s %*s %255s", command,
                   &pid, type, name) < 4) {
            continue;
        }

        /* Extract port from NAME field */
        char *port_str = strrchr(name, ':');
        if (!port_str)
            continue;

        uint16_t port = (uint16_t)atoi(port_str + 1);

        /* Try to match with listeners */
        for (int i = 0; i < listen_count; i++) {
            if (listeners[i].local_port == port && listeners[i].pid == -1) {
                listeners[i].pid = pid;
                safe_strcpy(listeners[i].process_name, command,
                            sizeof(listeners[i].process_name));
                break;
            }
        }

        /* Try to match with connections */
        for (int i = 0; i < conn_count; i++) {
            if (conns[i].local_port == port && conns[i].pid == -1) {
                conns[i].pid = pid;
                safe_strcpy(conns[i].process_name, command,
                            sizeof(conns[i].process_name));
                break;
            }
        }
    }

    pclose(fp);
}

int probe_network_listeners(net_listener_t *listeners, int max, int *count) {
    if (!listeners || !count)
        return -1;
    *count = 0;

    int conn_count = 0;
    parse_netstat_macos(listeners, max, count, NULL, 0, &conn_count);

    /* Try to enrich with process info */
    enrich_with_lsof(listeners, *count, NULL, 0);

    return 0;
}

int probe_network_connections(net_connection_t *conns, int max, int *count) {
    if (!conns || !count)
        return -1;
    *count = 0;

    /* We need a dummy listener array for parse_netstat_macos */
    net_listener_t dummy[1];
    int dummy_count = 0;

    parse_netstat_macos(dummy, 0, &dummy_count, conns, max, count);

    /* Try to enrich with process info */
    enrich_with_lsof(NULL, 0, conns, *count);

    return 0;
}

#endif /* PLATFORM_MACOS */

/* ============================================================
 * BSD Network Probing (via netstat and sockstat)
 * ============================================================ */

#ifdef PLATFORM_BSD

/*
 * BSD network probing uses:
 * - netstat -an for connection state
 * - sockstat for process attribution (FreeBSD)
 * - fstat for process attribution (OpenBSD/NetBSD)
 *
 * netstat output format varies slightly between BSDs but generally:
 * tcp4  0  0  *.22  *.*  LISTEN
 * tcp4  0  0  192.168.1.5.54321  172.217.14.206.443  ESTABLISHED
 */

/* Try to get process info for a port using sockstat (FreeBSD) */
static void bsd_get_process_for_port(uint16_t port, pid_t *pid, char *name,
                                     size_t name_len) {
    char cmd[128];
    FILE *fp;

    *pid = -1;
    name[0] = '\0';

#if defined(__FreeBSD__) || defined(__DragonFly__)
    /* FreeBSD/DragonFly: use sockstat */
    snprintf(cmd, sizeof(cmd),
             "sockstat -4 -l 2>/dev/null | grep ':%d' | head -1", port);
    fp = popen(cmd, "r");
    if (fp) {
        char line[512];
        if (fgets(line, sizeof(line), fp)) {
            char user[32], process[64];
            int proc_pid;
            /* Format: USER COMMAND PID FD PROTO LOCAL FOREIGN */
            if (sscanf(line, "%31s %63s %d", user, process, &proc_pid) >= 3) {
                *pid = proc_pid;
                safe_strcpy(name, process, name_len);
            }
        }
        pclose(fp);
    }
#elif defined(__OpenBSD__) || defined(__NetBSD__)
    /* OpenBSD/NetBSD: use fstat */
    snprintf(cmd, sizeof(cmd),
             "fstat 2>/dev/null | grep 'internet.*:%d' | head -1", port);
    fp = popen(cmd, "r");
    if (fp) {
        char line[512];
        if (fgets(line, sizeof(line), fp)) {
            char user[32], process[64];
            int proc_pid;
            /* Format varies, but generally: USER COMMAND PID FD ... */
            if (sscanf(line, "%31s %63s %d", user, process, &proc_pid) >= 3) {
                *pid = proc_pid;
                safe_strcpy(name, process, name_len);
            }
        }
        pclose(fp);
    }
#else
    /* Generic BSD fallback - no process info */
    (void)cmd;
    (void)fp;
    (void)port;
#endif
}

int probe_network_listeners(net_listener_t *listeners, int max, int *count) {
    if (!listeners || !count)
        return -1;
    *count = 0;

    FILE *fp;
    char line[512];

    /* Run netstat for TCP listeners */
    fp = popen("netstat -an -p tcp 2>/dev/null", "r");
    if (!fp) {
        /* Try without -p on some BSDs */
        fp = popen("netstat -an 2>/dev/null | grep tcp", "r");
        if (!fp)
            return -1;
    }

    while (fgets(line, sizeof(line), fp) && *count < max) {
        char proto[8], local[128];
        char state[32] = "";

        /* BSD netstat format: proto recv-q send-q local foreign state */
        /* tcp4  0  0  *.22  *.*  LISTEN */
        if (sscanf(line, "%7s %*d %*d %127s %*s %31s", proto, local, state) <
            2) {
            continue;
        }

        /* Only LISTEN state */
        if (strcmp(state, "LISTEN") != 0)
            continue;

        /* Extract port from local address (format: addr.port or *.port) */
        char *dot = strrchr(local, '.');
        if (!dot)
            continue;

        net_listener_t *l = &listeners[*count];
        memset(l, 0, sizeof(*l));

        l->local_port = (uint16_t)atoi(dot + 1);
        *dot = '\0';

        safe_strcpy(l->protocol, proto, sizeof(l->protocol));
        if (strcmp(local, "*") == 0) {
            safe_strcpy(l->local_addr, "0.0.0.0", sizeof(l->local_addr));
        } else {
            safe_strcpy(l->local_addr, local, sizeof(l->local_addr));
        }
        safe_strcpy(l->state, "LISTEN", sizeof(l->state));

        /* Try to get process info */
        bsd_get_process_for_port(l->local_port, &l->pid, l->process_name,
                                 sizeof(l->process_name));

        (*count)++;
    }

    pclose(fp);

    /* Also check UDP bound ports */
    fp = popen("netstat -an -p udp 2>/dev/null", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp) && *count < max) {
            char proto[8], local[128];

            if (sscanf(line, "%7s %*d %*d %127s", proto, local) < 2) {
                continue;
            }

            /* Extract port */
            char *dot = strrchr(local, '.');
            if (!dot)
                continue;

            uint16_t port = (uint16_t)atoi(dot + 1);
            if (port == 0)
                continue; /* Skip unbound */

            *dot = '\0';

            net_listener_t *l = &listeners[*count];
            memset(l, 0, sizeof(*l));

            safe_strcpy(l->protocol, proto, sizeof(l->protocol));
            if (strcmp(local, "*") == 0) {
                safe_strcpy(l->local_addr, "0.0.0.0", sizeof(l->local_addr));
            } else {
                safe_strcpy(l->local_addr, local, sizeof(l->local_addr));
            }
            l->local_port = port;
            safe_strcpy(l->state, "BOUND", sizeof(l->state));

            bsd_get_process_for_port(l->local_port, &l->pid, l->process_name,
                                     sizeof(l->process_name));

            (*count)++;
        }
        pclose(fp);
    }

    return 0;
}

int probe_network_connections(net_connection_t *conns, int max, int *count) {
    if (!conns || !count)
        return -1;
    *count = 0;

    FILE *fp = popen("netstat -an -p tcp 2>/dev/null", "r");
    if (!fp) {
        fp = popen("netstat -an 2>/dev/null | grep tcp", "r");
        if (!fp)
            return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp) && *count < max) {
        char proto[8], local[128], remote[128];
        char state[32] = "";

        if (sscanf(line, "%7s %*d %*d %127s %127s %31s", proto, local, remote,
                   state) < 3) {
            continue;
        }

        /* Only ESTABLISHED connections */
        if (strcmp(state, "ESTABLISHED") != 0)
            continue;

        net_connection_t *c = &conns[*count];
        memset(c, 0, sizeof(*c));

        /* Parse local address */
        char *dot = strrchr(local, '.');
        if (dot) {
            c->local_port = (uint16_t)atoi(dot + 1);
            *dot = '\0';
            safe_strcpy(c->local_addr, local, sizeof(c->local_addr));
        }

        /* Parse remote address */
        dot = strrchr(remote, '.');
        if (dot) {
            c->remote_port = (uint16_t)atoi(dot + 1);
            *dot = '\0';
            safe_strcpy(c->remote_addr, remote, sizeof(c->remote_addr));
        }

        safe_strcpy(c->protocol, proto, sizeof(c->protocol));
        safe_strcpy(c->state, "ESTABLISHED", sizeof(c->state));

        /* Try to get process info */
        bsd_get_process_for_port(c->local_port, &c->pid, c->process_name,
                                 sizeof(c->process_name));

        (*count)++;
    }

    pclose(fp);
    return 0;
}

#endif /* PLATFORM_BSD */

/* ============================================================
 * Network Stats (Portable via platform-specific implementations)
 * ============================================================ */

int probe_network(network_info_t *net) {
    if (!net)
        return -1;

    memset(net, 0, sizeof(*net));

    /* Probe listeners */
    probe_network_listeners(net->listeners, MAX_LISTENERS,
                            &net->listener_count);

    /* Probe active connections */
    probe_network_connections(net->connections, MAX_CONNECTIONS,
                              &net->connection_count);

    /* Set summary counts */
    net->total_listening = net->listener_count;
    net->total_established = net->connection_count;

    return 0;
}
