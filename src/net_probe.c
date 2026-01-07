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
 *   - BSD (via netstat/sysctl)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "sentinel.h"
#include "platform.h"

/* ============================================================
 * Helper Functions
 * ============================================================ */

/* Safe string copy */
static void safe_strcpy(char *dest, const char *src, size_t dest_size) {
    if (dest_size == 0) return;
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
            snprintf(ip, ip_len, "%x:%x:%x:%x:%x:%x:%x:%x",
                     (a >> 16) & 0xFFFF, a & 0xFFFF,
                     (b >> 16) & 0xFFFF, b & 0xFFFF,
                     (c >> 16) & 0xFFFF, c & 0xFFFF,
                     (d >> 16) & 0xFFFF, d & 0xFFFF);
        } else {
            safe_strcpy(ip, hex, ip_len);
        }
    } else {
        /* IPv4 - /proc stores as little-endian hex */
        unsigned int addr;
        sscanf(hex, "%X", &addr);
        snprintf(ip, ip_len, "%u.%u.%u.%u",
                 addr & 0xFF,
                 (addr >> 8) & 0xFF,
                 (addr >> 16) & 0xFF,
                 (addr >> 24) & 0xFF);
    }
}

/* Get process name from pid via /proc */
static void get_process_name(pid_t pid, char *name, size_t name_len) {
    char path[64];
    FILE *f;
    
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    f = fopen(path, "r");
    if (f) {
        if (fgets(name, (int)name_len, f)) {
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

/* Find PID for a socket inode by scanning /proc/[pid]/fd */
static pid_t find_socket_pid(unsigned long inode) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return -1;
    
    struct dirent *proc_entry;
    while ((proc_entry = readdir(proc_dir)) != NULL) {
        /* Skip non-numeric entries */
        if (proc_entry->d_name[0] < '0' || proc_entry->d_name[0] > '9') {
            continue;
        }
        
        char fd_path[280];  /* /proc/ + PID + /fd + null */
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", proc_entry->d_name);
        
        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;
        
        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir)) != NULL) {
            char link_path[544];  /* fd_path + / + fd_name + null */
            char link_target[256];
            
            snprintf(link_path, sizeof(link_path), "%s/%s", 
                     fd_path, fd_entry->d_name);
            
            ssize_t len = readlink(link_path, link_target, 
                                   sizeof(link_target) - 1);
            if (len > 0) {
                link_target[len] = '\0';
                
                /* Check if this is our socket */
                unsigned long sock_inode;
                if (sscanf(link_target, "socket:[%lu]", &sock_inode) == 1) {
                    if (sock_inode == inode) {
                        closedir(fd_dir);
                        closedir(proc_dir);
                        return atoi(proc_entry->d_name);
                    }
                }
            }
        }
        closedir(fd_dir);
    }
    closedir(proc_dir);
    return -1;
}

/* Parse a /proc/net/tcp or tcp6 file */
static int parse_proc_net_tcp(const char *path, const char *proto,
                              net_listener_t *listeners, int max,
                              int *count, int is_ipv6) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;  /* Not an error - file might not exist */
    
    char line[512];
    /* Skip header line */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }
    
    while (fgets(line, sizeof(line), f) && *count < max) {
        char local_addr[64], remote_addr[64];
        unsigned int local_port, remote_port;
        unsigned int state;
        unsigned long inode;
        
        /* Parse: sl local_address remote_address st tx_queue:rx_queue
         *        tr:tm->when retrnsmt uid timeout inode */
        int parsed = sscanf(line,
            " %*d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X "
            "%*X:%*X %*X:%*X %*X %*u %*d %lu",
            local_addr, &local_port,
            remote_addr, &remote_port,
            &state, &inode);
        
        if (parsed < 6) continue;
        
        /* Only interested in LISTEN state (0x0A) for listeners */
        if (state != 0x0A) continue;
        
        net_listener_t *l = &listeners[*count];
        memset(l, 0, sizeof(*l));
        
        safe_strcpy(l->protocol, proto, sizeof(l->protocol));
        hex_to_ip(local_addr, l->local_addr, sizeof(l->local_addr), is_ipv6);
        l->local_port = (uint16_t)local_port;
        safe_strcpy(l->state, "LISTEN", sizeof(l->state));
        
        /* Find owning process */
        l->pid = find_socket_pid(inode);
        if (l->pid > 0) {
            get_process_name(l->pid, l->process_name, sizeof(l->process_name));
        }
        
        (*count)++;
    }
    
    fclose(f);
    return 0;
}

/* Parse UDP listeners (no state, just check if bound) */
static int parse_proc_net_udp(const char *path, const char *proto,
                              net_listener_t *listeners, int max,
                              int *count, int is_ipv6) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    char line[512];
    /* Skip header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }
    
    while (fgets(line, sizeof(line), f) && *count < max) {
        char local_addr[64];
        unsigned int local_port;
        unsigned long inode;
        
        int parsed = sscanf(line,
            " %*d: %64[0-9A-Fa-f]:%X %*s %*s %*X:%*X %*X:%*X %*X %*u %*d %lu",
            local_addr, &local_port, &inode);
        
        if (parsed < 3) continue;
        if (local_port == 0) continue;  /* Skip unbound */
        
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
    if (!listeners || !count) return -1;
    *count = 0;
    
    parse_proc_net_tcp("/proc/net/tcp", "tcp", listeners, max, count, 0);
    parse_proc_net_tcp("/proc/net/tcp6", "tcp6", listeners, max, count, 1);
    parse_proc_net_udp("/proc/net/udp", "udp", listeners, max, count, 0);
    parse_proc_net_udp("/proc/net/udp6", "udp6", listeners, max, count, 1);
    
    return 0;
}

int probe_network_connections(net_connection_t *conns, int max, int *count) {
    if (!conns || !count) return -1;
    *count = 0;
    
    /* Parse established TCP connections */
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) return -1;
    
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
            local_addr, &local_port,
            remote_addr, &remote_port,
            &state, &inode);
        
        if (parsed < 6) continue;
        
        /* Only established connections */
        if (state != 0x01) continue;
        
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
                               int *listen_count,
                               net_connection_t *conns, int max_conn,
                               int *conn_count) {
    FILE *fp;
    char line[512];
    
    /* Run netstat to get network state */
    fp = popen("netstat -an 2>/dev/null", "r");
    if (!fp) return -1;
    
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
        int parsed = sscanf(line, "%7s %*d %*d %127s %127s %31s",
                           proto, local, remote, state);
        
        if (parsed < 3) continue;
        
        /* Extract port from address (format: addr.port or *.port) */
        char *last_dot = strrchr(local, '.');
        if (!last_dot) continue;
        
        uint16_t local_port = (uint16_t)atoi(last_dot + 1);
        *last_dot = '\0';  /* Truncate to get just address */
        
        /* Convert * to 0.0.0.0 */
        char local_addr[64];
        if (strcmp(local, "*") == 0) {
            safe_strcpy(local_addr, "0.0.0.0", sizeof(local_addr));
        } else {
            safe_strcpy(local_addr, local, sizeof(local_addr));
        }
        
        /* Check if this is a listener */
        if (strcmp(state, "LISTEN") == 0 && *listen_count < max_listen) {
            net_listener_t *l = &listeners[*listen_count];
            memset(l, 0, sizeof(*l));
            
            safe_strcpy(l->protocol, proto, sizeof(l->protocol));
            safe_strcpy(l->local_addr, local_addr, sizeof(l->local_addr));
            l->local_port = local_port;
            safe_strcpy(l->state, "LISTEN", sizeof(l->state));
            l->pid = -1;  /* Will try to get via lsof */
            
            (*listen_count)++;
        }
        /* Check if this is an established connection */
        else if (strcmp(state, "ESTABLISHED") == 0 && conns && *conn_count < max_conn) {
            /* Parse remote address */
            char *remote_dot = strrchr(remote, '.');
            if (!remote_dot) continue;
            
            uint16_t remote_port = (uint16_t)atoi(remote_dot + 1);
            *remote_dot = '\0';
            
            net_connection_t *c = &conns[*conn_count];
            memset(c, 0, sizeof(*c));
            
            safe_strcpy(c->protocol, proto, sizeof(c->protocol));
            safe_strcpy(c->local_addr, local_addr, sizeof(c->local_addr));
            c->local_port = local_port;
            safe_strcpy(c->remote_addr, remote, sizeof(c->remote_addr));
            c->remote_port = remote_port;
            safe_strcpy(c->state, "ESTABLISHED", sizeof(c->state));
            c->pid = -1;
            
            (*conn_count)++;
        }
    }
    
    pclose(fp);
    return 0;
}

/* Use lsof to get process info for network connections */
static void enrich_with_lsof(net_listener_t *listeners, int listen_count,
                             net_connection_t *conns, int conn_count) {
    FILE *fp;
    char line[1024];
    
    /* Run lsof -i to get network connections with process info
     * Requires appropriate permissions */
    fp = popen("lsof -i -n -P -F pcn 2>/dev/null", "r");
    if (!fp) return;
    
    pid_t current_pid = -1;
    char current_name[256] = "";
    
    while (fgets(line, sizeof(line), fp)) {
        /* Remove newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        
        if (line[0] == 'p') {
            /* Process ID */
            current_pid = atoi(line + 1);
        } else if (line[0] == 'c') {
            /* Command name */
            safe_strcpy(current_name, line + 1, sizeof(current_name));
        } else if (line[0] == 'n') {
            /* Network address - format: n192.168.1.5:443 or n*:443 (LISTEN) */
            char *addr = line + 1;
            char *colon = strrchr(addr, ':');
            if (!colon) continue;
            
            uint16_t port = (uint16_t)atoi(colon + 1);
            
            /* Find matching listener */
            for (int i = 0; i < listen_count; i++) {
                if (listeners[i].local_port == port && listeners[i].pid == -1) {
                    listeners[i].pid = current_pid;
                    safe_strcpy(listeners[i].process_name, current_name,
                              sizeof(listeners[i].process_name));
                    break;
                }
            }
            
            /* Find matching connection */
            for (int i = 0; i < conn_count; i++) {
                if (conns[i].local_port == port && conns[i].pid == -1) {
                    conns[i].pid = current_pid;
                    safe_strcpy(conns[i].process_name, current_name,
                              sizeof(conns[i].process_name));
                    break;
                }
            }
        }
    }
    
    pclose(fp);
}

int probe_network_listeners(net_listener_t *listeners, int max, int *count) {
    if (!listeners || !count) return -1;
    *count = 0;
    
    int conn_count = 0;
    parse_netstat_macos(listeners, max, count, NULL, 0, &conn_count);
    
    /* Try to enrich with process info */
    enrich_with_lsof(listeners, *count, NULL, 0);
    
    return 0;
}

int probe_network_connections(net_connection_t *conns, int max, int *count) {
    if (!conns || !count) return -1;
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
 * BSD Network Probing (via netstat)
 * ============================================================ */

#ifdef PLATFORM_BSD

/* BSD uses similar approach to macOS - netstat parsing */

int probe_network_listeners(net_listener_t *listeners, int max, int *count) {
    if (!listeners || !count) return -1;
    *count = 0;
    
    FILE *fp = popen("netstat -an -p tcp 2>/dev/null | grep LISTEN", "r");
    if (!fp) return -1;
    
    char line[512];
    while (fgets(line, sizeof(line), fp) && *count < max) {
        char proto[8], local[128];
        char state[32];
        
        /* FreeBSD format: tcp4  0  0  *.22  *.*  LISTEN */
        if (sscanf(line, "%7s %*d %*d %127s %*s %31s",
                   proto, local, state) < 3) {
            continue;
        }
        
        if (strcmp(state, "LISTEN") != 0) continue;
        
        char *dot = strrchr(local, '.');
        if (!dot) continue;
        
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
        l->pid = -1;
        
        (*count)++;
    }
    
    pclose(fp);
    return 0;
}

int probe_network_connections(net_connection_t *conns, int max, int *count) {
    if (!conns || !count) return -1;
    *count = 0;
    
    FILE *fp = popen("netstat -an -p tcp 2>/dev/null | grep ESTABLISHED", "r");
    if (!fp) return -1;
    
    char line[512];
    while (fgets(line, sizeof(line), fp) && *count < max) {
        char proto[8], local[128], remote[128];
        
        if (sscanf(line, "%7s %*d %*d %127s %127s",
                   proto, local, remote) < 3) {
            continue;
        }
        
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
        c->pid = -1;
        
        (*count)++;
    }
    
    pclose(fp);
    return 0;
}

#endif /* PLATFORM_BSD */

/* ============================================================
 * Network Stats (Portable via getifaddrs or platform-specific)
 * ============================================================ */

int probe_network(network_info_t *net) {
    if (!net) return -1;
    
    memset(net, 0, sizeof(*net));
    
    /* Probe listeners */
    probe_network_listeners(net->listeners, MAX_LISTENERS, &net->listener_count);
    
    /* Probe active connections */
    probe_network_connections(net->connections, MAX_CONNECTIONS, 
                             &net->connection_count);
    
    /* Set summary counts */
    net->total_listening = net->listener_count;
    net->total_established = net->connection_count;
    
    return 0;
}
