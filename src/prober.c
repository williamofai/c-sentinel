/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * prober.c - System state capture via /proc filesystem (Linux)
 *            and sysctl/mach APIs (macOS)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include "sentinel.h"
#include "platform.h"

/* ============================================================
 * Helper Functions
 * ============================================================ */

/* Safe string copy that always null-terminates */
static void safe_strcpy(char *dest, const char *src, size_t dest_size) {
    if (dest_size == 0) return;
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

/* ============================================================
 * File Descriptor Counting (Platform-Specific)
 * ============================================================ */

#ifdef PLATFORM_LINUX
/* Count open file descriptors for a process via /proc */
static int count_fds(pid_t pid) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/fd", pid);
    
    DIR *dir = opendir(path);
    if (!dir) return -1;
    
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') {
            count++;
        }
    }
    
    closedir(dir);
    return count;
}
#endif /* PLATFORM_LINUX */

#ifdef PLATFORM_MACOS
/* Count open file descriptors for a process via libproc */
static int count_fds(pid_t pid) {
    int buf_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (buf_size <= 0) return -1;
    return buf_size / (int)PROC_PIDLISTFD_SIZE;
}
#endif /* PLATFORM_MACOS */

/* ============================================================
 * System Info Probing
 * ============================================================ */

int probe_system_info(system_info_t *info) {
    if (!info) return -1;
    
    memset(info, 0, sizeof(*info));
    
    /* Hostname - portable */
    if (gethostname(info->hostname, sizeof(info->hostname)) != 0) {
        safe_strcpy(info->hostname, "unknown", sizeof(info->hostname));
    }
    
    /* Kernel version via uname - portable */
    struct utsname uts;
    if (uname(&uts) == 0) {
        snprintf(info->kernel_version, sizeof(info->kernel_version),
                 "%.60s %.60s", uts.sysname, uts.release);
    }

#ifdef PLATFORM_LINUX
    /* Linux: use sysinfo() */
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info->total_ram = si.totalram * si.mem_unit;
        info->free_ram = si.freeram * si.mem_unit;
        info->uptime_seconds = si.uptime;
        info->load_avg[0] = si.loads[0] / 65536.0;
        info->load_avg[1] = si.loads[1] / 65536.0;
        info->load_avg[2] = si.loads[2] / 65536.0;
    }
    
    /* Calculate boot time */
    info->probe_time = time(NULL);
    info->boot_time = info->probe_time - info->uptime_seconds;

#elif defined(PLATFORM_MACOS)
    /* macOS: use sysctl and mach APIs */
    
    /* Total RAM: sysctl hw.memsize */
    int64_t memsize = 0;
    size_t len = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &len, NULL, 0) == 0) {
        info->total_ram = (uint64_t)memsize;
    }
    
    /* Free RAM: mach vm_statistics64 */
    mach_port_t host_port = mach_host_self();
    vm_statistics64_data_t vm_stat;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    
    if (host_statistics64(host_port, HOST_VM_INFO64,
                          (host_info64_t)&vm_stat, &count) == KERN_SUCCESS) {
        vm_size_t page_size = 0;
        host_page_size(host_port, &page_size);
        
        /* Free memory = free + inactive (pages that can be reclaimed) */
        info->free_ram = ((uint64_t)vm_stat.free_count + 
                          (uint64_t)vm_stat.inactive_count) * page_size;
    }
    
    /* Uptime and boot time: sysctl kern.boottime */
    struct timeval boottime;
    len = sizeof(boottime);
    if (sysctlbyname("kern.boottime", &boottime, &len, NULL, 0) == 0) {
        info->boot_time = boottime.tv_sec;
        info->probe_time = time(NULL);
        info->uptime_seconds = (uint64_t)(info->probe_time - info->boot_time);
    }
    
    /* Load average: getloadavg() */
    double loadavg[3];
    if (getloadavg(loadavg, 3) != -1) {
        info->load_avg[0] = loadavg[0];
        info->load_avg[1] = loadavg[1];
        info->load_avg[2] = loadavg[2];
    }
#endif

    return 0;
}

/* ============================================================
 * Process Probing (Linux)
 * ============================================================ */

#ifdef PLATFORM_LINUX

/* Parse /proc/[pid]/stat for process info */
static int parse_proc_stat(pid_t pid, process_info_t *proc) {
    char path[128];
    char buf[2048];
    
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    
    if (fgets(buf, sizeof(buf), f) == NULL) {
        fclose(f);
        return -1;
    }
    fclose(f);
    
    /* Parse the stat line - format is complex due to comm field
     * which may contain spaces and parentheses */
    char *start = strchr(buf, '(');
    char *end = strrchr(buf, ')');
    if (!start || !end) return -1;
    
    /* Extract process name (inside parentheses) */
    size_t name_len = (size_t)(end - start - 1);
    if (name_len >= sizeof(proc->name)) {
        name_len = sizeof(proc->name) - 1;
    }
    memcpy(proc->name, start + 1, name_len);
    proc->name[name_len] = '\0';
    
    /* Parse fields after the comm field */
    char state;
    int ppid;
    unsigned long vsize;
    long rss;
    unsigned long long starttime;
    int num_threads;
    
    int parsed = sscanf(end + 2,
        "%c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
        "%*u %*u %*d %*d %*d %*d %d %*d %llu %lu %ld",
        &state, &ppid, &num_threads, &starttime, &vsize, &rss);
    
    if (parsed < 6) return -1;
    
    proc->pid = pid;
    proc->ppid = ppid;
    proc->state = state;
    proc->vsize_bytes = vsize;
    proc->rss_bytes = (uint64_t)rss * sysconf(_SC_PAGESIZE);
    proc->thread_count = (uint32_t)num_threads;
    
    /* Calculate process start time */
    long ticks_per_sec = sysconf(_SC_CLK_TCK);
    time_t boot_time = time(NULL);
    
    /* Get actual boot time from /proc/stat */
    FILE *stat_f = fopen("/proc/stat", "r");
    if (stat_f) {
        char line[256];
        while (fgets(line, sizeof(line), stat_f)) {
            if (strncmp(line, "btime ", 6) == 0) {
                boot_time = atol(line + 6);
                break;
            }
        }
        fclose(stat_f);
    }
    
    proc->start_time = boot_time + (time_t)(starttime / ticks_per_sec);
    proc->age_seconds = (uint64_t)(time(NULL) - proc->start_time);
    
    /* Heuristic: process might be stuck if it's old and in certain states */
    /* D = uninterruptible sleep, often indicates I/O issues */
    if (proc->state == 'D' && proc->age_seconds > 300) {
        proc->is_potentially_stuck = 1;
    }
    /* Z = zombie */
    if (proc->state == 'Z') {
        proc->is_potentially_stuck = 1;
    }
    
    return 0;
}

int probe_processes(process_info_t *procs, int max_procs, int *count) {
    if (!procs || !count) return -1;
    
    *count = 0;
    
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return -1;
    
    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL && *count < max_procs) {
        /* Skip non-numeric entries (not PIDs) */
        if (!isdigit(entry->d_name[0])) continue;
        
        pid_t pid = atoi(entry->d_name);
        if (pid <= 0) continue;
        
        process_info_t *proc = &procs[*count];
        memset(proc, 0, sizeof(*proc));
        
        if (parse_proc_stat(pid, proc) == 0) {
            /* Count open file descriptors */
            proc->open_fd_count = count_fds(pid);
            (*count)++;
        }
    }
    
    closedir(proc_dir);
    return 0;
}

#endif /* PLATFORM_LINUX */

/* ============================================================
 * Process Probing (macOS)
 * ============================================================ */

#ifdef PLATFORM_MACOS

/* Convert macOS process status to single-char state */
static char macos_state_to_char(uint32_t status) {
    switch (status) {
        case SIDL:    return 'I';  /* Idle (being created) */
        case SRUN:    return 'R';  /* Running */
        case SSLEEP:  return 'S';  /* Sleeping */
        case SSTOP:   return 'T';  /* Stopped */
        case SZOMB:   return 'Z';  /* Zombie */
        default:      return '?';
    }
}

/* Parse process info for a single PID using libproc */
static int parse_proc_macos(pid_t pid, process_info_t *proc) {
    struct proc_bsdinfo bsdinfo;
    
    /* Get basic process info */
    int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, 
                           &bsdinfo, sizeof(bsdinfo));
    if (ret <= 0) return -1;
    
    proc->pid = pid;
    proc->ppid = bsdinfo.pbi_ppid;
    
    /* Process name - try to get the full name first */
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
        char *name = strrchr(pathbuf, '/');
        if (name) {
            safe_strcpy(proc->name, name + 1, sizeof(proc->name));
        } else {
            safe_strcpy(proc->name, pathbuf, sizeof(proc->name));
        }
    } else {
        safe_strcpy(proc->name, bsdinfo.pbi_name, sizeof(proc->name));
        if (proc->name[0] == '\0') {
            safe_strcpy(proc->name, bsdinfo.pbi_comm, sizeof(proc->name));
        }
    }
    
    /* Process state */
    proc->state = macos_state_to_char(bsdinfo.pbi_status);
    
    /* Get task info for memory and threads */
    struct proc_taskinfo taskinfo;
    ret = proc_pidinfo(pid, PROC_PIDTASKINFO, 0,
                       &taskinfo, sizeof(taskinfo));
    if (ret > 0) {
        proc->rss_bytes = taskinfo.pti_resident_size;
        proc->vsize_bytes = taskinfo.pti_virtual_size;
        proc->thread_count = taskinfo.pti_threadnum;
    }
    
    /* Start time */
    proc->start_time = (time_t)bsdinfo.pbi_start_tvsec;
    proc->age_seconds = (uint64_t)(time(NULL) - proc->start_time);
    
    /* File descriptor count */
    proc->open_fd_count = (uint32_t)count_fds(pid);
    
    /* Heuristic: detect potentially stuck processes */
    proc->is_potentially_stuck = 0;
    if (proc->state == 'Z') {
        proc->is_potentially_stuck = 1;  /* Zombie */
    }
    
    return 0;
}

int probe_processes(process_info_t *procs, int max_procs, int *count) {
    if (!procs || !count) return -1;
    
    *count = 0;
    
    /* Get list of all process IDs */
    int num_pids = proc_listallpids(NULL, 0);
    if (num_pids <= 0) return -1;
    
    /* Allocate buffer for PIDs */
    size_t buf_size = (size_t)(num_pids + 20) * sizeof(pid_t);
    pid_t *pid_list = malloc(buf_size);
    if (!pid_list) return -1;
    
    num_pids = proc_listallpids(pid_list, (int)buf_size);
    if (num_pids <= 0) {
        free(pid_list);
        return -1;
    }
    
    /* Iterate through PIDs and gather info */
    for (int i = 0; i < num_pids && *count < max_procs; i++) {
        pid_t pid = pid_list[i];
        if (pid <= 0) continue;
        
        process_info_t *proc = &procs[*count];
        memset(proc, 0, sizeof(*proc));
        
        if (parse_proc_macos(pid, proc) == 0) {
            (*count)++;
        }
    }
    
    free(pid_list);
    return 0;
}

#endif /* PLATFORM_MACOS */

/* ============================================================
 * Config File Probing (Portable)
 * ============================================================ */

int probe_config_files(const char **paths, int path_count,
                       config_file_t *configs, int *config_count) {
    if (!configs || !config_count) return -1;
    
    *config_count = 0;
    
    for (int i = 0; i < path_count && *config_count < MAX_CONFIG_FILES; i++) {
        struct stat st;
        if (stat(paths[i], &st) != 0) continue;
        
        config_file_t *cfg = &configs[*config_count];
        memset(cfg, 0, sizeof(*cfg));
        
        safe_strcpy(cfg->path, paths[i], sizeof(cfg->path));
        cfg->size = st.st_size;
        cfg->mtime = st.st_mtime;
        cfg->ctime = st.st_ctime;
        cfg->permissions = st.st_mode;
        cfg->owner = st.st_uid;
        cfg->group = st.st_gid;
        
        /* Compute SHA256 checksum */
        sha256_file(paths[i], cfg->checksum, sizeof(cfg->checksum));
        
        (*config_count)++;
    }
    
    return 0;
}

/* ============================================================
 * Full Fingerprint Capture
 * ============================================================ */

int fingerprint_init(fingerprint_t *fp) {
    if (!fp) return -1;
    memset(fp, 0, sizeof(*fp));
    return 0;
}

int capture_fingerprint(fingerprint_t *fp, const char **config_paths,
                        int config_path_count) {
    if (!fp) return -1;
    
    fingerprint_init(fp);
    
    clock_t start = clock();
    
    /* Capture system info */
    if (probe_system_info(&fp->system) != 0) {
        fp->probe_errors++;
    }
    
    /* Capture process list */
    if (probe_processes(fp->processes, MAX_PROCS, &fp->process_count) != 0) {
        fp->probe_errors++;
    }
    
    /* Capture config files if specified */
    if (config_paths && config_path_count > 0) {
        if (probe_config_files(config_paths, config_path_count,
                               fp->configs, &fp->config_count) != 0) {
            fp->probe_errors++;
        }
    }
    
    clock_t end = clock();
    fp->probe_duration_ms = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    
    return fp->probe_errors > 0 ? -1 : 0;
}

/* ============================================================
 * Quick Analysis - Deterministic Pre-checks
 * ============================================================ */

int analyze_fingerprint_quick(const fingerprint_t *fp, quick_analysis_t *result) {
    if (!fp || !result) return -1;
    
    memset(result, 0, sizeof(*result));
    
    for (int i = 0; i < fp->process_count; i++) {
        const process_info_t *p = &fp->processes[i];
        
        /* Count zombies */
        if (p->state == 'Z') {
            result->zombie_process_count++;
        }
        
        /* High FD count (potential leak) - only flag if we could actually read FDs */
        /* Note: uint32 -1 wraps to ~4 billion, so add upper bound check */
        if (p->open_fd_count > 100 && p->open_fd_count < 100000) {
            result->high_fd_process_count++;
        }
        
        /* Long-running processes (>7 days) */
        if (p->age_seconds > 7 * 24 * 3600) {
            result->long_running_process_count++;
        }
    }
    
    /* Config file checks */
    for (int i = 0; i < fp->config_count; i++) {
        const config_file_t *c = &fp->configs[i];
        
        /* World-writable is usually bad */
        if (c->permissions & S_IWOTH) {
            result->config_permission_issues++;
        }
    }
    
    /* Network checks */
    result->unusual_listeners = fp->network.unusual_port_count;
    
    /* Count external connections (non-localhost) */
    for (int i = 0; i < fp->network.connection_count; i++) {
        const net_connection_t *c = &fp->network.connections[i];
        /* Check if remote address is not localhost */
        if (strcmp(c->remote_addr, "127.0.0.1") != 0 &&
            strcmp(c->remote_addr, "0.0.0.0") != 0 &&
            strncmp(c->remote_addr, "00000000", 8) != 0) {
            result->external_connections++;
        }
    }
    
    /* Calculate total issues for exit code */
    result->total_issues = result->zombie_process_count +
                           result->config_permission_issues +
                           result->unusual_listeners;
    
    return 0;
}
