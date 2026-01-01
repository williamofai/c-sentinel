/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * prober.c - System state capture via /proc filesystem
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include "sentinel.h"

/* ============================================================
 * Helper Functions
 * ============================================================ */

/* Safe string copy that always null-terminates */
static void safe_strcpy(char *dest, const char *src, size_t dest_size) {
    if (dest_size == 0) return;
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

/* Count open file descriptors for a process */
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

/* ============================================================
 * System Info Probing
 * ============================================================ */

int probe_system_info(system_info_t *info) {
    if (!info) return -1;
    
    memset(info, 0, sizeof(*info));
    
    /* Hostname */
    if (gethostname(info->hostname, sizeof(info->hostname)) != 0) {
        safe_strcpy(info->hostname, "unknown", sizeof(info->hostname));
    }
    
    /* Kernel version via uname */
    struct utsname uts;
    if (uname(&uts) == 0) {
        /* Truncate safely - kernel_version is 128 bytes */
        snprintf(info->kernel_version, sizeof(info->kernel_version),
                 "%.60s %.60s", uts.sysname, uts.release);
    }
    
    /* System info: memory, uptime, load */
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
    
    return 0;
}

/* ============================================================
 * Process Probing
 * ============================================================ */

/* Parse /proc/[pid]/stat for process info */
static int parse_proc_stat(pid_t pid, process_info_t *proc) {
    char path[128];
    char buf[2048];
    
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    
    /* Parse the stat line - format is complex due to comm field */
    /* pid (comm) state ppid ... */
    char *start = strchr(buf, '(');
    char *end = strrchr(buf, ')');
    
    if (!start || !end) return -1;
    
    /* Extract comm (process name) */
    size_t name_len = end - start - 1;
    if (name_len >= sizeof(proc->name)) {
        name_len = sizeof(proc->name) - 1;
    }
    memcpy(proc->name, start + 1, name_len);
    proc->name[name_len] = '\0';
    
    /* Parse fields after the comm */
    unsigned long vsize;
    long rss;
    unsigned long long starttime;
    
    int thread_count_tmp;
    
    int parsed = sscanf(end + 2, 
        "%c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
        "%*u %*u %*d %*d %*d %*d %d %*d %llu %lu %ld",
        &proc->state,
        &proc->ppid,
        &thread_count_tmp,
        &starttime,
        &vsize,
        &rss);
    
    if (parsed < 6) return -1;
    
    proc->pid = pid;
    proc->thread_count = (uint32_t)thread_count_tmp;
    proc->vsize_bytes = vsize;
    proc->rss_bytes = rss * sysconf(_SC_PAGESIZE);
    
    /* Calculate process age */
    /* starttime is in clock ticks since boot */
    long ticks_per_sec = sysconf(_SC_CLK_TCK);
    time_t now = time(NULL);
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        time_t boot_time = now - si.uptime;
        proc->start_time = boot_time + (starttime / ticks_per_sec);
        proc->age_seconds = now - proc->start_time;
    }
    
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

/* ============================================================
 * Config File Probing
 * ============================================================ */

/* Simple checksum - in production, use SHA256 */
static void compute_simple_checksum(const char *path, char *out, size_t out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        safe_strcpy(out, "error", out_size);
        return;
    }
    
    /* Simple hash for demonstration - replace with OpenSSL SHA256 */
    unsigned long hash = 5381;
    int c;
    while ((c = fgetc(f)) != EOF) {
        hash = ((hash << 5) + hash) + c;
    }
    fclose(f);
    
    snprintf(out, out_size, "%016lx", hash);
}

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
        
        compute_simple_checksum(paths[i], cfg->checksum, sizeof(cfg->checksum));
        
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
    
    return 0;
}
