/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * process_chain.h - Process ancestry walking
 *
 * This header provides functions to build and analyze process
 * chains (parent process ancestry) for security analysis.
 *
 * NOTE: This is a stub file. The actual implementation should
 * exist in process_chain.c in your main source tree.
 */

#ifndef PROCESS_CHAIN_H
#define PROCESS_CHAIN_H

#include <stdbool.h>
#include <sys/types.h>
#include "audit.h"

/*
 * Build process chain by walking parent PIDs
 * 
 * @param pid    Starting process ID
 * @param chain  Output chain structure (names[0] should already be set)
 * 
 * Walks up the process tree via /proc (Linux) or proc_pidinfo (macOS)
 * filling in chain->names[1..] with parent process names.
 */
void build_process_chain(pid_t pid, process_chain_t *chain);

/*
 * Check if a process chain looks suspicious
 * 
 * @param chain   Process chain to analyze
 * @param reason  Output: reason string if suspicious (optional)
 * @return        true if chain is suspicious
 *
 * Suspicious patterns include:
 *   - Web server (apache, nginx) spawning shell
 *   - Database (mysql, postgres) spawning shell
 *   - Init/systemd directly spawning user commands
 */
bool is_suspicious_chain(const process_chain_t *chain, const char **reason);

/*
 * Get process name by PID
 *
 * @param pid   Process ID
 * @param name  Output buffer
 * @param len   Buffer length
 * @return      0 on success, -1 on error
 */
int get_process_name_by_pid(pid_t pid, char *name, size_t len);

/*
 * Get parent PID
 *
 * @param pid   Process ID
 * @return      Parent PID, or 0 on error
 */
pid_t get_parent_pid(pid_t pid);

#endif /* PROCESS_CHAIN_H */
