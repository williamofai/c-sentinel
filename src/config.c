/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * config.c - Configuration file parsing
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>

#include "sentinel.h"

/* Configuration structure */
typedef struct {
    /* API keys */
    char anthropic_api_key[256];
    char openai_api_key[256];
    char ollama_host[256];
    
    /* Default model */
    char default_model[64];     /* "claude", "openai", "ollama" */
    char ollama_model[64];      /* e.g., "llama3.2:3b" */
    
    /* Thresholds */
    int zombie_threshold;       /* Alert if more than this many */
    int high_fd_threshold;      /* What counts as "high" FDs */
    int unusual_port_threshold; /* How many unusual ports before critical */
    double memory_warn_percent; /* Warn above this % */
    double memory_crit_percent; /* Critical above this % */
    double load_warn_factor;    /* Warn if load > cores * this */
    
    /* Webhook */
    char webhook_url[512];
    int webhook_on_critical;    /* Send webhook on critical findings */
    int webhook_on_warning;     /* Send webhook on warnings */
    
    /* Watch mode defaults */
    int default_interval;       /* Default --interval value */
    int network_by_default;     /* Always include network probe */
    
    /* Paths */
    char extra_configs[1024];   /* Comma-separated list of extra configs to probe */
    
} sentinel_config_t;

/* Default configuration */
static sentinel_config_t default_config = {
    .anthropic_api_key = "",
    .openai_api_key = "",
    .ollama_host = "http://localhost:11434",
    .default_model = "claude",
    .ollama_model = "llama3.2:3b",
    .zombie_threshold = 0,
    .high_fd_threshold = 100,
    .unusual_port_threshold = 3,
    .memory_warn_percent = 80.0,
    .memory_crit_percent = 95.0,
    .load_warn_factor = 1.5,
    .webhook_url = "",
    .webhook_on_critical = 1,
    .webhook_on_warning = 0,
    .default_interval = 60,
    .network_by_default = 0,
    .extra_configs = ""
};

/* Global config instance */
static sentinel_config_t g_config;
static int g_config_loaded = 0;

/* Get config directory path */
static void get_config_dir(char *path, size_t path_size) {
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    snprintf(path, path_size, "%s/.sentinel", home);
}

/* Get config file path */
static void get_config_path(char *path, size_t path_size) {
    char dir[256];
    get_config_dir(dir, sizeof(dir));
    snprintf(path, path_size, "%s/config", dir);
}

/* Trim whitespace from string */
static char* trim(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    
    return str;
}

/* Parse a single config line */
static void parse_config_line(sentinel_config_t *cfg, const char *key, const char *value) {
    /* API keys */
    if (strcmp(key, "anthropic_api_key") == 0) {
        strncpy(cfg->anthropic_api_key, value, sizeof(cfg->anthropic_api_key) - 1);
    } else if (strcmp(key, "openai_api_key") == 0) {
        strncpy(cfg->openai_api_key, value, sizeof(cfg->openai_api_key) - 1);
    } else if (strcmp(key, "ollama_host") == 0) {
        strncpy(cfg->ollama_host, value, sizeof(cfg->ollama_host) - 1);
    }
    /* Models */
    else if (strcmp(key, "default_model") == 0) {
        strncpy(cfg->default_model, value, sizeof(cfg->default_model) - 1);
    } else if (strcmp(key, "ollama_model") == 0) {
        strncpy(cfg->ollama_model, value, sizeof(cfg->ollama_model) - 1);
    }
    /* Thresholds */
    else if (strcmp(key, "zombie_threshold") == 0) {
        cfg->zombie_threshold = atoi(value);
    } else if (strcmp(key, "high_fd_threshold") == 0) {
        cfg->high_fd_threshold = atoi(value);
    } else if (strcmp(key, "unusual_port_threshold") == 0) {
        cfg->unusual_port_threshold = atoi(value);
    } else if (strcmp(key, "memory_warn_percent") == 0) {
        cfg->memory_warn_percent = atof(value);
    } else if (strcmp(key, "memory_crit_percent") == 0) {
        cfg->memory_crit_percent = atof(value);
    } else if (strcmp(key, "load_warn_factor") == 0) {
        cfg->load_warn_factor = atof(value);
    }
    /* Webhook */
    else if (strcmp(key, "webhook_url") == 0) {
        strncpy(cfg->webhook_url, value, sizeof(cfg->webhook_url) - 1);
    } else if (strcmp(key, "webhook_on_critical") == 0) {
        cfg->webhook_on_critical = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
    } else if (strcmp(key, "webhook_on_warning") == 0) {
        cfg->webhook_on_warning = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
    }
    /* Watch mode */
    else if (strcmp(key, "default_interval") == 0) {
        cfg->default_interval = atoi(value);
    } else if (strcmp(key, "network_by_default") == 0) {
        cfg->network_by_default = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
    }
    /* Paths */
    else if (strcmp(key, "extra_configs") == 0) {
        strncpy(cfg->extra_configs, value, sizeof(cfg->extra_configs) - 1);
    }
}

/* Load configuration file */
int config_load(void) {
    char path[512];
    FILE *f = NULL;
    
    /* Start with defaults */
    memcpy(&g_config, &default_config, sizeof(g_config));
    
    /* Also check environment variables */
    const char *env_key = getenv("ANTHROPIC_API_KEY");
    if (env_key) {
        strncpy(g_config.anthropic_api_key, env_key, sizeof(g_config.anthropic_api_key) - 1);
    }
    env_key = getenv("OPENAI_API_KEY");
    if (env_key) {
        strncpy(g_config.openai_api_key, env_key, sizeof(g_config.openai_api_key) - 1);
    }
    
    /* Try system config first (/etc/sentinel/config) */
    f = fopen("/etc/sentinel/config", "r");
    
    /* Fall back to user config (~/.sentinel/config) */
    if (!f) {
        get_config_path(path, sizeof(path));
        f = fopen(path, "r");
    }
    
    if (!f) {
        g_config_loaded = 1;
        return 0;  /* No config file is OK - use defaults + env */
    }
    
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and empty lines */
        char *trimmed = trim(line);
        if (*trimmed == '#' || *trimmed == '\0') continue;
        
        /* Find = separator */
        char *eq = strchr(trimmed, '=');
        if (!eq) continue;
        
        *eq = '\0';
        char *key = trim(trimmed);
        char *value = trim(eq + 1);
        
        /* Remove quotes from value */
        if (*value == '"' || *value == '\'') {
            value++;
            char *end = strrchr(value, *value == '"' ? '"' : '\'');
            if (end) *end = '\0';
        }
        
        parse_config_line(&g_config, key, value);
    }
    
    fclose(f);
    g_config_loaded = 1;
    return 0;
}

/* Get current config */
const sentinel_config_t* config_get(void) {
    if (!g_config_loaded) {
        config_load();
    }
    return &g_config;
}

/* Create default config file */
int config_create_default(void) {
    char dir[512], path[512];
    get_config_dir(dir, sizeof(dir));
    get_config_path(path, sizeof(path));
    
    /* Create directory */
    struct stat st;
    if (stat(dir, &st) != 0) {
        if (mkdir(dir, 0700) != 0) {
            return -1;
        }
    }
    
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    
    fprintf(f, "# C-Sentinel Configuration\n");
    fprintf(f, "# ~/.sentinel/config\n");
    fprintf(f, "\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "# API Keys (can also be set via environment variables)\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "# anthropic_api_key = sk-ant-...\n");
    fprintf(f, "# openai_api_key = sk-...\n");
    fprintf(f, "ollama_host = http://localhost:11434\n");
    fprintf(f, "\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "# Default AI Model\n");
    fprintf(f, "# Options: claude, openai, ollama\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "default_model = claude\n");
    fprintf(f, "ollama_model = llama3.2:3b\n");
    fprintf(f, "\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "# Thresholds\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "zombie_threshold = 0\n");
    fprintf(f, "high_fd_threshold = 100\n");
    fprintf(f, "unusual_port_threshold = 3\n");
    fprintf(f, "memory_warn_percent = 80.0\n");
    fprintf(f, "memory_crit_percent = 95.0\n");
    fprintf(f, "load_warn_factor = 1.5\n");
    fprintf(f, "\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "# Webhook Alerts\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "# webhook_url = https://hooks.slack.com/services/...\n");
    fprintf(f, "webhook_on_critical = true\n");
    fprintf(f, "webhook_on_warning = false\n");
    fprintf(f, "\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "# Watch Mode Defaults\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "default_interval = 60\n");
    fprintf(f, "network_by_default = false\n");
    fprintf(f, "\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "# Additional Config Files to Monitor\n");
    fprintf(f, "# Comma-separated paths\n");
    fprintf(f, "# ============================================================\n");
    fprintf(f, "# extra_configs = /etc/nginx/nginx.conf,/etc/mysql/my.cnf\n");
    
    fclose(f);
    
    /* Secure the file */
    chmod(path, 0600);
    
    return 0;
}

/* Print current config */
void config_print(void) {
    const sentinel_config_t *cfg = config_get();
    
    printf("\nC-Sentinel Configuration\n");
    printf("══════════════════════════════════════════════════\n");
    printf("\n");
    printf("API Keys:\n");
    printf("  Anthropic: %s\n", cfg->anthropic_api_key[0] ? "[set]" : "[not set]");
    printf("  OpenAI:    %s\n", cfg->openai_api_key[0] ? "[set]" : "[not set]");
    printf("  Ollama:    %s\n", cfg->ollama_host);
    printf("\n");
    printf("Models:\n");
    printf("  Default:   %s\n", cfg->default_model);
    printf("  Ollama:    %s\n", cfg->ollama_model);
    printf("\n");
    printf("Thresholds:\n");
    printf("  Zombie processes:   %d\n", cfg->zombie_threshold);
    printf("  High FD count:      %d\n", cfg->high_fd_threshold);
    printf("  Unusual ports:      %d\n", cfg->unusual_port_threshold);
    printf("  Memory warn:        %.1f%%\n", cfg->memory_warn_percent);
    printf("  Memory critical:    %.1f%%\n", cfg->memory_crit_percent);
    printf("  Load warn factor:   %.1f\n", cfg->load_warn_factor);
    printf("\n");
    printf("Webhook:\n");
    printf("  URL:              %s\n", cfg->webhook_url[0] ? cfg->webhook_url : "[not set]");
    printf("  On critical:      %s\n", cfg->webhook_on_critical ? "yes" : "no");
    printf("  On warning:       %s\n", cfg->webhook_on_warning ? "yes" : "no");
    printf("\n");
    printf("Watch Mode:\n");
    printf("  Default interval: %d seconds\n", cfg->default_interval);
    printf("  Network default:  %s\n", cfg->network_by_default ? "yes" : "no");
    printf("\n");
    
    char path[512];
    get_config_path(path, sizeof(path));
    printf("Config file: %s\n", path);
}
