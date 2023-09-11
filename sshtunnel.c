// GNU General Public License
/*
 * Copyright (c) 2023 Beom Jin An
 *
 * 2023 Beom Jin An Created this.
 * sshtunnel Detect SSH tunneling
 */

#define _POSIX_SOURCE
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "sshtunnel.h"
#include "log.c/src/log.h"
#include "sshtunnel.skel.h"

#define GETPEERNAME 1
#define CONNECT 2
#define EXECVE 3
#define MAX_ARGS_KEY 259


static int logLevel = LOG_INFO; // set desired logging level here

volatile sig_atomic_t intSignal;

const char *argp_program_version = "sshtunnel 0.1";
const char *argp_program_bug_address =
    "https://github.com/qjawls2003/eBPF-Detect-SSH-Tunnels";
const char argp_program_doc[] =
    "Detect SSH tunneling\n"
    "\n"
    "USAGE: sudo ./sshtunnel [-a] [-p] [-v] [-w] [-h]\n"

    "EXAMPLES:\n"
    "   ./sshtunnel           # Detect SSH tunneling\n"
    "   ./sshtunnel -p        # printf all logs\n"
    "   ./sshtunnel -v        # verbose events\n"
    "   ./sshtunnel -w        # verbose warnings\n"
    "   ./sshtunnel -h        # show help\n";

static const struct argp_option opts[] = {
    {"print", 'p', NULL, 0, "printf all logs"},
    {"verbose", 'v', NULL, 0, "verbose debugging"},
    {"warning", 'w', NULL, 0, "verbose warnings"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

FILE *fp; // Save logs to File

static struct envVar {
  bool print;
  bool verbose;
  bool warning;
  bool all;
  int max_args;
} envVar = {.print = false, .verbose = false, .warning = false, .all = false,
  .max_args = DEFAULT_MAXARGS
};

void intHandler(int signal) {
  log_trace("Received interrupt signal, exiting");
  intSignal = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {

  if (level >= LIBBPF_DEBUG)
    return 0;

  return vfprintf(stderr, format, args);
}

struct ipData {
  char ipAddress[INET6_ADDRSTRLEN];
  uint16_t port;
};


char * print_args(const struct event e)
{
	int i, args_counter = 0;
  char * args = malloc(envVar.max_args);
  args[0] = '\0';
  int len;
	for (i = 0; i < e.args_size && args_counter < e.args_count; i++) {
    len = strlen(args);
		char c = e.args[i];

			if (c == '\0') {
				args_counter++;
				args[len] = ' ';
        args[len+1] = '\0';
			} else {
				args[len] = c;
        args[len+1] = '\0';
			}
	}
  len = strlen(args);
  args[len+1] = '\0';
  //printf("%s\n",args);
  return args;
}

struct ipData ipHelper(struct sockaddr_in6 *ipRaw) {
  struct ipData ipRes = {0};
  switch (ipRaw->sin6_family) {
  case AF_INET: { // IPv4
    struct sockaddr_in *ip = (struct sockaddr_in *)ipRaw;
    inet_ntop(AF_INET, &(ip->sin_addr), ipRes.ipAddress, INET_ADDRSTRLEN);
    ipRes.port = htons(ip->sin_port);
    log_trace("Converting sockaddr to IPv4 address Successful: %s %d",
              ipRes.ipAddress, ipRes.port);
    return ipRes;
  }
  case AF_INET6: { // IPv6
    struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)ipRaw;
    inet_ntop(AF_INET6, &(ip6->sin6_addr), ipRes.ipAddress, INET6_ADDRSTRLEN);
    ipRes.port = htons(ip6->sin6_port);
    log_trace("Converting sockaddr to IPv6 address Successful: %s %d",
              ipRes.ipAddress, ipRes.port);
    return ipRes;
  }
  default:
    log_trace("Converting sockaddr_in to IP address Not Successful");
    return ipRes;
  }
}

char *getUser(uid_t uid) {
  log_trace("Entering getUser(%d)", uid);
  long bufferSize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufferSize == -1) {
    bufferSize = 16384;
  }
  char *user = (char *)malloc(bufferSize);
  struct passwd *pwd = getpwuid(uid);
  if (pwd == NULL) {
    log_debug("Unable to find username for UID %d", uid);
    char tmp[3] = "n/a";
    strcpy(user, tmp);
  } else {
    strcpy(user, pwd->pw_name);
  }
  log_trace("Exiting getUser(%d) with User: %s", uid, user);
  return user;
}
/*
pid_t getPPID(pid_t pid) {
  log_trace("Entering getPPID(%d)", pid);
  char file[1000] = {0};
  pid_t ppid = 1;
  sprintf(file, "/proc/%d/stat", pid);
  FILE *f = fopen(file, "r");
  if (f == NULL) {
    log_debug("Failed to open %s, returning default PID 1", file);
    return ppid;
  }
  fscanf(f, "%*d %*s %*c %d", &ppid);
  fclose(f);
  log_trace("Exiting getPPID(%d) and returning %d", pid, ppid);
  return ppid;
}

char *getCommand(pid_t pid) {
  log_trace("Entering getCommand(%d)", pid);
  char file[1000] = {0};
  char *comm = (char *)malloc(1000 * sizeof(char));
  sprintf(file, "/proc/%d/stat", pid);
  FILE *f = fopen(file, "r");
  if (f == NULL) {
    log_debug("Failed to open %s, returning empty command", file);
    return comm;
  }
  fscanf(f, "%*d %s %*c %*d", comm);
  fclose(f);
  log_trace("Exiting getCommand(%d) and returning %s", pid, comm);
  return comm;
}
*/

uid_t getUID(pid_t pid) {
  log_trace("Entering getUID(%d)", pid);
  uid_t uid = 0;
  if (pid == 1) {
    log_debug("Attempted getUID() on PID 1, returning %d", uid);
    return uid;
  }
  char file[1000] = {0};
  sprintf(file, "/proc/%d/status", pid);
  FILE *f = fopen(file, "r");
  if (f == NULL) {
    log_debug("Failed to open %s, returning empty UID", file);
    return uid;
  }
  char tmp[256];
  int lines = 9;
  while (lines--) {
    fgets(tmp, 256, f);
  }
  sscanf(tmp, "Uid:\t%d\t", &uid);
  fclose(f);
  log_trace("Exiting getUID(%d) and returning %d", pid, uid);
  return uid;
}


void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
  log_trace("%s", "Entering handle_event()");
  struct data_t *m = data;
  struct ipData sockData = ipHelper(&m->addr);

  // timestamp
  time_t t;
  struct tm *tm;
  char ts[64];
  t = time(NULL);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%c", tm);

  int addrErr;
  int userErr;
  uid_t org_user;
  log_trace("%s", "Getting the user BPF map object");
  int userMap = bpf_obj_get("/sys/fs/bpf/raw_user"); // PID -> user 
  if (userMap <= 0) {
    log_debug("%s", "No file descriptor returned for the user BPF map object");
  } else {
    log_trace("Looking up PPID %d in the user BPF map", m->ppid);
    userErr = bpf_map_lookup_elem(userMap, &m->ppid, &org_user);
  }

  if (userErr == 0) {
    log_trace("Ancestor user found");
  } else {
    log_trace("Ancestor user not found");
  }



  int addrMap = bpf_obj_get("/sys/fs/bpf/addresses"); // pid -> IP data
  if (addrMap <= 0) {
    log_debug("No addr map file descriptor returned for the port BPF map object");
  }


  if (m->type_id == CONNECT) {
    pid_t pid = m->ppid;
    struct ipData remoteData;
    addrErr = bpf_map_lookup_elem(addrMap, &pid, &remoteData); //get the origin of SSH tunnel
    userErr = bpf_map_lookup_elem(userMap, &pid, &org_user); 
    if (addrErr != 0) {
          log_trace("Couldn't find a corresponding sockaddr_in for the %d sshd process",pid);
          return; //not a tunnel
    } else {
          log_trace("Found a corresponding sockaddr_in for the sshd process");
    }
    if (userErr != 0) {
          log_trace("Couldn't find a corresponding user for the sshd process");
          return; //not a tunnel
    } else {
          log_trace("Found a corresponding user for the sshd process");
    }
    if (sockData.port == 0) {
      return;
    }
    char *originalUser;
    if (userErr == 0) {
      uid_t originalUID = getUID(pid);
      originalUser = getUser(originalUID);
      log_trace("OriginalUser found, %s", originalUser);
    } else { 
      originalUser = getUser(m->uid);
      log_trace("OriginalUser not found, %s", originalUser);
    }
    if (fp == NULL) {
        log_info("Log file could not be opened");
    }
    /*
    fprintf(fp,
            "{\"timestamp\":%ld,\"pid\":%d,\"ppid\":%d,\"uid\":%d,"
            "\"currentUser\":\"%s\",\"originalUser\":\"%s\",\"command\":\"%s\","
            "\"ip\":\"%s\",\"port\":%d}\n",
            t, m->pid, m->ppid, m->uid, currentUser, originalUser, m->command,
            sockData.ipAddress, sockData.port);
    fflush(fp);
    */
    if (envVar.print) {
      printf("A SSH tunnel detected from remote IP: %s:%d going to %s:%d \n",
      remoteData.ipAddress, remoteData.port, sockData.ipAddress, sockData.port);
      /*
      printf("%-8s %-6d %-6d %-6d %-16s %-16s %-16s %-16d\n", ts,
             m->pid, m->ppid, m->uid, originalUser, m->command,
             sockData.ipAddress, sockData.port);
      */
    }
  
  } else if (m->type_id == EXECVE) {
    log_info("User started SSH");

  } else if (m->type_id == GETPEERNAME) {
    if (addrMap){
      bpf_map_update_elem(addrMap, &m->pid, &sockData, BPF_ANY);
      log_trace("Updated %d PID for sshd",m->pid);
    }
  } else {
    log_info("Unexpected event sent");
  }

  log_trace("Exiting handle_event()");
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz) {
  printf("lost event\n");
}

static int parse_arg(int key, char *arg, struct argp_state *state) {
  long int max_args;
  switch (key) {
  case 'p':
    envVar.print = true;
    break;
  case 'v':
    envVar.verbose = true;
    logLevel = LOG_TRACE;
    break;
  case 'a':
    envVar.all = true;
    break;
  case 'w':
    envVar.warning = true;
    logLevel = LOG_DEBUG;
    break;
  case 'h':
    argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
    break;
  case MAX_ARGS_KEY:
		errno = 0;
		max_args = strtol(arg, NULL, 10);
		if (errno || max_args < 1 || max_args > TOTAL_MAX_ARGS) {
			fprintf(stderr, "Invalid MAX_ARGS %s, should be in [1, %d] range\n",
					arg, TOTAL_MAX_ARGS);

			argp_usage(state);
		}
		envVar.max_args = max_args;
		break;
  }
  return 0;
}



int main(int argc, char **argv) {

  static const struct argp argp = {
      .options = opts,
      .parser = parse_arg,
      .doc = argp_program_doc,
  };
  int argErr = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (argErr)
    return argErr;
  log_info("%s", "Starting program...");
  log_set_level(logLevel);
  if (envVar.print) {
    /*
    printf("%-24s %-6s %-6s %-6s %-16s %-16s %-16s %-16s %-16s %-6s\n",
           "Timestamp", "PID", "PPID", "UID", "Current User", "Origin User",
           "Command", "IP Address", "Port", "Command Args");
    */
    printf("Detecting SSH tunnel going through this box... \n");
  }

  fp = fopen("/var/log/sshtunnel.log", "a"); // open file
  if (fp == NULL) {
    log_info("Log file could not be created or opened");
    return -1;
  }
  log_trace("%s", "Setting LIBBPF options");
  libbpf_set_print(libbpf_print_fn);
  char log_buf[128 * 1024];
  LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_buf = log_buf,
              .kernel_log_size = sizeof(log_buf), .kernel_log_level = 1, );

  log_trace("%s", "Opening BPF skeleton object");
  struct sshtunnel_bpf *skel = sshtunnel_bpf__open_opts(&opts);
  if (!skel) {
    log_trace("%s", "Error while opening BPF skeleton object");
    return EXIT_FAILURE;
  }

  int err = 0;

  log_trace("%s", "Loading BPF skeleton object");
  err = sshtunnel_bpf__load(skel);
  // Print the verifier log
  /*
        for (int i=0; i < 10000; i++) {
                if (log_buf[i] == 0 && log_buf[i+1] == 0) {
                        break;
                }
                printf("%c", log_buf[i]);
        }
  */
  if (err) {
    log_trace("%s", "Error while loading BPF skeleton object");
    goto cleanup;
  }

  log_trace("%s", "Attaching BPF skeleton object");
  err = sshtunnel_bpf__attach(skel);
  if (err) {
    log_trace("%s", "Error while attaching BPF skeleton object");
    goto cleanup;
  }

  log_trace("%s", "Initializing perf buffer");
  struct perf_buffer *pb = perf_buffer__new(
      bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
  if (!pb) {
    log_trace("%s", "Error while initializing perf buffer");
    goto cleanup;
  }

  log_trace("Setting up interrupt signal handler");
  signal(SIGINT, intHandler);

  log_trace("%s", "Start polling for BPF events...");
  while (!intSignal) {
    err = perf_buffer__poll(pb, 100 /* timeout, ms */);
  }

  log_trace("%s", "Freeing perf buffer");
  perf_buffer__free(pb);
  goto cleanup;

cleanup:
  log_trace("%s", "Closing File");
  fclose(fp);
  log_trace("%s", "Entering cleanup");
  sshtunnel_bpf__destroy(skel);
  log_trace("%s", "Finished cleanup");

  return EXIT_SUCCESS;
}
