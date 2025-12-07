/* AFL fuzzing helpers injected into httpd */

#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define FUZZING_PORT 8080
#define MAX_INPUT_SIZE (1024 * 128)  /* 128KB */
#define CONNECT_RETRY_USEC 1000

static volatile int should_exit = 0;

__AFL_FUZZ_INIT();

static void cleanup_handler(int sig) {
    (void)sig;
    should_exit = 1;
    _exit(0);
}

static int send_case_to_httpd(const unsigned char *buf, size_t len) {
    int fd;
    struct sockaddr_in addr;
    size_t total = 0;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(FUZZING_PORT);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    while (total < len) {
        ssize_t n = send(fd, buf + total, len - total, 0);
        if (n <= 0) {
            break;
        }
        total += (size_t)n;
    }

    shutdown(fd, SHUT_WR);
    close(fd);
    return (int)total;
}

static void *fuzzer_thread(void *arg) {
    unsigned char *buf;
    int len;
    int attempts = 0;

    (void)arg;
    signal(SIGTERM, cleanup_handler);
    signal(SIGINT, cleanup_handler);

    /* Get data from AFL */
    buf = __AFL_FUZZ_TESTCASE_BUF;
    len = __AFL_FUZZ_TESTCASE_LEN;
    
    if (len < 0) len = 0;
    if (len > MAX_INPUT_SIZE) len = MAX_INPUT_SIZE;

    while (attempts < 20) {
        if (send_case_to_httpd(buf, (size_t)len) >= 0) {
            break;
        }
        usleep(CONNECT_RETRY_USEC);
        attempts++;
    }

    kill(getpid(), SIGTERM);
    return NULL;
}

static void launch_fuzzy_thread(void) {
    pthread_t tid;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&tid, &attr, fuzzer_thread, NULL) != 0) {
        fprintf(stderr, "[!] Failed to create fuzzing thread\n");
        exit(1);
    }
    pthread_attr_destroy(&attr);
}

__attribute__((constructor))
static void start_afl_fuzzing(void) {
    if (getenv("__AFL_SHM_ID") != NULL || getenv("AFL_NO_FORKSRV") != NULL) {
        launch_fuzzy_thread();
    }
}
