/* AFL fuzzing helpers injected into httpd */

#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#define FUZZING_PORT 8080
#define MAX_INPUT_SIZE (1024 * 128)  // 128KB

static int global_socket_fd = -1;
static volatile int should_exit = 0;

__AFL_FUZZ_INIT();

static void cleanup_handler(int sig) {
    should_exit = 1;
    if (global_socket_fd >= 0) {
        close(global_socket_fd);
    }
    _exit(0);
}

static void *fuzzer_thread(void *arg) {
    struct sockaddr_in addr;
    int listen_fd, conn_fd;
    
    signal(SIGTERM, cleanup_handler);
    signal(SIGINT, cleanup_handler);
    
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return NULL;
    }
    
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(FUZZING_PORT);
    
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return NULL;
    }
    
    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        close(listen_fd);
        return NULL;
    }
    
    fprintf(stderr, "[*] Fuzzer thread listening on 127.0.0.1:%d\n", FUZZING_PORT);
    
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    
    while (__AFL_LOOP(10000)) {   Increased from 1000
        int len = __AFL_FUZZ_TESTCASE_LEN;
        
        if (len > MAX_INPUT_SIZE) {
            len = MAX_INPUT_SIZE;
        }
        
        conn_fd = accept(listen_fd, NULL, NULL);
        if (conn_fd < 0) {
            if (should_exit) break;
            continue;
        }
        
        global_socket_fd = conn_fd;
        
        // Send fuzzing input
        ssize_t sent = 0;
        while (sent < len) {
            ssize_t n = write(conn_fd, buf + sent, len - sent);
            if (n <= 0) break;
            sent += n;
        }
        
        // Give server time to process
        usleep(1000);  // 1ms, tune if necessary
        
        close(conn_fd);
        global_socket_fd = -1;
    }
    
    close(listen_fd);
    return NULL;
}

static void launch_fuzzy_thread(void) {
    pthread_t tid;
    pthread_attr_t attr;
    
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    if (pthread_create(&tid, &attr, fuzzer_thread, NULL) != 0) {
        fprintf(stderr, "[!] Failed to create fuzzer thread\n");
        exit(1);
    }
    
    pthread_attr_destroy(&attr);
    
    // Give thread time to set up
    sleep(1);
}

__attribute__((constructor))
static void start_afl_fuzzing(void) {
    if (getenv("__AFL_SHM_ID") != NULL) {
        fprintf(stderr, "[+] AFL detected, launching fuzzing thread\n");
        launch_fuzzy_thread();
    }
}
