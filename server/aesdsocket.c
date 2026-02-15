/* 
A server daemon that logs received messages.
Written in reference to https://beej.us/guide/bgnet/html/ 

Use this command to view streamed syslog messages: 
journalctl -f -t aesdsocket

To test the server, you can use netcat in a separate terminal:
nc -q 0 localhost 9000

TODO: accept multiple simultaneous connections
*/
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <syslog.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdatomic.h>

#define PORT "9000"
#define BACKLOG 10
#define DATA_PATH "/var/tmp/aesdsocketdata"
#define RECEIVE_SIZE 4096
#define SEND_SIZE 4096
#define PACKET_DELIM_CH '\n'

typedef struct {
    int fd;                                  // fd of connected client
    struct sockaddr_storage addr;            // Interchangeable for IPv4 & IPv6
    socklen_t addr_len;                      // Length of socket address
    char conaddr_str[INET6_ADDRSTRLEN + 16]; // "IPv4: <addr>:<port>" or "IPv6: [<addr>]:<port>"
    size_t bytes_received;
} conn_info_t;

typedef struct {
    char *data;
    size_t len;
    size_t capacity;
} dyn_buffer_t;

static volatile sig_atomic_t exit_requested = 0;

static void handle_signal(int signo)
{
    (void)signo;          // unused
    exit_requested = 1;   // set flag only
}

static void init_exit_signals();
static int setup_server_socket(const char *port);
static int accept_client_connection(int sock_fd, conn_info_t *client_info);
static void skeleton_daemon();
static void str_sockaddr(conn_info_t *client_info);
static int socket_receive_packets(int data_fd, int sock_fd, dyn_buffer_t *recv_buf, size_t *total_bytes);
static int socket_send_file(int sock_fd, int file_fd);
static int file_append_packets(int fd, dyn_buffer_t *dyn_buf, const char delim_ch);
static void free_dyn_buffer(dyn_buffer_t *dyn_buf);
static void redirect_stdio_to_devnull(void);


int main(int argc, char *argv[]) {

    conn_info_t client_info;
    int sock_fd, data_fd;

    // Setup signal handler for program exit
    init_exit_signals();

    bool isdaemon = false;
    if (argc == 2) {
        isdaemon = (strcmp("-d",argv[1]) == 0) ? true : false;
    }

    openlog("aesdsocket", LOG_PID | LOG_CONS, LOG_USER);

    sock_fd = setup_server_socket(PORT);

    // Create server as a daemon
    if (isdaemon) {
        skeleton_daemon();
        printf("Running server as daemon with PID %d\n", getpid());
        syslog(LOG_INFO, "Running server as daemon");
    }

    // Open save data file
    data_fd = open(DATA_PATH, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (data_fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    while (!exit_requested) {
        if (accept_client_connection(sock_fd, &client_info) < 0) { // Receive new socket for pending connection
            perror("accept");
            break;
        }
        str_sockaddr(&client_info); // Set client connection string
        printf("Accepted connection from %s\n", client_info.conaddr_str);
        syslog(LOG_INFO, "Accepted connection from %s", client_info.conaddr_str);
        
        dyn_buffer_t recv_buf = {0};
        socket_receive_packets(data_fd, client_info.fd, &recv_buf, &client_info.bytes_received);
        printf("Received %d total bytes from client\n", client_info.bytes_received);
        syslog(LOG_INFO, "Received %d total bytes from client", client_info.bytes_received);

        free_dyn_buffer(&recv_buf);

        socket_send_file(client_info.fd, data_fd); // Return full content of saved data to client

        close(client_info.fd);
        printf("Closed connection from %s\n", client_info.conaddr_str);
        syslog(LOG_INFO, "Closed connection from %s", client_info.conaddr_str);
    }

    close(sock_fd);
    close(data_fd);
    remove(DATA_PATH);
    closelog();

    return EXIT_SUCCESS;
}

static void free_dyn_buffer(dyn_buffer_t *dyn_buf) {
    if (!dyn_buf) {
        return;
    }

    free(dyn_buf->data);
    dyn_buf->data = NULL;
    dyn_buf->len = 0;
    dyn_buf->capacity = 0;
}

/**
 * @brief Writes buffer to file with each packet appended on a new line
 * 
 * @param fd The file to append packets to
 * @param dyn_buf The dynamic buffer to write to the file
 * @param delim_ch The delimeter character which separates packets
 *
 * @return Number of packets appended to file
 */
static int file_append_packets(int fd, dyn_buffer_t *dyn_buf, const char delim_ch) {
    int packet_count = 0;
    size_t start = 0;
    for (size_t i = 0; i < dyn_buf->len; i++) {

        if (dyn_buf->data[i] == delim_ch) {
            size_t packet_len = i - start + 1; // include newline

            printf("Wrote %d bytes to data file\n", packet_len);
            syslog(LOG_INFO, "Wrote %d bytes to data file", packet_len);
            ssize_t written = write(fd, dyn_buf->data + start, packet_len);

            if (written != (ssize_t)packet_len) {
                return -1;
            }

            start = i + 1;
            packet_count += 1;
        }
    }

    if (start > 0) {
        memmove(dyn_buf->data, dyn_buf->data + start, dyn_buf->len - start);

        dyn_buf->len -= start;
    }

    return packet_count;
}

static int append_to_dynamic_buffer(dyn_buffer_t *dyn_buf, char *append_data, size_t append_len) {
    size_t new_capacity = dyn_buf->capacity + append_len;

    char* newptr = realloc(dyn_buf->data, new_capacity);
    if (newptr == NULL) {
        perror("realloc");
        return -1;
    }

    dyn_buf->data = newptr;
    dyn_buf->capacity = new_capacity;

    memcpy(dyn_buf->data + dyn_buf->len, append_data, append_len);

    dyn_buf->len += append_len;

    return 0;
}

static int socket_receive_packets(int data_fd, int sock_fd, dyn_buffer_t *recv_buf, size_t *total_bytes) {
    char chunk_buf[RECEIVE_SIZE];
    ssize_t bytes_read;

    while (1) {
        bytes_read = recv(sock_fd, chunk_buf, sizeof(chunk_buf), 0);

        if (bytes_read > 0) {

            if (append_to_dynamic_buffer(recv_buf, chunk_buf, bytes_read) < 0) {
                return -1;
            }

            int packets_written = 
                file_append_packets(data_fd, recv_buf, PACKET_DELIM_CH);

            if (packets_written < 0) {
                return -1;
            }

            if (packets_written > 0) {
                *total_bytes = bytes_read;
                printf("Received %d packets\n", packets_written);
                break;   // at least one newline processed
            }
        }
        else if (bytes_read == 0) { // Client closed connection
            if (recv_buf->len > 0) {
                // Write remaining partial packet
                if (write(data_fd, recv_buf->data, recv_buf->len) != recv_buf->len)
                    return -1;
            }
            break;
        }
        else {
            perror("recv");
            return -1;
        }
    }
    return 0;
}

static int accept_client_connection(int sock_fd, conn_info_t *client_info) {
    client_info->addr_len = sizeof(client_info->addr);

    int client_fd = accept(sock_fd, (struct sockaddr *)&client_info->addr, &client_info->addr_len);

    if (client_fd == -1) {
        return -1;
    }

    client_info->fd = client_fd;
    client_info->bytes_received = 0;
    return client_fd;
}

static int setup_server_socket(const char* port) {
    struct addrinfo hints, *servinfo;
    int sock_fd;
    int ret = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE; // Autofill IP
    hints.ai_socktype = SOCK_STREAM; // TCP stream
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6

    // Allocate address structures that a socket can be binded to
    ret = getaddrinfo(NULL, PORT, &hints, &servinfo);
    if (ret != 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }

    // Attempt to bind each possible address until one works
    struct addrinfo *p; 
    for (p = servinfo; p != NULL; p = p->ai_next) {

        sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock_fd == -1) {
            perror("socket");
            continue;
        }

        int yes = 1; // Allow port reuse
        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("bind");
            close(sock_fd);
            continue;
        }
        
        freeaddrinfo(servinfo);
        break;
    }

    if (sock_fd == -1) {
        fprintf(stderr, "Failed to bind to any address\n");
        exit(EXIT_FAILURE);
    }

    printf("Socket created. Listening for connections...\n");
    ret = listen(sock_fd, BACKLOG);
    if (ret == -1) {
        perror("listen");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    return sock_fd;
}

/**
 * @brief Initilize signal handlers for SIGINT and SIGTERM
 *
 */
static void init_exit_signals() {
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/**
 * @brief Write full contents of a file to a socket until completion in chunks of SEND_SIZE
 * 
 * @param sock_fd fd of the socket to write to
 * @param file_fd fd of the file to send
 * 
 * @return 0 on sucess and -1 on error
 */
static int socket_send_file(int sock_fd, int file_fd) {
    char buf[SEND_SIZE];
    ssize_t bytes_read = 0;

    if (lseek(file_fd, 0, SEEK_SET) == -1) {
        return -1;
    }
    
    while ((bytes_read = read(file_fd, buf, sizeof(buf))) > 0) {
        ssize_t total_sent = 0;
        while (total_sent < bytes_read) {
            ssize_t bytes_sent = send(sock_fd, buf + total_sent, bytes_read - total_sent, 0);
            if (bytes_sent < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            total_sent += bytes_sent;
        }
    }

    if (bytes_read == -1) {
        return -1;
    }
    return 0;
}

static void skeleton_daemon()
{
    pid_t pid;
    
    pid = fork();
    
    if (pid < 0) { // Error occurred
        perror("fork");
        exit(EXIT_FAILURE);
    }
    
    if (pid > 0) { // Terminate parent 
        exit(EXIT_SUCCESS);
    }
    
    if (setsid() < 0) { // Ensure child is session leader
        perror("setsid");
        exit(EXIT_FAILURE);
    }

    redirect_stdio_to_devnull();
    umask(0);
    chdir("/");
}

/**
 * @brief Convert the stored socket address in conn_info_t to human-readable string.
 *
 * Stores result in client_info->connadr_str as:
 * "IPv4: <addr>:<port>"
 * "IPv6: [<addr>]:<port>"
 *
 * @param client_info client_info Pointer to initialized conn_info_t
 */
static void str_sockaddr(conn_info_t *client_info) {
    char ipstr[INET6_ADDRSTRLEN];
    const void *addr = NULL;
    const char *ipver = NULL;
    uint16_t port = 0;

    if (client_info->addr.ss_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)&client_info->addr;
        addr = &(ipv4->sin_addr);
        port = ntohs(ipv4->sin_port);
        ipver = "IPv4";
    } else {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)&client_info->addr;
        addr = &(ipv6->sin6_addr);
        port = ntohs(ipv6->sin6_port);
        ipver = "IPv6";
    }

    inet_ntop(client_info->addr.ss_family, addr, ipstr, sizeof(ipstr));
    if (client_info->addr.ss_family == AF_INET6)
        snprintf(client_info->conaddr_str, sizeof(client_info->conaddr_str), "%s: [%s]:%u", ipver, ipstr, port);
    else
        snprintf(client_info->conaddr_str, sizeof(client_info->conaddr_str), "%s: %s:%u", ipver, ipstr, port);
}

static void redirect_stdio_to_devnull(void)
{
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        exit(EXIT_FAILURE);
    }

    // Redirect stdout, stderr
    if (dup2(fd, STDOUT_FILENO) < 0) exit(EXIT_FAILURE);
    if (dup2(fd, STDERR_FILENO) < 0) exit(EXIT_FAILURE);

    // Close extra descriptor if it's not one of the standard ones
    if (fd > STDERR_FILENO) {
        close(fd);
    }
}