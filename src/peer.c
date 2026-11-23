#include "common.h"
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"


// Global variables to be used by both the server and client side of the peer.
Address_t *my_address;

Address_t** network = NULL;
uint32_t peer_count = 0;
pthread_mutex_t network_lock = PTHREAD_MUTEX_INITIALIZER;
hashdata_t my_network_signature;
char my_network_salt[SALT_LEN];
int my_network_ready = 0;
/* Adds per to the network unless ip+port is already known.
 * Returns 1 if added, 0 if it was a duplicate. Thread-safe. */
int add_peer_if_new(Address_t* peer)
{
  pthread_mutex_lock(&network_lock);
  for (uint32_t i = 0; i < peer_count; i++) {
    if (network[i]->port == peer->port &&
        strncmp(network[i]->ip, peer->ip, IP_LEN) == 0){
      pthread_mutex_unlock(&network_lock);
      return 0;
    }
  }
network = realloc(network, (peer_count + 1) * sizeof(Address_t*));
network[peer_count++] = peer;
pthread_mutex_unlock(&network_lock);
return 1;
}
/* signature = sha256(data || salt) */
void get_signature(const char* data, size_t data_len,
    const char* salt, hashdata_t out)
{
  char buf[SHA256_HASH_SIZE + SALT_LEN];
  memcpy(buf, data, data_len);
  memcpy(buf + data_len, salt, SALT_LEN);
  get_data_sha(buf, out, data_len + SALT_LEN, SHA256_HASH_SIZE);
}
/*
 * Send a request message to another peer on the network. Unless this is 
 * specifically an 'inform' message as described in the assignment handout, a 
 * reply will always be expected.
 */
void send_message(Address_t peer_address, int command, 
    char* request_body, int body_length)
{
    fprintf(stdout, "Connecting to server at %s:%d to run command %d\n", 
        peer_address.ip, peer_address.port, command);

    compsys_helper_state_t state;
    char msg_buf[MAX_MSG_LEN];
    FILE* fp;

    // Setup connection. Note that we need to convert our port from an integer
    // to a string
    char port_char[6];
    port_char[5] = '\0';
    sprintf(port_char, "%d", peer_address.port);
    int peer_socket = compsys_helper_open_clientfd(peer_address.ip, port_char);
    compsys_helper_readinitb(&state, peer_socket);

    // Construct a request message and send it to the peer
    struct RequestHeader request_header;
    strncpy(request_header.ip, my_address->ip, IP_LEN);
    memcpy(request_header.signature, my_address->signature, SHA256_HASH_SIZE);
    request_header.port = htonl(my_address->port);
    request_header.command = htonl(command);
    request_header.length = htonl(body_length);
    // Copy the header and body together to the message buffer, then write to 
    // the socket
    memcpy(msg_buf, &request_header, REQUEST_HEADER_LEN);
    memcpy(msg_buf+REQUEST_HEADER_LEN, request_body, body_length);
    compsys_helper_writen(peer_socket, msg_buf, REQUEST_HEADER_LEN+body_length);

    /*
    3: Handing the response to the register message
    Rather than closing immediately we should probably handle a response.
    */

    close(peer_socket);
}


void inform_other_peers(Address_t *new_peer)
{
    // Build the 68-byte INFORM body
    char body[PEER_ADDR_LEN];

    memcpy(body, new_peer->ip, IP_LEN);

    uint32_t port = htonl(new_peer->port);
    memcpy(body + IP_LEN, &port, PORT_LEN);

    memcpy(body + IP_LEN + PORT_LEN,
           new_peer->signature, SHA256_HASH_SIZE);

    memcpy(body + IP_LEN + PORT_LEN + SHA256_HASH_SIZE,
           new_peer->salt, SALT_LEN);

    // Copy the addresses while holding the mutex
    pthread_mutex_lock(&network_lock);

    Address_t *recipients = malloc(
        peer_count * sizeof(Address_t)
    );

    uint32_t count = 0;

    if (recipients != NULL) {
        for (uint32_t i = 0; i < peer_count; i++) {
            if (network[i] != my_address &&
                network[i] != new_peer) {
                recipients[count++] = *network[i];
            }
        }
    }

    pthread_mutex_unlock(&network_lock);

    if (recipients == NULL) {
        perror("malloc failed");
        return;
    }

    // Send INFORM to all existing peers
    for (uint32_t i = 0; i < count; i++) {
        printf("Informing peer %s:%u\n",
               recipients[i].ip, recipients[i].port);

        send_message(recipients[i], COMMAND_INFORM,
                     body, PEER_ADDR_LEN);
    }

    free(recipients);
}


/*
 * Function to act as thread for all required client interactions. This thread 
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 */ 
void* client_thread()
{
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to: ");
    scanf("%16s", peer_ip);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_ip); i<IP_LEN; i++)
    {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%16s", peer_port);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_port); i<PORT_STR_LEN; i++)
    {
        peer_port[i] = '\0';
    }

    Address_t peer_address;
    memcpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);

    /*
    2: Sending a first register message
    Here you should probably send a first register message using the 
    send_message function.
    */
    send_message(peer_address,COMMAND_REGISTER,NULL, 0);
    // You should never see this printed in your finished implementation
    printf("Client thread done\n");

    return NULL;
}


int send_one_block_reply(int connfd, uint32_t status,
                         const char *body, uint32_t body_length)
{
    // Check the maximum message size
    if (body_length > MAX_MSG_LEN - REPLY_HEADER_LEN ||
        (body_length > 0 && body == NULL)) {
        return 0;
    }

    ReplyHeader_t reply = {0};

    reply.length = htonl(body_length);
    reply.status = htonl(status);
    reply.this_block = htonl(0);
    reply.block_count = htonl(1);

    // Calculate the SHA-256 hash of the body
    get_data_sha(body != NULL ? body : "",
                 reply.block_hash,
                 body_length, SHA256_HASH_SIZE);

    // For a single block, both hashes are identical
    memcpy(reply.total_hash, reply.block_hash,
           SHA256_HASH_SIZE);

    // Combine header and body
    char message[MAX_MSG_LEN];

    memcpy(message, &reply, REPLY_HEADER_LEN);

    if (body_length > 0) {
        memcpy(message + REPLY_HEADER_LEN, body, body_length);
    }

    // Send the complete response
    size_t message_length = REPLY_HEADER_LEN + body_length;

    if (compsys_helper_writen(connfd, message, message_length)
        != (ssize_t)message_length) {
        perror("Failed to send response");
        return 0;
    }

    return 1;
}



/*
 * Handler for all server requests. This will call the relevent function based 
 * on the parsed command code
 */

void* handle_server_request_thread(void *vargp)
{
    char buf[MAXLINE];
    compsys_helper_state_t state;

    int connfd = *((int *)vargp);
    pthread_detach(pthread_self());
    free(vargp);

    /*
    5: Reading Server Requests
    */

    // Initialize the provided reading helper
    compsys_helper_readinitb(&state, connfd);

    // Read the request header
    ssize_t bytes_read = compsys_helper_readnb(
        &state, buf, REQUEST_HEADER_LEN
    );

    if (bytes_read != REQUEST_HEADER_LEN) {
        printf("Failed to read request header\n");
        close(connfd);
        return NULL;
    }

    // Copy the received bytes into the provided struct
    RequestHeader_t header;
    memcpy(&header, buf, REQUEST_HEADER_LEN);

    // Convert values from network byte order
    uint32_t port = ntohl(header.port);
    uint32_t command = ntohl(header.command);
    uint32_t body_length = ntohl(header.length);

    // Print the received request
    printf("Request received:\n");
    printf("IP: %.*s\n", IP_LEN, header.ip);
    printf("Port: %u\n", port);
    printf("Command: %u\n", command);
    printf("Body length: %u\n", body_length);


    // Check that the body is not too large
    if (body_length > MAX_MSG_LEN - REQUEST_HEADER_LEN) {
        printf("Request body is too large\n");
        close(connfd);
        return NULL;
    }

    // Read the request body if it exists
    if (body_length > 0) {
        ssize_t body_read = compsys_helper_readnb(
            &state, buf, body_length
        );

        if (body_read != (ssize_t)body_length) {
            printf("Failed to read request body\n");
            close(connfd);
            return NULL;
        }
    }

    printf("Received body of %u bytes\n", body_length);

    
    // Check which command was received
    switch (command) {
        case COMMAND_REGISTER:
            if (body_length != 0) {
                printf("Invalid REGISTER request\n");
                const char error[] = "REGISTER must have an empty body";
                send_one_block_reply(connfd, STATUS_MALFORMED,
                     error, strlen(error));
                break;
            }

            // Allocate memory for the new peer
            Address_t *new_peer = malloc(sizeof(Address_t));

            if (new_peer == NULL) {
                perror("malloc failed");
                break;
            }

            // Copy IP and port from the request header
            memcpy(new_peer->ip, header.ip, IP_LEN);
            new_peer->ip[IP_LEN - 1] = '\0';
            new_peer->port = port;

            // Check the address
            if (!is_valid_ip(new_peer->ip) ||
                new_peer->port == 0 ||
                !is_valid_port(new_peer->port)) {
                printf("Invalid peer address\n");
                free(new_peer);
                break;
            }

            // Generate a network salt
            generate_random_salt(new_peer->salt);

            // Hash the received signature with the network salt
            get_signature(
                (const char *)header.signature,
                SHA256_HASH_SIZE,
                new_peer->salt,
                new_peer->signature
            );

            // Add the peer if it does not already exist
            uint32_t status = STATUS_OK;

            if (add_peer_if_new(new_peer)) {
                printf("Registered new peer: %s:%u\n",
                    new_peer->ip, new_peer->port);
            } else {
                printf("Peer already registered\n");
                status = STATUS_PEER_EXISTS;
                free(new_peer);
            }

            // Create the response body
            char reply_body[MAX_MSG_LEN - REPLY_HEADER_LEN];
            uint32_t reply_length = 0;
            int too_many_peers = 0;

            // Protect the shared network list
            pthread_mutex_lock(&network_lock);

            // Create our own network signature once
            if (!my_network_ready) {
                generate_random_salt(my_network_salt);

                get_signature(
                    (const char *)my_address->signature,
                    SHA256_HASH_SIZE,
                    my_network_salt,
                    my_network_signature
                );

                my_network_ready = 1;
            }

            for (uint32_t i = 0; i < peer_count; i++) {
                Address_t *peer = network[i];


                // Check that the peer fits in one response block
                if (reply_length + PEER_ADDR_LEN > sizeof(reply_body)) {
                    too_many_peers = 1;
                    break;
                }

                // IP address (16 bytes)
                memcpy(reply_body + reply_length, peer->ip, IP_LEN);
                reply_length += IP_LEN;

                // Port in network byte order (4 bytes)
                uint32_t network_port = htonl(peer->port);
                memcpy(reply_body + reply_length, &network_port, PORT_LEN);
                reply_length += PORT_LEN;

                
                if (peer == my_address) {
                    // Use our separately stored network signature
                    memcpy(reply_body + reply_length,
                        my_network_signature, SHA256_HASH_SIZE);
                    reply_length += SHA256_HASH_SIZE;

                    memcpy(reply_body + reply_length,
                        my_network_salt, SALT_LEN);
                    reply_length += SALT_LEN;
                } else {
                    memcpy(reply_body + reply_length,
                        peer->signature, SHA256_HASH_SIZE);
                    reply_length += SHA256_HASH_SIZE;

                    memcpy(reply_body + reply_length,
                        peer->salt, SALT_LEN);
                    reply_length += SALT_LEN;
                }

            }

            pthread_mutex_unlock(&network_lock);

            // Send the response
            if (too_many_peers) {
                const char error[] = "Peer list too large";
                send_one_block_reply(connfd, STATUS_OTHER,
                                    error, strlen(error));
            } else {
                send_one_block_reply(connfd, status,
                                    reply_body, reply_length);

                printf("Sent REGISTER response: %u bytes\n",
                    reply_length);
            }

            // Inform existing peers when a new peer joins
            if (status == STATUS_OK) {
                inform_other_peers(new_peer);
}
            break;

        case COMMAND_RETREIVE:
            if (body_length == 0) {
                printf("Invalid RETRIEVE request\n");
            } else {
                printf("RETRIEVE request for: %.*s\n",
                       (int)body_length, buf);
            }
            break;

        case COMMAND_INFORM: {
            if (body_length != PEER_ADDR_LEN) {
                printf("Invalid INFORM request\n");
                break;
            }

            // Allocate memory for the informed peer
            Address_t *informed_peer = malloc(sizeof(Address_t));

            if (informed_peer == NULL) {
                perror("malloc failed");
                break;
            }

            // Read IP address
            memcpy(informed_peer->ip, buf, IP_LEN);
            informed_peer->ip[IP_LEN - 1] = '\0';

            // Read port in network byte order
            uint32_t network_port;
            memcpy(&network_port, buf + IP_LEN, PORT_LEN);
            informed_peer->port = ntohl(network_port);

            // Read network signature and salt
            memcpy(informed_peer->signature,
                buf + IP_LEN + PORT_LEN,
                SHA256_HASH_SIZE);

            memcpy(informed_peer->salt,
                buf + IP_LEN + PORT_LEN + SHA256_HASH_SIZE,
                SALT_LEN);

            // Validate the address
            if (!is_valid_ip(informed_peer->ip) ||
                !is_valid_port(informed_peer->port)) {
                printf("Invalid informed peer address\n");
                free(informed_peer);
                break;
            }

            // Add the peer to our network list
            if (add_peer_if_new(informed_peer)) {
                printf("INFORM: Added peer %s:%u\n",
                    informed_peer->ip, informed_peer->port);
            } else {
                printf("INFORM: Peer already known\n");
                free(informed_peer);
            }

            break;
        }

        default:
            printf("Unknown command: %u\n", command);
            break;
    }



    close(connfd);
    return NULL;
}


/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void* server_thread()
{
    int listenfd;
    
    // Start listening
    char port_char[6];
    port_char[5] = '\0';
    sprintf(port_char, "%d", my_address->port);
    listenfd = compsys_helper_open_listenfd(port_char);
    
    printf("Starting to listen on %s:%d\n", my_address->ip, my_address->port);
    
    /*
    4: Setting Up Server Threading
    Here we should implement some sort of loop to accept inbound communications
    and handle them within a thread so they do not block subsequent 
    connections. The function 'handle_server_request_thread' has been provided
    as a simple skeleton function you could use to process your requests in.
    */

    while (1) {
    // Wait for an incoming connection
        int connfd = accept(listenfd, NULL, NULL);

        if (connfd < 0) {
            perror("accept failed");
            continue;
        }

        printf("New connection accepted\n");

        // Allocate memory for the connection descriptor
        int *connfd_ptr = malloc(sizeof(int));

        if (connfd_ptr == NULL) {
            perror("malloc failed");
            close(connfd);
            continue;
        }

        *connfd_ptr = connfd;

        // Create a new thread to handle this connection
        pthread_t thread_id;

        int result = pthread_create(
            &thread_id,
            NULL,
            handle_server_request_thread,
            connfd_ptr
        );

        if (result != 0) {
            fprintf(stderr, "pthread_create failed: %s\n",
                    strerror(result));
            close(connfd);
            free(connfd_ptr);
        }
    }

    // You should never see this printed in your finished implementation
    printf("Server thread done\n");

    return NULL;
}


int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    my_address = (Address_t*)malloc(sizeof(Address_t));
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }
    
    if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n", 
            my_address->port);
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Most correctly, we should randomly generate our salts, but this can make
    // repeated testing difficult so feel free to use the hard coded salt below
    char user_salt[SALT_LEN+1] = "0123456789ABCDEF\0";
    //generate_random_salt(user_salt);
    memcpy(my_address->salt, user_salt, SALT_LEN);
    get_signature(password, strlen(password), user_salt, my_address->signature);

    /* 
    1: Setting Up
    After determining our salt but before saving our address we should probably
    work out what our signature should be. 
    */

    // Start our record of the network by recording our own address. Make sure
    // any time we update this array we also update the peer_count.
    network = malloc(sizeof(Address_t*));
    network[0] = my_address;
    peer_count = 1;

    // Setup the client and server threads 
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Wait for them to complete. 
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}
