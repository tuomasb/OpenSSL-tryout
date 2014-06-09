#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/objects.h>
#include <unistd.h>

static char cn[256];

// Verify the certificate
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
  X509 * cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  int temp = X509_STORE_CTX_get_error(x509_ctx);
  int check;
  if(temp == 0) { printf("Certificate OK: yes\n"); }
  else { printf("Certificate OK: no\n"); }
  char buf[6][256];
  printf("Certificate subject:\n");
  check = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, buf[0], 256);
  if(check > 0) printf(" - Common name: %s\n", buf[0]);
  check = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_organizationName, buf[1], 256);
  if(check > 0) printf(" - Organization name: %s\n", buf[1]);
  check = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_organizationalUnitName, buf[2], 256);
  if(check > 0) printf(" - Organizational unit name: %s\n", buf[2]);
  printf("Certificate issuer:\n");
  check = X509_NAME_get_text_by_NID(X509_get_issuer_name(cert), NID_commonName, buf[3], 256);
  if(check > 0) printf(" - Common name: %s\n", buf[3]);
  check = X509_NAME_get_text_by_NID(X509_get_issuer_name(cert), NID_organizationName, buf[4], 256);
  if(check > 0) printf(" - Organization name: %s\n", buf[4]);
  check = X509_NAME_get_text_by_NID(X509_get_issuer_name(cert), NID_organizationalUnitName, buf[5], 256);
  if(check > 0) printf(" - Organizational unit name: %s\n", buf[5]);
  printf("===\n");
  strncpy(cn, buf[0], 256); // Common name from last certificate for verification purposes

  // Errors are specified in x509_vfy.h I will only handle here a couple of cases
  // since I don't think handling 20 different errors is within the scope of this exercise
  switch(temp) {
    case X509_V_OK:
      return preverify_ok;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
      printf("Exiting due to error: self signed certificate\n");
      exit(0);
    case X509_V_ERR_CERT_HAS_EXPIRED:
      printf("Exiting due to error: expired certificate\n");
      exit(0);
    case X509_V_ERR_CERT_REVOKED:
      printf("Exiting due to error: certificate revoked\n");
      exit(0);
    default:
      printf("Exiting due to error: Generic error %d (lookup code from /usr/include/openssl/x509_vfy.h)\n", temp);
  }

  return preverify_ok;
}

int main(int argc, char *argv[]) {
  int sockfd = 0;
  struct hostent * host;
  struct sockaddr_in serveraddr;
  int portno;

  SSL_CTX * ctx;
  SSL * ssl;
  BIO * sbio;

  // Check parameters
  if(argc < 3) {
    printf("Exiting due to error: Not enough parameters. Use ./ssl <host> <port>\n");
    exit(0);
  }

  // Create a socket
  if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("Exiting due to error: Could not create socket\n");
    exit(0);
  }

  if((host = gethostbyname(argv[1])) == NULL) {
    printf("Exiting due to error: Could not resolve host\n");
    exit(0);
  }

  memset(&serveraddr, 0, sizeof(serveraddr));
  portno = atoi(argv[2]);
  // Populate serveraddr struct with destination address
  serveraddr.sin_family = AF_INET; // AF_INET socket family
  serveraddr.sin_port = htons(portno); // Host byte order
  serveraddr.sin_addr = *((struct in_addr *) host->h_addr_list[0]);

  // connect() uses OS settings so it takes more than a minute to timeout
  // and return -1 if TCP connection cannot be established
  if(connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
    printf("Exiting due to error: Could not connect to host\n");
    exit(0);
  }
  
  SSL_load_error_strings(); // Load error strings
  SSL_library_init(); // Adds all ciphers and digests into the internal table

  ctx = SSL_CTX_new(TLSv1_client_method()); // New SSL context
                                            // Only TLSv1, no SSLv2/3

  // Set root certificate location
  if(SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1) {
    printf("Exiting due to error: Could not load root certificates\n");
    exit(0);
  }

  // Set verify callback with OpenSSL doing preverification in contrast to
  // using SSL_set_cert_verify_callback which overrides the whole verification process
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
  ssl = SSL_new(ctx); // New SSL connection
  sbio = BIO_new_socket(sockfd, BIO_NOCLOSE); // New BIO abstraction binded to sockfd
  SSL_set_bio(ssl, sbio, sbio); // ssl to use sbio for input and output

  // Start TLSv1 negotiation with HELLO and complete it
  if(SSL_connect(ssl) < 1) {
    printf("Exiting due to error: Could not negotiate TLS\n");
    exit(0);
  }

  // Verify common name before sending data
  if(strcasecmp(cn, argv[1]) != 0) {
    printf("Exiting due to error: Common name doesn't match hostname\n");
    exit(0);
  }


  char * request = malloc(1024);
  snprintf(request, 1023, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", argv[1]);
  printf("%s", request);
  SSL_write(ssl, request, strlen(request));
  free(request);

  // sleep 1 second, read until SSL_pending return 0 and stop (not optimal way to do it)
  sleep(1);
  char rbuf[1024];
  SSL_read(ssl, rbuf, 1024);
  printf("%s\n", rbuf);

  while(SSL_pending(ssl) > 0) {
    memset(rbuf, 0, 1024);
    SSL_read(ssl, rbuf, 1024);
    printf("%s\n", rbuf);
  }
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
}
