# Need python-openssl library
import sys, os, socket
from OpenSSL import SSL

def verify_callback(connection, certificate, error, depth, preverify):
  # Checking error codes which are same in C and .py versions
  if error == 18:
    print "Exiting due to error: Self signed certificate"
    sys.exit(1)

  if preverify != 1:
    print "Exiting due to error: Cannot verify certificate. Error code: " + str(error) + "See /usr/include/openssl/x509_vry.h for more info"
    sys.exit(1)
  commonname = certificate.get_subject().commonName

  # Verify hostname
  # Only check hostname at the lowest level
  if depth == 0:
    if commonname.lower() != sys.argv[1].lower():
      print "Exiting due to error: Common name doesn't match hostname"
      sys.exit(1)
  return preverify

def main():

  if(len(sys.argv) < 3):
    print "Exiting due to error: Not enough parameters. Use python " + sys.argv[0] + " <host> <port>\n"
    sys.exit(1)
  hostname = sys.argv[1]
  port = int(sys.argv[2])
  # Initialize SSL context with TLSv1
  context = SSL.Context(SSL.TLSv1_METHOD)
  # Set verify callback
  context.set_verify(SSL.VERIFY_PEER, verify_callback)
  # Load certificates
  context.load_verify_locations(None, "/etc/ssl/certs/")
  sock = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
  sock.connect((sys.argv[1], int(sys.argv[2])))

  sock.send("GET / HTTP/1.1\r\nHost: " + hostname + "\r\n\r\n")
  print sock.recv(1024)
  # pending doesn't work before the first read
  while (sock.pending() > 0):
    print sock.recv(1024)



if __name__ == "__main__":
  main()

