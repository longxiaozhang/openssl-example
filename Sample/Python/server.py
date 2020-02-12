import socket
import ssl

class server_ssl:
    def build_listen(self):
        ca_file = "rootca.crt"
        key_file = "server.key"
        cert_file = "server.crt"
	context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
	context.load_cert_chain(certfile = cert_file, keyfile=key_file)
	context.load_verify_locations(ca_file)
	context.verify_mode = ssl.CERT_REQUIRED

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
	    with context.wrap_socket(sock, sesrver_side=True) as ssock:
		ssock.bind(('127.0.0..1'), 1024))
		ssock.listen(5)
		while True:
		    client_socket, addr = ssock.accept()
		    msg = client_socket.recv(1024).decode("utf-8")
		    print(f"receive msg from client{addr}:{msg}")
		    msg = f"yes, you have client_socket with server.\r\n".encode("utf-8")
		    client_socket.send(msg)
		    client_socket.close()

if __name__ == "__main__":
    server = server_ssl()
    server.build_listen()
