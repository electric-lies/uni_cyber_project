import socket


def message() -> bytes:
    client_id = "0123456789abcdef0123456789abcdef"
    version = 1
    code = 1025
    paylod_size = 5
    content = 1
    message = (
        bytes.fromhex(client_id)
        + version.to_bytes(1)
        + code.to_bytes(2)
        + paylod_size.to_bytes(4)
        + content.to_bytes(5)
    )
    return message


HOST, PORT = "localhost", 1256
data = message()

# Create a socket (SOCK_STREAM means a TCP socket)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    # Connect to server and send data
    sock.connect((HOST, PORT))
    sock.sendall(data)

    # Receive data from the server and shut down
    received = str(sock.recv(1024), "utf-8")

print("Sent:     {}".format(data))
print("Received: {}".format(received))
