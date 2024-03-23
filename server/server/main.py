import sqlite3
import socketserver
import logging
from messages import (
    TOTAL_HEADER_LENGTH,
    parse_message_header,
    parse_meesage_content,
    Message,
)
from protocol import FileRepo, SessionStore
from responses import Response, ResponseHeader

logging.basicConfig(level=logging.INFO)
sessions = SessionStore(FileRepo(), 'defensive.db')


class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.header_data = self.request.recv(TOTAL_HEADER_LENGTH)
        logging.info(f"recived {self.header_data}")
        try:
            header = parse_message_header(self.header_data)
        except Exception as e:
            logging.error("Exception during header reading", e)
            self.request.sendall(ResponseHeader(3, 1607, 0).encode())
            return
        print(header)
        self.data = self.request.recv(header.payload_size)
        content = parse_meesage_content(header.code, self.data)
        print(content)
        message = Message(header, content)
        response = sessions.proccess_message(message)
        if response is not None:
            logging.info(f"responding with {response}")
            self.request.sendall(response.encode())

        logging.info(
            "Processed %s message of size %s bytes from client %s in address %s",
            message.header.code,
            message.header.payload_size,
            message.header.client_id,
            self.client_address[0],
        )


if __name__ == "__main__":
    logging.info("server starting")
    try:
        with open("port.info", "r") as f:
            PORT = int(f.read())
    except Exception as e:
        logging.warning("cant get port number from port.info", e)
        PORT = 1256
    HOST = "localhost"

    con = sqlite3.connect("defensive.db")
    cur = con.cursor()
    cur.execute("CREATE IF NOT EXISTS TABLE clients(ID VARCHAR(16), Name VARCHAR(255), PublicKey VARCHAR(160), LastSeen INTEGER, AES VARCHAR(32))")
    cur.execute("CREATE IF NOT EXISTS TABLE files(ID VARCHAR(16), FileName VARCHAR(255), PublicKey VARCHAR(255), Verified INTEGER")
    logging.info(f"listening on {HOST}:{PORT} for incomin traffic")

    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()
