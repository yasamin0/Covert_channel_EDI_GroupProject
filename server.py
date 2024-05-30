import socket
import argparse

def start_server(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ip, port))
        s.listen()
        print(f"Server listening on {ip}:{port}")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print(f"Received: {data.decode()}")
                    conn.sendall(data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP server")
    parser.add_argument("ip", help="IP address to bind to")
    parser.add_argument("port", type=int, help="Port to bind to")

    args = parser.parse_args()
    start_server(args.ip, args.port)
