import socket

HOST = '127.0.0.1'  # localhost
PORT = 8583

def run_iso8583_test_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"ISO8583 Test Server Running on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(2048)
                    if not data:
                        break
                    print("Received:", data)
                    # Respond with a minimal ISO8583 ACK message or dummy response
                    # Here just sending back fixed message, can customize later
                    conn.sendall(b"ISO8583 ACK:123456")

if __name__ == "__main__":
    run_iso8583_test_server()
