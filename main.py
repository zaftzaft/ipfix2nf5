import socket

bind_address = "127.0.0.1"
bind_port = 9400
buf = 9100

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((bind_address, bind_port))

while True:
    data, addr = sock.recvfrom(buf)
