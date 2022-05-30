import argparse
import select
import socket
import sys
import threading
from urllib.parse import urlparse


def parse_header(data: bytes) -> (bytes, int, bool):
    first_line = data.split(b'\n')[0]
    method, url = first_line.split(b' ')[0:2]

    if method == b'CONNECT':
        is_tls = True
        url = b'//' + url
        url_data = urlparse(url)
    else:
        is_tls = False
        host_begin = data.find(b'Host:') + 6
        host_end = data.find(b'\r', host_begin)
        url_data = urlparse(b'//' + data[host_begin:host_end])

    return url_data.hostname, (url_data.port if url_data.port else 80), is_tls


def recieve_from(sock: socket.socket) -> (bytes, bool):
    data = sock.recv(args.bufsize)
    return data, len(data) == 0


def create_tcp_tunnel(client_conn: socket.socket, server_conn: socket.socket):
    client_conn.setblocking(False)
    server_conn.setblocking(False)

    sockets = [client_conn, server_conn]
    while True:
        client_sent = b''
        server_sent = b''

        try:
            inputs_ready, outputs_ready, except_ready = select.select(sockets, [], [], None)
        except Exception as e:
            print(str(e))
            return

        for sock in inputs_ready:
            try:
                data, is_conn_closed = recieve_from(sock)
            except OSError as e:
                print(f'[*] Unable to receive data from {sock.getsockname()}: {e}')
                return

            if is_conn_closed:
                return
            elif sock == client_conn:
                client_sent += data
            elif sock == server_conn:
                server_sent += data

        if len(server_sent) > 0:
            client_conn.sendall(server_sent)
        if len(client_sent) > 0:
            server_conn.sendall(client_sent)


def start_proxy(client_conn: socket.socket, data: bytes):
    try:
        host, port, is_tls = parse_header(data)
        assert host is not None
    except Exception as e:
        print(f'[*] Unable to parse header: {e}')
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_conn,\
         client_conn:
        try:
            server_conn.connect((host.decode('utf-8'), port))
            if is_tls:
                client_conn.sendall(b'HTTP/1.1 200 OK\r\n\n')
            else:
                server_conn.sendall(data)
        except OSError as e:
            print(f'[*] Unable to connect to server {server_conn.getsockname()}: {e}')
            return

        create_tcp_tunnel(client_conn, server_conn)

    return


def main(args):
    try:
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.bind(('localhost', args.lport))
        lsock.listen()
    except OSError as e:
        print(f'[*] Unable to open a listening socket at port {args.lport}: {e}')
        sys.exit()

    print(f'[*] Started proxy at port {args.lport}')
    while True:
        try:
            client_conn, addr = lsock.accept()
            data = client_conn.recv(args.bufsize)

            thread = threading.Thread(target=start_proxy, args=(client_conn, data))
            thread.setDaemon(True)
            thread.start()
        except KeyboardInterrupt:
            lsock.close()
            print("[*] Shutdown")
            sys.exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='lport', type=int, default=8080, help='listening port')
    parser.add_argument('-b', dest='bufsize', type=int, default=4096, help='buffer size')
    args = parser.parse_args()
    main(args)
