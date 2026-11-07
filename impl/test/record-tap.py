#!/usr/bin/env python3
"""Passive TLS record tap: relay bytes between a client and a server
while logging every TLS record (time, direction, type, length) as
JSONL. Never decrypts, never terminates TLS: the record sizes and
timing it logs are exactly what a passive observer sees.

Usage: record-tap.py <listen-port> <target-port> <log-file.jsonl>
Runs until killed. One connection at a time is expected (the bench
drives a single session per leg); concurrent connections are each
handled on their own thread with their own record parser.

Record types: 20 change_cipher_spec, 21 alert, 22 handshake,
23 application_data. Only type-23 records after the handshake are
the data-plane shape under comparison; handshake records are logged
too so the comparison can exclude them.
"""
import json
import socket
import sys
import threading
import time

LISTEN_PORT = int(sys.argv[1])
TARGET_PORT = int(sys.argv[2])
LOG_PATH = sys.argv[3]

log_lock = threading.Lock()
log_f = open(LOG_PATH, "a", buffering=1)


def log_record(direction, rectype, length):
    with log_lock:
        log_f.write(json.dumps({
            "t_ms": int(time.time() * 1000),
            "dir": direction,
            "type": rectype,
            "len": length,
        }) + "\n")


class RecordParser:
    """Incrementally parse TLS records from a byte stream."""

    def __init__(self, direction):
        self.direction = direction
        self.buf = b""

    def feed(self, data):
        self.buf += data
        while len(self.buf) >= 5:
            rectype = self.buf[0]
            length = int.from_bytes(self.buf[3:5], "big")
            if len(self.buf) < 5 + length:
                return
            log_record(self.direction, rectype, length)
            self.buf = self.buf[5 + length:]


def pump(src, dst, direction):
    parser = RecordParser(direction)
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            parser.feed(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(conn, target_port):
    try:
        upstream = socket.create_connection(("127.0.0.1", target_port))
    except OSError:
        conn.close()
        return
    t1 = threading.Thread(target=pump, args=(conn, upstream, "c2s"), daemon=True)
    t2 = threading.Thread(target=pump, args=(upstream, conn, "s2c"), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    try:
        conn.close()
    except OSError:
        pass
    try:
        upstream.close()
    except OSError:
        pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN_PORT))
    srv.listen(8)
    print(f"record-tap listening 127.0.0.1:{LISTEN_PORT} -> 127.0.0.1:{TARGET_PORT} log={LOG_PATH}", flush=True)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        threading.Thread(target=handle, args=(conn, TARGET_PORT), daemon=True).start()


if __name__ == "__main__":
    main()
