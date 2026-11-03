import argparse
import csv
import json
import logging
import shlex
import time
from collections import defaultdict
from datetime import datetime
from functools import partial
from urllib.parse import urlparse

from scapy.all import IP, TCP, UDP, Raw, sniff


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filter", default="udp port 631 or tcp")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--iface", default=None)
    parser.add_argument("--known-printers", default=None)
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--csv", default=None, help="write alerts to this CSV file")
    parser.add_argument("--json", default=None, help="write alerts to this JSON file")
    return parser.parse_args()

def setup_logging(verbose):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

def record_alert(sink, alert, source, detail):
    """Store one alert and, if a CSV file is open, append it immediately."""
    row = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "alert": alert,
        "source": source,
        "detail": detail,
    }
    sink["rows"].append(row)
    if sink["csv_writer"] is not None:
        sink["csv_writer"].writerow([row["timestamp"], alert, source, detail])
        sink["csv_file"].flush()

def handle_pkt(pkt, known, seen, args, unauthorized, sink):
    logging.info("Captured: %s", pkt.summary())
    if UDP in pkt and pkt[UDP].dport == 631:
        fields = parse_browse(pkt)
        if fields is None:
            logging.debug("Unparsable announcement")
            return
        logging.info("Parsed advertisement: %s", fields)
        handle_announcement(pkt, fields, known, seen, args, unauthorized, sink)
    elif TCP in pkt:
        handle_ipp_connection(pkt, unauthorized, sink)


def handle_announcement(pkt, fields, known, seen, args, unauthorized, sink):
    src = pkt[IP].src
    u = urlparse(fields["uri"])

    now = time.time()
    seen[src].append(now)
    seen[src] = [t for t in seen[src] if now - t <= args.window]
    if len(seen[src]) > args.threshold:
        logging.warning("[FLOOD] %s sent %d announcements in %ds", src, len(seen[src]), args.window)
        record_alert(sink, "FLOOD", src, "%d announcements in %ds" % (len(seen[src]), args.window))

    if src not in known:
        target = (u.hostname, u.port)
        if target not in unauthorized:
            unauthorized.append(target)
        logging.warning("[UNAUTHORIZED AD] %s advertised %s:%s", src, u.hostname, u.port)
        record_alert(sink, "UNAUTHORIZED AD", src, "advertised %s:%s" % (u.hostname, u.port))

    validate(src, fields, known, sink)     # pure validation, no side effects

def handle_ipp_connection(pkt, unauthorized, sink):
    if TCP not in pkt or pkt[IP] is None:
        return
    if pkt[TCP].flags != "S":          # only flag the SYN (connection open)
        return
    dst = (pkt[IP].dst, pkt[TCP].dport)
    if dst in unauthorized:
        logging.warning("[SUSPICIOUS IPP] connection to attacker-advertised printer %s:%d", dst[0], dst[1])
        record_alert(sink, "SUSPICIOUS IPP", dst[0], "connection to attacker-advertised printer %s:%d" % (dst[0], dst[1]))

def validate(src, fields, known, sink):
    problems = []
    try:
        int(fields["type"], 16)
    except ValueError:
        problems.append("type not valid hex: {}".format(fields["type"]))
    if fields["state"] not in {"3", "4", "5"}:
        problems.append("abnormal printer-state: {}".format(fields["state"]))
    u = urlparse(fields["uri"])
    if u.scheme not in {'http', 'ipp', 'https'}:
        problems.append(f'invalid uri scheme: {u.scheme}')
    if u.hostname not in known:
        problems.append(f'not known IP: {u.hostname}')
    if u.port != 631:
        problems.append(f'unexpected port number: {u.port}')
    if problems:
        logging.warning("[MALFORMED] %s from %s: %s", "; ".join(problems), src, fields.get("uri"))  # noqa: LOG015
        record_alert(sink, "MALFORMED", src, "%s uri=%s" % ("; ".join(problems), fields.get("uri")))

def load_known_printers(path):
    known = {}
    if path is None:
        return known
    try:
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                known[row["ip"]] = row      # key by IP → {ip, name, port}
    except FileNotFoundError:
        logging.warning("No known-printers file at %s — treating all as unknown", path)
    return known

def parse_browse(pkt):
    if Raw not in pkt:
        return None
    data = pkt[Raw].load            # bytes
    text = data.decode("latin-1", "replace")   # bytes → str, tolerant of junk
    vals = shlex.split(text)
    if len(vals) != 6:
        return None
    fieldsvals = ['type', 'state', 'uri', 'location', 'info', 'make_model']
    fields = {}
    for i in range(6):
        fields[fieldsvals[i]] = vals[i]
    return fields


if __name__ == "__main__":
    args = parse_arguments()
    setup_logging(args.verbose)
    logging.info("Listening on %s (filter: %s)", args.iface, args.filter)
    known = load_known_printers(args.known_printers)
    logging.info("Known printers: %s", known)
    seen = defaultdict(list)
    unauthorized = []

    # alert sink: in-memory rows, plus an optional live CSV writer
    sink = {"rows": [], "csv_writer": None, "csv_file": None}
    if args.csv:
        sink["csv_file"] = open(args.csv, "w", newline="")
        sink["csv_writer"] = csv.writer(sink["csv_file"])
        sink["csv_writer"].writerow(["timestamp", "alert", "source", "detail"])
        sink["csv_file"].flush()

    try:
        sniff(iface=args.iface, filter=args.filter,
              prn=partial(handle_pkt, known=known, seen=seen, args=args,
                          unauthorized=unauthorized, sink=sink),
              store=False)
    except KeyboardInterrupt:
        pass
    finally:
        if sink["csv_file"] is not None:
            sink["csv_file"].close()
        if args.json:
            with open(args.json, "w") as jf:
                json.dump(sink["rows"], jf, indent=2)
        logging.info("Recorded %d alert(s)", len(sink["rows"]))