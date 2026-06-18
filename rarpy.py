import argparse
from scapy.all import sniff, sendp, Ether, Raw, get_if_hwaddr
from textwrap import dedent
import os

import logging

logger = logging.getLogger(__name__)


def get_mac_to_ip(mapping_file, mappings):
    mac_to_ip = {}

    # Load mappings from file
    if mapping_file and not os.path.exists(mapping_file):
        logger.error(f"Mapping file {mapping_file} not found.")
        exit(1)
    elif mapping_file:
        any_mapping = False
        with open(mapping_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                mac, ip = line.split()
                logger.debug(f"Mapping from file: {mac} -> {ip}")
                mac_to_ip[mac.lower()] = ip
                any_mapping = True

        if not any_mapping:
            logger.warning(
                f"Configured mapping file {mapping_file} is empty or contains no valid mappings."
            )

    # Override with command-line mappings
    if mappings:
        for mac, ip in mappings:
            if mac.lower() in mac_to_ip:
                logger.debug(
                    f"Mapping from command line: {mac} -> {ip} (overrides mapping from file)"
                )
            else:
                logger.debug(f"Mapping from command line: {mac} -> {ip}")
            mac_to_ip[mac.lower()] = ip

    return mac_to_ip


def ip_to_bytes(ip):
    return bytes(int(x) for x in ip.split("."))


def build_rarp_reply(mac, ip, interface):
    mac_bytes = bytes.fromhex(mac.replace(":", ""))

    payload = (
        b"\x00\x01"  # Ethernet
        b"\x08\x00"  # IPv4
        b"\x06"  # hlen
        b"\x04"  # plen
        b"\x00\x04"  # RARP reply
        + mac_bytes  # sha
        + ip_to_bytes(ip)
        + mac_bytes  # tha
        + ip_to_bytes(ip)
    )

    return Ether(
        dst=mac,
        src=get_if_hwaddr(interface),  # server MAC
        type=0x8035,  # RARP
    ) / Raw(payload)


def handle(pkt, mac_to_ip, interface):
    if pkt.type != 0x8035:  # RARP
        return

    raw = bytes(pkt.payload)

    # Check if the packet is long enough to contain a RARP request
    if len(raw) < 28:
        return

    opcode = int.from_bytes(raw[6:8], "big")

    # Only handle RARP requests (opcode 3)
    if opcode != 3:
        return

    mac = ":".join(f"{b:02x}" for b in raw[8:14])

    print(f"RARP request from {mac}")

    ip = mac_to_ip.get(mac)

    if ip is None:
        print("No mapping configured")
        return

    reply = build_rarp_reply(mac, ip, interface)

    print(f"Sending {ip} to {mac}")

    sendp(
        reply,
        iface=interface,
        verbose=False,
    )


def main(interface, mapping_file, mappings, verbose):
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)
    logging.info(f"Listening on {interface} for RARP requests...")

    mac_to_ip = get_mac_to_ip(mapping_file, mappings)

    sniff(
        iface=interface,
        filter="ether proto 0x8035",
        prn=lambda pkt: handle(pkt, mac_to_ip, interface),
        store=False,
    )


def main_cli():
    parser = argparse.ArgumentParser(
        prog="rarpy",
        description="RARP server that responds to RARP requests with a configured MAC-to-IP mapping. Run with sudo.",
        epilog=dedent("""
        Example usages: 
        
            sudo rarpy -f /path/to/mapping/file en0
            
            sudo rarpy -m 02:0d:db:a1:15:10 192.168.10.201 en0
            
            sudo rarpy -m 02:0d:db:a1:15:10 192.168.10.201 -m 02:0d:db:a1:15:11 192.168.10.201 en0
            
        By default, the server will look for a mapping file at /etc/ethers. The mapping file should contain MAC IP pairs separated by newlines. For example:
       
            02:0d:db:a1:15:10 192.168.10.201
            02:0d:db:a1:15:11 192.168.10.201
       
        When using the --mapping (-m) option, you can specify additional MAC-to-IP mappings directly on the command line which will override mapping with the same MAC address in the mapping file.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("interface", help="Network interface to listen on.")
    parser.add_argument(
        "--mapping-file",
        "-f",
        help="Path to a file containing MAC-to-IP mappings. Default is /etc/ethers if it exists. The format is a list of MAC IP pairs (e.g. 02:0d:db:a1:15:10 192.168.10.201) separated by newlines.",
    )
    parser.add_argument(
        "--mapping",
        "-m",
        nargs=2,
        metavar=("MAC", "IP"),
        action="append",
        help="MAC-to-IP mapping in the format MAC:IP (e.g. 02:0d:db:a1:15:10 192.168.10.201). Can be specified multiple times.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output."
    )
    args = parser.parse_args()

    if not args.mapping and os.path.exists("/etc/ethers"):
        args.mapping_file = "/etc/ethers"

    main(args.interface, args.mapping_file, args.mapping, args.verbose)


if __name__ == "__main__":
    main_cli()
