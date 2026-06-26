#!/usr/bin/env python3
import struct
import socket
import time
import sys
import os

FILE_PATH = "/tmp/xdp_flow.bitnetflow"

def ip_to_str(ip_int):
    return socket.inet_ntoa(struct.pack("<I", ip_int))

def proto_name(proto):
    if proto == 6: return "TCP"
    if proto == 17: return "UDP"
    if proto == 1: return "ICMP"
    if proto == 58: return "ICMPv6"
    if proto == 132: return "SCTP"
    return f"OTHER({proto})"

def main():
    if not os.path.exists(FILE_PATH):
        print(f"Error: {FILE_PATH} does not exist yet. Run bpftune first to generate telemetry.")
        return

    with open(FILE_PATH, "rb") as f:
        # Read header (8 bytes)
        hdr_data = f.read(8)
        if len(hdr_data) < 8:
            print("Error: Invalid header or empty file.")
            return
        
        magic, version, record_size = struct.unpack("<IHH", hdr_data)
        if magic != 0x424E4650:
            print(f"Error: Invalid magic 0x{magic:08X} (expected 0x424E4650)")
            return
        
        print("=== Bitnetflow Header ===")
        print(f"Magic:       0x{magic:08X} (BNFP)")
        print(f"Version:     {version}")
        print(f"Record Size: {record_size} bytes")
        print("=" * 25)
        print(f"{'PROTO':<6} {'SRC IP:PORT':<21}    {'DST IP:PORT':<21} {'PKTS':<8} {'BYTES':<10} {'MEAN IAT':<12} {'STDDEV IAT':<12}")
        print("-" * 98)

        # Structure format for record (64 bytes):
        # src_ip (I), dst_ip (I), src_port (H), dst_port (H), protocol (B), pad (3s), 
        # packets (Q), total_bytes (Q), first_seen (Q), last_seen (Q), mean_iat (d), stddev_iat (d)
        record_fmt = "<IIHHB3sQQQQdd"
        
        follow = "-f" in sys.argv or "--follow" in sys.argv

        while True:
            rec_data = f.read(record_size)
            if len(rec_data) < record_size:
                if follow:
                    time.sleep(0.5)
                    continue
                else:
                    break
            
            src_ip, dst_ip, src_port, dst_port, protocol, _, packets, total_bytes, first_seen, last_seen, mean_iat, stddev_iat = struct.unpack(record_fmt, rec_data)
            
            src_str = f"{ip_to_str(src_ip)}:{src_port}"
            dst_str = f"{ip_to_str(dst_ip)}:{dst_port}"
            
            print(f"{proto_name(protocol):<6} {src_str:<21} -> {dst_str:<21} {packets:<8} {total_bytes:<10} {mean_iat:.3f}ms     {stddev_iat:.3f}ms")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting.")
