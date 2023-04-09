#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime

from scapy.all import *
from scapy.layers.inet import *

FilteredData = tuple[int, int, int, str, str, str, bool]
filtered_data_csv_header = ["packet_id", "timestamp",
                            "packet_size", "eth_src", "device_name", "protocol", "iot"]

DeviceList = Optional[dict[str, tuple[str, bool]]]


def drop_packets(packet: Packet) -> bool:
    if packet.haslayer("IP") and packet[0].proto != 1 and packet[0].proto != 58 and packet[0].proto != 2:
        return False
    return True


def format_float_time(float_timestamp: EDecimal) -> int:
    # Convert the float timestamp to a datetime object
    dt = datetime.fromtimestamp(float(float_timestamp))

    # Convert the datetime object to a nanosecond timestamp
    return int(dt.timestamp() * 1e9)


def parse_packet(packet: Packet, index: int, device_list: DeviceList) -> FilteredData:
    size = len(packet)
    eth_src = packet[Ether].src
    device_name = ""
    is_iot = False

    protocol = packet.lastlayer().name
    protocol = protocol if protocol is not None else "Unknown"

    timestamp = format_float_time(packet.time)

    if device_list is not None:
        try:
            device_name, is_iot = device_list[eth_src]
        except KeyError as e:
            print(
                "The following MAC could not be identified in the given device list: {}".format(
                    eth_src)
            )

    return (index, timestamp, size, eth_src, device_name, protocol, is_iot)


def parse_pcap(file_path: str, count: int, device_list: DeviceList, verbose=False, drop=False) -> list[FilteredData]:
    out: list[FilteredData] = []
    failed = []

    for index, packet in enumerate(PcapReader(file_path)):
        packet_index: int = index + 1

        if drop and drop_packets(packet):
            continue

        if index > count > 0:
            break

        try:
            filtered_data = parse_packet(packet, index, device_list)
            out.append(filtered_data)
        except IndexError as e:
            failed.append(packet_index + 1)

            if verbose:
                print(e)
                print("For packet ({}):".format(packet_index))
                packet.show()
            else:
                print(
                    "Index error for packet {} (probably could not find a layer, enable verbose to see more)".format(packet_index))

    if len(failed) > 0:
        print("Failed to parse {} packets out of {}".format(
            len(failed), len(out) + len(failed)))

        if verbose:
            print("Following packets could not be parsed:\n {}".format(failed))

    return out


def open_device_list(file_name: str | None) -> dict[str, tuple[str, bool]] | None:
    if file_name is None:
        return None

    with open(file_name, "r", newline="") as f:
        reader = csv.DictReader(f)
        devices = {}

        for line in reader:
            device_name = line["device_name"]
            device_mac = line["eth_src"]
            is_iot = line["iot"]

            devices[device_mac] = (device_name, is_iot)
        return devices


def to_csv(input: list[FilteredData], file_name: str) -> None:
    with open(file_name, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(filtered_data_csv_header)
        writer.writerows(input)


def main(input_file: str, output_file: str | None, device_list_file: str | None, count: int, verbose: bool, drop_icmp: bool) -> None:
    device_list = open_device_list(device_list_file)

    parsed: list[FilteredData] = parse_pcap(
        input_file, count, device_list, verbose=verbose, drop=drop_icmp)

    if output_file is None:
        output_file = input_file.replace("pcap", "csv")
    to_csv(parsed, output_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="pcap_to_csv.py"
    )
    parser.add_argument("input", nargs='+')
    parser.add_argument("-o" "--output", type=str)
    parser.add_argument("-d", "--device-list", type=str)
    parser.add_argument("-v", "--verbose", action='store_true')
    parser.add_argument("--no-drop-icmp", action="store_true")
    parser.add_argument("-c", "--count", default=50, type=int,
                        help="Number of packets parsed per file. Default is 50. To analyze all files, set to -1.")

    args = parser.parse_args()

    for file in args.input:
        try:
            print("Parsing {}...".format(file))
            main(file, args.o__output, args.device_list,
                 args.count, args.verbose, not args.no_drop_icmp)
        except KeyboardInterrupt:
            user_input = input(
                "Do you want to continue with the next file? (Y/n)")
            if user_input == "n":
                break