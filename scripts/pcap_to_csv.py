#!/usr/bin/env python3

import argparse
import csv
from scapy.all import *
from scapy.layers.inet import *

# TODO Might wanna do this with pd.dataframes
FilteredData = tuple[int, int, str, str, bool]
filtered_data_csv_header = ["Packet ID", "size", "eth.src", "Device", "IoT"]


def parse_pcap(file_path: str, count: int, device_list: dict[str, tuple[str, bool]] | None, verbose=False) -> list[FilteredData]:
    out: list[FilteredData] = []
    failed = []

    try:
        for index, packet in enumerate(PcapReader(file_path)):
            packet_index: int = index + 1

            if index > count > 0:
                break

            try:
                size: int = len(packet)
                eth_src: str = packet[Ether].src
                device_name: str = ""
                is_iot: bool = False

                if device_list is not None:
                    try:
                        device_name, is_iot = device_list[eth_src]
                    except KeyError as e:
                        print(
                            "The following MAC could not be identified in the given device list: {}".format(
                                eth_src)
                        )

                out.append((packet_index, size, eth_src, device_name, is_iot))
            except IndexError as e:
                failed.append(packet_index + 1)

                if verbose:
                    print(e)
                    print("For packet ({}):".format(packet_index))
                    packet.show()
                else:
                    print(
                        "Index error for packet {} (probably could not find a layer, enable verbose to see more)".format(packet_index))

    except KeyboardInterrupt:
        print("Intercepted exit code, finishing early...")

    if len(failed) > 0:
        print("Failed to parse {} packets out of {}".format(
            len(failed), len(out) + len(failed)))

        if verbose:
            print("Following packets could not be parsed:\n {}".format(failed))

    return out


def open_device_list(file_name: str | None) -> dict[str, [str, bool]] | None:
    if file_name is None:
        return None

    with open(file_name, "r", newline="") as f:
        reader = csv.DictReader(f)
        devices = {}

        for line in reader:
            device_name = line["Device Name"]
            device_mac = line["Mac Address"]
            is_iot = line["IoT"]

            devices[device_mac] = (device_name, is_iot)
        return devices


def to_csv(input: list[FilteredData], file_name: str) -> None:
    with open(file_name, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(filtered_data_csv_header)
        writer.writerows(input)


def main(input_file: str, output_file: str | None, device_list_file: str | None, count: int, verbose: bool) -> None:
    device_list = open_device_list(device_list_file)

    parsed: list[FilteredData] = parse_pcap(
        input_file, count, device_list, verbose=verbose)

    if output_file is None:
        output_file = input_file.replace("pcap", "csv")
    to_csv(parsed, output_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="pcap_to_csv.py"
    )
    parser.add_argument("input", type=str)
    parser.add_argument("-o" "--output", type=str)
    parser.add_argument("-d", "--device-list", type=str)
    parser.add_argument("-v", "--verbose", action='store_true')
    parser.add_argument("-c", "--count", default=50, type=int)

    args = parser.parse_args()
    main(args.input, args.o__output, args.device_list, args.count, args.verbose)
