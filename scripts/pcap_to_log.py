#!/usr/bin/env python3

import argparse
import csv
from scapy.all import *
# from scapy.layers.inet import *

# TODO Might wanna do this with pd.dataframes
FilteredData = list[tuple[str, int]]
filtered_data_csv_header = ["mac_src", "packet_size"]


def parse_pcap(file_path: str, count, verbose=False, resolve=False) -> FilteredData:
    out = []
    failed = []

    try:
        for index, packet in enumerate(PcapReader(file_path)):
            try:
                size = len(packet)
                origin = packet[Ether].src

                if resolve:
                    # TODO Resolve MAC
                    pass

                out.append((origin, size))
            except IndexError as e:
                failed.append(index)

                if verbose:
                    print(e)
                    print("For packet ({}):".format(index))
                    packet.show()
                else:
                    print(
                        "Index error for packet {} (probably could not find a layer, enable verbose to see more)".format(index))

    except KeyboardInterrupt:
        print("Intercepted exit code, finishing early...")

    if len(failed) > 0:
        print("Failed to parse {} packets out of {}".format(
            len(failed), len(out) + len(failed)))

        if verbose:
            print("Following packets could not be parsed:\n {}".format(failed))
    return out


def to_csv(input: FilteredData, file_name: str) -> None:
    with open(file_name, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(filtered_data_csv_header)
        writer.writerows(input)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=str)
    parser.add_argument("output", type=str)
    parser.add_argument("-v", "--verbose", action='store_true')
    parser.add_argument("-c", "--count", default=50, type=int)

    args = parser.parse_args()

    parsed = parse_pcap(args.input, args.count, verbose=args.verbose)
    to_csv(parsed, args.output)
