#!/usr/bin/env python3

import argparse
import os
import pcap_to_csv as pcap_parser

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_folder", type=str)
    parser.add_argument("-d" "--device-list", type=str)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    files: list[str] = os.listdir(args.input_folder)
    filtered_files = []

    for file in files:
        if "pcap" in file:
            filtered_files.append(file)

    print("Parsing {} files...".format(len(filtered_files)))

    for file in filtered_files:
        data = pcap_parser.main(
            args.input_folder + "/" + file,
            None,
            args.d__device_list,
            count=-1,
            verbose=args.verbose
        )
