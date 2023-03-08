import pandas as pd
import sys

# Dictionary storing the mean of each device and the name of each device
global dev_means, dev_MACs


def initialize_dev_means(device):
    # Create a copy to modify
    global dev_means
    global dev_MACs
    # Initialize to be empty
    dev_means = {}
    dev_MACs = {}
    # Iterate over each device
    for i in device.index:
        # Initialize the mean of each device to 0 and sets its counter to 1
        dev_means[device['Mac Address'][i]] = (0, 1.0)
        # Store the name with the device name
        dev_MACs[device['Mac Address'][i]] = device['Device Name'][i]
    return dev_means


def calculate_mean(packages, att):
    # Calculate the mean of the given attribute for each device
    for j in packages.index:
        x, y = dev_means.get(packages['eth.src'][j])
        upd_mean = ((x * (y - 1)) / y) + (packages[att][j] / y)
        dev_means[packages['eth.src'][j]] = (upd_mean, y + 1)


def main(csv, devices):
    # Read the CSV of the list of devices into a dataframe
    df_dev = pd.read_csv(devices, usecols=['Device Name', 'Mac Address'])

    # Initialize the dictionary storing the means of each device
    initialize_dev_means(df_dev)

    # Read CSV of the pcaps into a dataframe
    df_pkg = pd.read_csv(csv, usecols=['eth.src', 'Size'])

    print(df_pkg)

    # Calculate the mean of the package size of each device
    calculate_mean(df_pkg, 'Size')


if __name__ == "__main__":
    csv = sys.argv[1]
    devices = sys.argv[2]

    main(csv, devices)

    for i in dev_means :
        x, y = dev_means.get(i)
        z = dev_MACs.get(i)
        print("Device " + z + " with MAC address " + i + " has a mean package size of", x)