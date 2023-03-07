import pandas as pd
import sys

global dev_mode, dev_mean, dev_median


def main(csv, devices):
    # Read the CSV of the list of devices into a dataframe
    df = pd.read_csv(devices, usecols=['Device Name', 'Mac Address'])

    # Read CSV of the pcaps into a dataframe
    df_pkg = pd.read_csv(csv, usecols=['eth.src', 'Size'])

    # Create a copy to modify
    global dev_mode, dev_mean, dev_median
    # Initialize to be empty
    dev_mode = []
    dev_mean = []
    dev_median = []

    for j in df.index:
        mode = df_pkg.loc[df_pkg['eth.src'] == df['Mac Address'][j], 'Size'].mode()
        mean = df_pkg.loc[df_pkg['eth.src'] == df['Mac Address'][j], 'Size'].mean()
        median = df_pkg.loc[df_pkg['eth.src'] == df['Mac Address'][j], 'Size'].median()

        final_mode = float("nan")
        if (len(mode) == 0):
            dev_mode.append(final_mode)
        else:
            final_mode = mode.iloc[0]
            dev_mode.append(final_mode)

        dev_mean.append(mean)
        dev_median.append(median)

        print (df['Device Name'][j] + " with mode =" , final_mode, " mean =", mean, "and median =", median)


if __name__ == "__main__":
    csv = sys.argv[1]
    devices = sys.argv[2]

    main(csv, devices)
    #
    # print(dev_mode)
    # print(dev_mean)
    # print(dev_median)
