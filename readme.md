# IoT Device Classifier

## Preparing the data

First, to get the data run the following command (this might take a while...):
```shell
$ ./scripts/get_data.sh
```
Next, parse an process the data to be trained
```shell 
$ ./scripts/parse_all_traces.py -d data/list_of_devices.csv data/traces/ data/traces/
```