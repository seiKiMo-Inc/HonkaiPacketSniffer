# Honkai Packet Sniffer

A simple command line sniffer/PCAP parser for the game Honkai Impact 3rd. Has been (somewhat) tested with version 6.1.

## Usage

Before use, set up a virtual environment and install the necessary dependencies via pipenv:

```
pipenv install
```

To read and parse a PCAP file and store the results in a JSON, use

```
pipenv run python sniffer.py --pcap <PCAP_PATH> --output <OUTPUT_PATH>
```

If you instead want to live sniff traffic, leave out the `--pcap` option. Note that, depending on your system, the necessary libraries need to be installed for this to work. Example:

```
pipenv run python sniffer.py --output <OUTPUT_PATH>
```

If you want to exclude certain packets from being logged to the console, you can use `--exclude`, for example

```
pipenv run python sniffer.py --exclude SyncTimeReq SyncTimeRsp --output <OUTPUT_PATH>
```
