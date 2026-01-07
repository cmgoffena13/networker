# Networker

A simple CLI to monitor a local area network (LAN).  

Check out the release artifacts for the binary/executable. Once downloaded just rename to `networker`.

See [CLI Documentation](docs/cli.md) for detailed command usage.

> **Note:** Scapy requires admin privileges for ARP requests so `sudo` or an admin console is required.

## Getting Started

1. Make sure the downloaded binary/executable is in your System Path. 
2. Utilize the `networker scan` command to scan your network and save the results to the database

## Naming Your Devices

To name your devices I would first recommend running `networker scan -p` to scan your devices for open ports and save the information to the database.  

Once that is done, you can utilize the `networker device list` command to list all the devices and acquired information about them.  

Use the information to determine what the devices actually are, and then you can utilize the `networker device update` command to update the device names. Example below:  

```
networker device update --id 1 --data '{"device_name": "my device!"}'
```

Once the device names are updated, any future commands will show the device names in the output as well!