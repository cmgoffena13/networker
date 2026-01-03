# Networker

A simple CLI to monitor a local area network (LAN).  

 Navigate to the repo directory and utilize the `networker` bash script for easy access. Try `./networker --help` to get started!  

 See [CLI Documentation](docs/cli.md) for detailed command usage.

> **Note:** Scapy requires admin privileges for ARP requests so `sudo` is utilized.

## Getting Started

1. Navigate to the repo  
2. Utilize the `./networker init` command to initialize the sqlite database  
3. Utilize the `./networker scan -s` command to log your network and device information  

## Naming Your Devices

To name your devices I would first recommend running `./networker scan -p -s` to scan your devices for open ports and save the information to the database.  

Once that is done, you can utilize the `./networker device list` command to list all the devices and acquired information about them.  

Use the information to determine what the devices actually are, and then you can utilize the `./networker device update` command to update the device names. Example below:  

```
./networker device update --id 1 --data '{"device_name": "my device!"}'
```

Once the device names are updated, any future scans will show the device names in the output as well!

## Device Inferences

Device Inferences are declared open ports in TCP/UDP that are used in an attempt to infer a device type.

### How to Add in New Device Inferences

1. Add a new DeviceInference class to `src.database.db.db_seed_device_inferences`  

2. Utilize the `./networker inference update` command to reseed the inference records


