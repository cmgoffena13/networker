# `networker`

Networker CLI - Interact with your local area network (LAN)

**Usage**:

```console
$ networker [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--install-completion`: Install completion for the current shell.
* `--show-completion`: Show completion for the current shell, to copy it or customize the installation.
* `--help`: Show this message and exit.

**Commands**:

* `scan`: Scan the network for devices
* `list`: List information on networks stored
* `update`: Update the network information
* `monitor`: Monitor network traffic.
* `test`: Test internet connectivity
* `delete`: Delete a network and all associated data
* `reset`: Reset the database.
* `device`: Device commands
* `inference`: Inference commands

## `networker scan`

Scan the network for devices

**Usage**:

```console
$ networker scan [OPTIONS]
```

**Options**:

* `-v, --verbose`: Enable verbose (DEBUG) logging
* `-p, --ports`: Scan the network for open ports on devices
* `--help`: Show this message and exit.

## `networker list`

List information on networks stored

**Usage**:

```console
$ networker list [OPTIONS]
```

**Options**:

* `-v, --verbose`: Enable verbose (DEBUG) logging
* `--help`: Show this message and exit.

## `networker update`

Update the network information

**Usage**:

```console
$ networker update [OPTIONS]
```

**Options**:

* `-i, --id INTEGER`: Network ID to update  [required]
* `-d, --data TEXT`: JSON dictionary of fields to update (e.g., &#x27;{&quot;network_name&quot;: &quot;my network&quot;}&#x27;)  [required]
* `-v, --verbose`: Enable verbose (DEBUG) logging
* `--help`: Show this message and exit.

## `networker monitor`

Monitor network traffic.

**Usage**:

```console
$ networker monitor [OPTIONS]
```

**Options**:

* `-f, --filter TEXT`: Filter network traffic. Ex &#x27;tcp port 80&#x27;
* `-v, --verbose`: Enable verbose (DEBUG) logging
* `-e, --exclude-host`: Exclude the host from the network traffic
* `-d, --dns`: Monitor DNS traffic
* `--help`: Show this message and exit.

## `networker test`

Test internet connectivity

**Usage**:

```console
$ networker test [OPTIONS]
```

**Options**:

* `-v, --verbose`: Enable verbose (DEBUG) logging
* `-t, --trace`: Trace the internet connectivity test
* `--help`: Show this message and exit.

## `networker delete`

Delete a network and all associated data

**Usage**:

```console
$ networker delete [OPTIONS]
```

**Options**:

* `-i, --id INTEGER`: Network ID to delete  [required]
* `-v, --verbose`: Enable verbose (DEBUG) logging
* `--help`: Show this message and exit.

## `networker reset`

Reset the database. Deletes information.

**Usage**:

```console
$ networker reset [OPTIONS]
```

**Options**:

* `-v, --verbose`: Enable verbose (DEBUG) logging
* `--help`: Show this message and exit.

## `networker device`

Device commands

**Usage**:

```console
$ networker device [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `scan`: Scan the device for open ports
* `list`: List information on devices stored
* `update`: Update the device information
* `delete`: Delete a device and all associated data

### `networker device scan`

Scan the device for open ports

**Usage**:

```console
$ networker device scan [OPTIONS]
```

**Options**:

* `-v, --verbose`: Enable verbose (DEBUG) logging
* `-i, --id INTEGER`: Device ID to scan for open ports  [required]
* `--help`: Show this message and exit.

### `networker device list`

List information on devices stored

**Usage**:

```console
$ networker device list [OPTIONS]
```

**Options**:

* `-v, --verbose`: Enable verbose (DEBUG) logging
* `--help`: Show this message and exit.

### `networker device update`

Update the device information

**Usage**:

```console
$ networker device update [OPTIONS]
```

**Options**:

* `-i, --id INTEGER`: Device ID to update  [required]
* `-d, --data TEXT`: JSON dictionary of fields to update (e.g., &#x27;{&quot;device_name&quot;: &quot;my device&quot;}&#x27;)  [required]
* `-v, --verbose`: Enable verbose (DEBUG) logging
* `--help`: Show this message and exit.

### `networker device delete`

Delete a device and all associated data

**Usage**:

```console
$ networker device delete [OPTIONS]
```

**Options**:

* `-i, --id INTEGER`: Device ID to delete  [required]
* `-v, --verbose`: Enable verbose (DEBUG) logging
* `--help`: Show this message and exit.

## `networker inference`

Inference commands

**Usage**:

```console
$ networker inference [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `list`: List all inferences

### `networker inference list`

List all inferences

**Usage**:

```console
$ networker inference list [OPTIONS]
```

**Options**:

* `-v, --verbose`: Enable verbose (DEBUG) logging
* `--help`: Show this message and exit.
