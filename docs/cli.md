# `networker`

Networker CLI - Interact with your local network

**Usage**:

```console
$ networker [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--install-completion`: Install completion for the current shell.
* `--show-completion`: Show completion for the current shell, to copy it or customize the installation.
* `--help`: Show this message and exit.

**Commands**:

* `init`: Initialize the sqlite database and seed...
* `network`: Network commands
* `device`: Device commands

## `networker init`

Initialize the sqlite database and seed lookup data

**Usage**:

```console
$ networker init [OPTIONS]
```

**Options**:

* `-v, --verbose`: Enable verbose (DEBUG) logging
* `--help`: Show this message and exit.

## `networker network`

Network commands

**Usage**:

```console
$ networker network [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `init`: Initialize the network and devices...
* `scan`: Scan the network for open ports on devices
* `list`: List information on networks stored
* `monitor`: Monitor network traffic

### `networker network init`

Initialize the network and devices information

**Usage**:

```console
$ networker network init [OPTIONS]
```

**Options**:

* `-v, --verbose`: Enable verbose (DEBUG) logging
* `--help`: Show this message and exit.

### `networker network scan`

Scan the network for open ports on devices

**Usage**:

```console
$ networker network scan [OPTIONS]
```

**Options**:

* `-s, --save`: Save the network scan results to the database
* `-v, --verbose`: Enable verbose (DEBUG) logging
* `--help`: Show this message and exit.

### `networker network list`

List information on networks stored

**Usage**:

```console
$ networker network list [OPTIONS]
```

**Options**:

* `-v, --verbose`: Enable verbose (DEBUG) logging
* `--help`: Show this message and exit.

### `networker network monitor`

Monitor network traffic

**Usage**:

```console
$ networker network monitor [OPTIONS]
```

**Options**:

* `-f, --filter TEXT`: Filter network traffic
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

### `networker device scan`

Scan the device for open ports

**Usage**:

```console
$ networker device scan [OPTIONS]
```

**Options**:

* `-s, --save`: Save the device scan results to the database
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
