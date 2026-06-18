# rarpy
RARP server implemented in Python that responds to RARP requests with a configured MAC-to-IP mapping.

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://github.com/Charlotte-Knight/rarpy/blob/main/LICENSE)


## Installation

Sudo must be used when installing and running rarpy so that it can access the network interfaces.

```
sudo pip install rarpy
```

## Usage

The server is started via the `rarpy` executable whose usage in the command line can be accessed via `sudo rarpy --help`.

The network interface that the server listens to must be specified, for example:
```
sudo rarpd en0
```
starts a server listening on interface `en0`.

The MAC-to-IP mapping can be configured via the command line with the `--mapping` (`-m`) option:
```
sudo rarpy -m 02:0d:db:a1:15:10 192.168.10.201 en0
```
and multiple mappings can be specified if desired:
```
sudo rarpy -m 02:0d:db:a1:15:10 192.168.10.201 -m 02:0d:db:a1:15:11 192.168.10.201 en0
```

Mappings can be also be configured in a file structured like:
```
02:0d:db:a1:15:10 192.168.10.201
02:0d:db:a1:15:11 192.168.10.201
```
and then picked up by `rarpy` with the `--mapping-file` (`-f`) option:
```
sudo rarpy -f /path/to/mapping/file en0
```
Mappings from a file and command line can be used simultaneously, and where there are conflicts, the command line mapping overrides the file. 

If no `--mapping-file` is specified, `rarpy` will look to see if `/etc/ethers` exists (default file from older RARP daemon tools), and if it does, it will use that file.