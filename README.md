# py-pingu
A Linux routing daemon with multi-gateway failover selection and metric assignment. Designed to work with dynamically assigned IP addresses.

It can also run **as standalone executable** (thanks to `py-installer`) and has been tested both on *x86_64* and *arm64v8* architectures.

## How does it works? 
py-pingu continuously monitors the main Linux routing table. When a default gateway is added to the routing table, py-pingu fetches the destination IP address and removes the entry from the routing table.

Periodically (each `period` seconds), for each interface in `config.json`, it tries to ping the specified `host` using the discovered default gateway for the interface (an interface is not probed if its default gateway has not been discovered)

If the `host` correctly replies to the ICMP requests (and the `max_lost` and `max_delay` conditions are met) the corresponding default gateway route is installed. *metric* and *proto* fields of the installed route are set as specified (for each interface) in the configuration file.

## Example Configuration File

```
{
  "host": "8.8.8.8", // Ping requests are sent to this host 
  "proto": 136, // Proto number of the routes installed by py-pingu
  "interfaces": {  // map of all monitored interfaces
    "eno2": { // interface name
      "metric": 100, // if the interface is ok the host then the route will be installed with this metric
      "count": 10, // count of sent ICMP requests
      "max_lost": 5, // maximum number of lost packets (if lost > max_lost the gw of this interface will be disabled)
      "max_delay": 100, // maximum average delay (
      "period": 10 // probe eno2 each 10 seconds
    },
    "wlo1": {
      "metric": 50,
      "period": 50 // probe wlo1 each 50 seconds
    }
  }
}
```

## Startup
`py-pingu --config config.json`

or 

`py-pingu --config config.json -v`

if you want enabled verbose mode.

## Requirements 
py-pingu requires `scapy` and `pyroute2` python packages.

`pip3 install --no-cache-dir scapy pyroute2`

In order to use Berkley Packet Filtering also the `tcpdump` is needed by py-pingu.
 
## Building 
You can use the `build.sh` script to generate a statically-linked single-executable. 
It must run as `sudo` and needs a running `docker` instance.

`sudo build.sh`

By default it generates an `arm64v8` executable.
You can uncomment `ARCH=x86` line to build an x86 executable.


## Changelog
29/10/2019
- It's now possible to probe each interface using a different wait period. (e.g. `wlo1` each 20 seconds, `eth0` each 200 seconds).
- Added the support for non-ethernet interfaces (such as PPP serial modem). 
When using a non-ethernet interface a L3 raw-socket is used and the ARP resolution is not performed.
The destination gateway for point-to-point interfaces is shown as `None` in the log.
 
## Authors

Luigi Rodorigo

Domenico De Guglielmo


