# py-pingu
A Linux routing daemon with multi-gateway failover selection and metric assignment. Designed to work with dynamically assigned IP addresses.

It can also run **as standalone executable** (thanks to `py-installer`) and has been tested both on *x86_64* and *arm64v8* architectures.

## How it works? 
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
      "max_delay": 100 // maximum average delay (
    },
    "wlo1": {
      "metric": 50
    }
  },
  "period": 5 // a ping loop will be executed each 'period' seconds on all above defined interfaces
}
```

## Startup
`py-pingu --config config.json`

or 

`py-pingu --config config.json -v`

if you want enabled verbose mode.

## Requirements 
py-pingu only requires `scapy` and `pyroute2` packages.

`pip3 install --no-cache-dir scapy pyroute2`

## Building 


## Authors

Luigi Rodorigo

Domenico De Guglielmo


