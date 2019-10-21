# py-pingu
A Linux routing daemon with multi-gateway failover selection and metric assignment. Designed to work with dynamically assigned IP addresses.

## How it works? 
py-pingu continuously monitors the main Linux routing table, when a new default gateway is added, py-pingu fetches the destination IP address and it removes from the kernel he associated route.

Periodically it tries to ping the `host` IP address by using the discovered default gateway for each interface in `config.json` (no routes are installed for an interface if a corresponding default gateway has not been discovered)

If the `host` correctly replies to the ICMP requests (and the `max_lost` and `max_delay` conditions are met) the corresponding default gateway route is installed, by using the metric and the proto specified (for each interface) in the configuration file and the.


## Example Configuration File

```
{
  "host": "8.8.8.8", // Ping requests are sent to this host 
  "proto": 136, // Proto number of the routes installed by py-pingu
  "interfaces": {  // map of all monitored interfaces
    "eno2": { // interface name
      "metric": 88, // if the interface is ok the host then the route will be installed with this metric
      "count": 10, // count of sent ICMP requests
      "max_lost": 5, // maximum number of lost packets (if lost > max_lost the gw of this interface will be disabled)
      "max_delay": 100 // maximum average delay (
    },
    "wlo1": {
      "metric": 50
    }
  },
  "period": 5 // a ping burst will be sent to all above interfaces each 'period' seconds
}
```

## Requirements 
py-pingu continuously monitors the main Linux routing table, when a new default gateway is added, py-pingu fetches the destination IP address and it removes from the kernel he associated route.

Periodically it tries to ping the `host` IP address by using the discovered default gateway for each interface in `config.json` (no routes are installed for an interface if a corresponding default gateway has not been discovered)

If the `host` correctly replies to the ICMP requests (and the `max_lost` and `max_delay` conditions are met) the corresponding default gateway route is installed, by using the metric and the proto specified (for each interface) in the configuration file and the.


