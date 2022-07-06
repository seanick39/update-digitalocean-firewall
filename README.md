# Update DigitalOcean Firewall

## Description
Update a firewall with a specified port for given IP address(es). Use option `-c` to fetch the current IP address of system running this program, and use it as the IP address.

### Building:
- Requires Boost::program_options, Boost::json and Boost::beast

```sh
$ mkdir build && cd build
$ cmake ..
$ make
```

#### Note: Use `cmake -DBOOST_ROOT=/path/to/boost_1_78_0 ..` if cmake fails to find boost
