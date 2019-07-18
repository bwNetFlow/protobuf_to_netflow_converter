# PROTOBUF_TO_NETFLOW_CONVERTER

This application aggregates consumed protobuf encoded flows according to their original NetFlow v9 exporter, converts these flows to NetFlow v9 compliant flows and subsequently sends NetFlow v9 compliant packets consisting of the aggregates flows to a user specified host.

# Installation

Debian/Ubuntu: Run first the configuration script
```
./configure.sh
```
Thereafter the make command can be used to compile the application
```
make
```

# Run

To run the protobuf_to_netflow converter the user needs superuser privileges.
The application can be started by the command
```
sudo ./main <path-to-config-file>
```

# Configuration File

The application needs a configuration file as starting parameter. The user must specify the following parameters in this configuration file:

topic: specifys-the-kafka-topic  
user: username  
pwd: pwd belonging to the user  
grp_id: the user specified grp id  
brokers: the kafka brokers to be used  
iface_name: the physical NIC id of the computer running this application, e.g., lo  
dst_ip: the target's ip address  
dst_port: the target's port number  
anonymization: yes or no; yes anonymizes all flow ip addresses according to the HMAC standard

