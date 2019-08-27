# libvirt-wol
Wake-On-LAN implementation for Libvirt to start-up libvirt guests
# Usage

./libvirt-wol -d device [-p password] [-c connection-uri]

where:
- device is typically the bridge to bind on to listen to WoL requests.
- password is the optional password in form of dotted IP decimal (e.g. 192.168.1.1) or MAC address (e.g. 01:23:45:67:89:ab)
- connection URI is the libvirt connection URI to be used for MAC address lookup and guest start-up.

This can be run in rc.local to run automatically on device/computer start-up.
