Automotive Ethernet Primer
##########################

Diagnostic over IP (DoIP), as the name implies, sits on top of the IP protocol (specifically TCP and/or UDP) and doesn't care too much about the layers below (though they're still described in ISO-13400 for completeness). On vehicles where DoIP is available, it's often exposed in two places: the diagnostic port (OBD2/J1962 connector) and 100BASE-T1/1000BASE-T1 automotive ethernet between ECU's.

OBD2 Port
---------
ISO-13400-4 allows for manufacturers to provide DoIP through the OBD2 port using one of two pinouts:

Option 1

* Pin 3 (RX+)
* Pin 11 (RX-)
* Pin 12 (TX+)
* Pin 13 (TX-)
* Pin 8 (Activation)

Option 2

* Pin 1 (RX+)
* Pin 9 (RX-)
* Pin 12 (TX+)
* Pin 13 (TX-)
* Pin 8 (Activation)

While the detection algorithm is fairly complex, the general idea is that a tester is supposed to sense the resistance between Pin 8 (Activation) and Pin 5 (Signal Ground) to determine which configuration is in use.
Or, you could just look at a maintenance manual and figure it out that way (assuming you have access to one).
Once the layout is known, the tester is supposed to signal to the DoIP Edge Node that it would like to connect via ethernet by applying +5V to Pin 8.

As an example, BMW's "ENET" cable appears to use Option 1. A guide on making such a cable can be found at:
`BimmerPost.com ENET Cable Build Guide <https://f30.bimmerpost.com/forums/attachment.php?attachmentid=704810&d=1339310761>`_.

The 2 pairs of Tx/Rx lines provide ordinary IEEE 802.3 100BASE-TX ("Fast ethernet") - the same as what is commonly seen on desktop computers.

Direct connect to ECU's
-----------------------
ECU's that communicate over DoIP typically use Automotive Ethernet (100BASE-T1 or BroadR-Reach).
Unlike the normal 100BASE-TX ("fast ethernet") with two twisted pairs (or 1000BASE-T with 4 pairs) that are common on desktop computers, Automotive Ethernet utilizes just two wires and operates in master/slave pairs.
These are often terminated with `TE MATEnet connectors <https://www.te.com/usa-en/products/connectors/automotive-connectors/intersection/matenet.html?tab=pgp-story>`_.
As such, to connect with an ordinary desktop, a media converter is needed.
A popular choice is the `Intrepid RAD-Moon <https://intrepidcs.com/products/automotive-ethernet-tools/rad-moon/>`_.
No activation line is present or necessary.

Connecting to computer
-----------------------
Once a suitable ethernet physical connection has been established between a traditional (Linux/Windows/Mac) computer and either a DoIP enabled ECU or a DoIP edge node, the IP layer needs to be setup.
While the specification doesn't require it, DHCP is likely to be present (especially through the OBD2 connector).
In that case, the client computer need only be configured for DHCP and negotiate an address on the vehicle's DoIP network.
If DHCP isn't present, some sleuthing is likely needed.
You might need to use Wireshark in promiscuous mode and look for UDP broadcast messages or other TCP traffic to determine the correct subnet and an unused IP address.
Once this information is found, manually configure the appropriate network adapter on the test PC.

Windows specific IP settings
----------------------------
If you intend to use `await_vehicle_announcement` or expect UDP broadcasts to be receive, make sure that your subnet is properly configured in the IPV4 settings for your network adapter.
Often this will be 255.255.255.0, where the ECU will broadcast to x.x.x.255.
Use Wireshark to monitor the interface in promiscuous mode can be useful.

Additionally, you may need to reconfigure/disable the Windows Defender Firewall on your Guest/Public network.

Notes:
------

* ECU's are free to be as (in)flexible as they want, with respect to handling the IP layers and below. You should not assume that common features like ping (ICMP) will work.
* Unless DoIP is serving as the regulation required diagnostic connection (i.e.: OBD2), vendors may deviate from the specification with custom encryption, etc.
* Production ECU's may filter based on MAC address - in which case the test PC will need to "spoof" the MAC address of a known good address.
* You may have to modify/disable firewalls on your desktop computer to establish a connection with the ECU.
