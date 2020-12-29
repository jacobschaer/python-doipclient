Automotive Ethernet Primer
##########################

Diagnostic over IP (DoIP) is typically implemented on top of Automotive Ethernet (100BASE-T1 or BroadR-Reach). Unlike normal 1000BASE-T with its four twisted pairs that is common on desktop computers, automotive ethernet utilizes just two wires and operates in master/slave pairs. As such, to connect with an ordinary desktop, a media converter is needed. A popular choice is the Intrepid RAD-Moon: Intrepid RAD-Moon: https://intrepidcs.com/products/automotive-ethernet-tools/rad-moon/

Above the physical layer, automotive ethernet and conventional ethernet are very similar. DoIP uses both UDP and TCP on IPv4 networks.

As a minimum to use python_doip library, the user must:
#. Connect to the ECU using an automotive ethernet media converter
#. Determine the ECU's subnet. If you don't already know this, and the ECU does not provide a DHCP server, you may need to do a little detective work using Wireshark.
#. Assign an appropriate IP address within the ECU's subnet to the network interface attached to the media converter

Notes:
------
* ECU's are free to be as inflexible as they'd like with respect to handling the IP layers and below. You should not assume that common features like ping (ICMP) will work.
* Production ECU's may filter based on MAC address which will make this quite difficult
* You may have to modify/disable firewalls on your desktop computer to establish a connection with the ECU