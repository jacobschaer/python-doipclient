Welcome to doipclient's documentation!
=======================================

doipclient is a pure Python Diagnostic over IP (DoIP) client which can be used
for communicating with modern ECU's over automotive ethernet.

To discover ECU's on your network, you can use the Vehicle Identification
Announcement broadcast message as follows:

.. toctree::
   :maxdepth: 2
   :hidden:

   automotive_ethernet
   messages
   connectors

.. code-block:: python

    from doipclient import DoIPClient
    address, announcement = DoIPClient.await_vehicle_announcement()
    # Power cycle your ECU and wait for a few seconds for the broadcast to be
    # received
    logical_address = announcement.logical_address
    ip, port = address
    print(ip, port, logical_address)

Once you have the IP address and Logical Address for your ECU, you can connect
to it and begin interacting.

.. code-block:: python

    client = DoIPClient(ip, logical_address)
    print(client.request_entity_status())

You can also use UDS for diagnostic communication.

.. code-block:: python

    from doipclient.connectors import DoIPClientUDSConnector
    from udsoncan.client import Client
    from udsoncan.services import *

    uds_connection = DoIPClientUDSConnector(client)
    with Client(uds_connection) as uds_client:
        client.ecu_reset(ECUReset.ResetType.hardReset)


DoIPClient
----------
.. autoclass:: doipclient.DoIPClient
    :members:
