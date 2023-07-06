Welcome to doipclient's documentation!
=======================================

doipclient is a pure Python Diagnostic over IP (DoIP) client which can be used
for communicating with modern ECU's over automotive ethernet.

To discover ECU's on your network, you can use the Vehicle Identification
Announcement broadcast message (sent at powerup) as follows:

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

Alternatively, you can request a Vehicle Identification Response message:

.. code-block:: python

    from doipclient import DoIPClient
    address, announcement = DoIPClient.get_entity()
    logical_address = announcement.logical_address
    ip, port = address
    print(ip, port, logical_address)

Once you have the IP address and Logical Address for your ECU, you can connect
to it and begin interacting.

.. code-block:: python

    client = DoIPClient(ip, logical_address)
    print(client.request_entity_status())

You can also use UDS for diagnostic communication with the `udsoncan` library.

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


Encrypted Communication
-----------------------
:abbr:`TLS (Transport Layer Security)`/:abbr:`SSL (Secure Sockets Layer)` can 
be enabled by setting the `use_secure` parameter when creating an instance of 
`DoIPClient`.

.. code-block:: python

    client = DoIPClient(
        ip,
        logical_address,
        use_secure=True,  # Enable encryption
        tcp_port=3496,
    )

If more control is required, a preconfigured `SSL context`_ can be provided. 
For instance, to enforce the use of TLSv1.2, create a context with the desired 
protocol version:

.. code-block:: python

    import ssl

    # Enforce use of TLSv1.2
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

    client = DoIPClient(
        ip,
        logical_address,
        use_secure=ssl_context,
        tcp_port=3496,
    )

.. note::
   Since the communication is encrypted, debugging without the pre-master 
   secret is not possible. To decrypt the TLS traffic for analysis, the 
   pre-master secret can be dumped to a file and `loaded into Wireshark`_. 
   This can be done via the `built-in mechanism`_ or with `sslkeylog`_ when 
   using Python 3.7 and earlier.

.. _SSL context: https://docs.python.org/3/library/ssl.html#ssl-contexts
.. _loaded into Wireshark: https://wiki.wireshark.org/TLS#using-the-pre-master-secret
.. _built-in mechanism: https://docs.python.org/3/library/ssl.html#ssl.SSLContext.keylog_filename
.. _sslkeylog: https://pypi.org/project/sslkeylog/
