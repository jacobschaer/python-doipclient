python-doipclient
#################

.. image:: https://travis-ci.com/jacobschaer/python-doipclient.svg?branch=main
    :target: https://travis-ci.com/jacobschaer/python-doipclient

doipclient is a pure Python 3 Diagnostic over IP (DoIP) client which can be used
for communicating with modern ECU's over automotive ethernet. It implements the
majority of ISO-13400 (2019) from the perspective of a short-lived synchronous
client. The primary use case is to serve as a transport layer implementation for
the `udsoncan <https://github.com/pylessard/python-udsoncan>`_ library. The code
is published under MIT license on GitHub (jacobschaer/python-doipclient).

Documentation
-------------

The documentation is available here : https://python-doipclient.readthedocs.io/

Requirements
------------

 - Python 3.6+

Installation
------------

using pip::

    pip install doipclient

Running Tests from source
-------------------------

using pytest::

    pip install pytest pytest-mock
    pytest

Example
-------
Updated version of udsoncan's example using `python_doip` instead of IsoTPSocketConnection

.. code-block:: python

   import SomeLib.SomeCar.SomeModel as MyCar

   import udsoncan
   from doipclient import DoIPClient
   from doipclient.connectors import DoIPClientUDSConnector
   from udsoncan.client import Client
   from udsoncan.exceptions import *
   from udsoncan.services import *
   
   udsoncan.setup_logging()
   
   ecu_ip = '127.0.0.1'
   ecu_logical_address = 0x00E0
   doip_client = DoIPClient(ecu_ip, ecu_logical_address)
   conn = DoIPClientUDSConnector(doip_client)
   with Client(conn,  request_timeout=2, config=MyCar.config) as client:
      try:
         client.change_session(DiagnosticSessionControl.Session.extendedDiagnosticSession)  # integer with value of 3
         client.unlock_security_access(MyCar.debug_level)                                   # Fictive security level. Integer coming from fictive lib, let's say its value is 5
         client.write_data_by_identifier(udsoncan.DataIdentifier.VIN, 'ABC123456789')       # Standard ID for VIN is 0xF190. Codec is set in the client configuration
         print('Vehicle Identification Number successfully changed.')
         client.ecu_reset(ECUReset.ResetType.hardReset)                                     # HardReset = 0x01
      except NegativeResponseException as e:
         print('Server refused our request for service %s with code "%s" (0x%02x)' % (e.response.service.get_name(), e.response.code_name, e.response.code))
      except InvalidResponseException, UnexpectedResponseException as e:
         print('Server sent an invalid payload : %s' % e.response.original_payload)

python-uds Support
------------------
The `python-uds <https://github.com/richClubb/python-uds>`_ can also be used
but requires a fork until the owner merges this PR
`Doip #63 <https://github.com/richClubb/python-uds/pull/63>`. For now, to use
the port:

using pip::

    git clone https://github.com/jacobschaer/python-uds
    git checkout doip
    cd python-uds
    pip install .

Example:

.. code-block:: python

   from uds import Uds

   ecu = Uds(transportProtocol="DoIP", ecu_ip="192.168.1.1", ecu_logical_address=1)
   try:
       response = ecu.send([0x3E, 0x00])
       print(TesterPresent)  # This should be [0x7E, 0x00]
   except:
       print("Send did not complete")