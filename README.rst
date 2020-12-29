python_doip
###########

python_doip is a pure Python 3 Diagnostic over IP (DoIP) client which can be used
for communicating with modern ECU's over automotive ethernet. It implements the
majority of ISO-13400 (2019) from the perspective of a short-lived synchronous
client. The primary use case is to serve as a transport layer implementation for
the `udsoncan <https://github.com/pylessard/python-udsoncan>`_ library. The code
is published under MIT license on GitHub (jacobschaer/python_doip).

Documentation
-------------

The documentation is available here :   http://python_doip.readthedocs.io

Requirements
------------

 - Python 3+

Installation
------------

using pip::

    pip install python_doip

Running Tests from source
-------------------------

using pytest::

    pip install pytest
    pytest

Example
-------
Updated version of udsoncan's example using python_doip instead of IsoTPSocketConnection

.. code-block:: python

   import SomeLib.SomeCar.SomeModel as MyCar

   import udsoncan
   from python_doip import DoIPClient
   from python_doip.adapters import PythonDoipUDSConnection
   from udsoncan.client import Client
   from udsoncan.exceptions import *
   from udsoncan.services import *
   
   udsoncan.setup_logging()
   
   ecu_ip = '127.0.0.1'
   ecu_logical_address = 0x00E0
   doip_client = DoIPClient(ecu_ip, ecu_logical_address)
   conn = PythonDoipUDSConnection(doip_client)
   with Client(conn,  request_timeout=2, config=MyCar.config) as client:
      try:
         client.change_session(DiagnosticSessionControl.Session.extendedDiagnosticSession)  # integer with value of 3
         client.unlock_security_access(MyCar.debug_level)   # Fictive security level. Integer coming from fictive lib, let's say its value is 5
         client.write_data_by_identifier(udsoncan.DataIdentifier.VIN, 'ABC123456789')       # Standard ID for VIN is 0xF190. Codec is set in the client configuration
         print('Vehicle Identification Number successfully changed.')
         client.ecu_reset(ECUReset.ResetType.hardReset)  # HardReset = 0x01
      except NegativeResponseException as e:
         print('Server refused our request for service %s with code "%s" (0x%02x)' % (e.response.service.get_name(), e.response.code_name, e.response.code))
      except InvalidResponseException, UnexpectedResponseException as e:
         print('Server sent an invalid payload : %s' % e.response.original_payload)