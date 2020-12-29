from udsoncan.connections import BaseConnection

class PythonDoipUDSConnection(BaseConnection):
    """
    Sends and receives data using a `python_doip <https://github.com/jacobschaer/python_doip>`_ Python module which is a Python implementation of the DoIP transport protocol.

    `python_doip <https://github.com/jacobschaer/python_doip>`_ must be installed in order to use this connection.

    See an :ref:`example<_example_using_python_doip>`

    :param doip_layer: The DoIP Transport layer object coming from the ``python_doip`` module.
    :type doip_layer: :class:`python_doip.DoipClient<python_doip.DoipClient>`

    :param name: This name is included in the logger name so that its output can be redirected. The logger name will be ``Connection[<name>]``
    :type name: string

    """

    def __init__(self, doip_layer, name=None):
        BaseConnection.__init__(self, name)
        self._connection = doip_layer
        self.opened = True

    def open(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        self._connection.close()
        self.opened = False

    def is_open(self):
        return self.opened

    def specific_send(self, payload):
        self._connection.send_diagnostic(bytearray(payload))

    def specific_wait_frame(self, timeout=2):
        return bytes(self._connection.receive_diagnostic(timeout=timeout))

    def empty_rxqueue(self):
        self._connection.empty_rxqueue()

    def empty_txqueue(self):
        self._connection.empty_txqueue()
