import logging
import socket
import struct
import time
import ssl
from enum import IntEnum
from .constants import TCP_DATA_UNSECURED, UDP_DISCOVERY, A_PROCESSING_TIME
from .messages import *

logger = logging.getLogger("doipclient")


class Parser:
    """Implements state machine for DoIP transport layer.

    See Table 16 "Generic DoIP header structure" of ISO 13400-2:2019 (E). While TCP transport
    is reliable, the UDP broadcasts are not, so the state machine is a little more defensive
    than one might otherwise expect. When using TCP, reads from the socket aren't guaranteed
    to be exactly one DoIP message, so the running buffer needs to be maintained across reads
    """

    class ParserState(IntEnum):
        READ_PROTOCOL_VERSION = 1
        READ_INVERSE_PROTOCOL_VERSION = 2
        READ_PAYLOAD_TYPE = 3
        READ_PAYLOAD_SIZE = 4
        READ_PAYLOAD = 5

    def __init__(self):
        self.rx_buffer = bytearray()
        self.protocol_version = None
        self.payload_type = None
        self.payload_size = None
        self.payload = bytearray()
        self._state = Parser.ParserState.READ_PROTOCOL_VERSION     

    def read_message(self, data_bytes):
        self.rx_buffer += data_bytes
        while self.rx_buffer:
            if self._state == Parser.ParserState.READ_PROTOCOL_VERSION:
                self.payload = bytearray()
                self.payload_type = None
                self.payload_size = None
                self.protocol_version = int(self.rx_buffer.pop(0))
                self._state = Parser.ParserState.READ_INVERSE_PROTOCOL_VERSION
            elif self._state == Parser.ParserState.READ_INVERSE_PROTOCOL_VERSION:
                inverse_protocol_version = int(self.rx_buffer.pop(0))
                if inverse_protocol_version != (0xFF ^ self.protocol_version):
                    logger.warning(
                        "Bad DoIP Header - Inverse protocol version does not match. Ignoring."
                    )
                    # Bad protocol version inverse - shift the buffer forward
                    self.protocol_version = inverse_protocol_version
                else:
                    self._state = Parser.ParserState.READ_PAYLOAD_TYPE
            elif self._state == Parser.ParserState.READ_PAYLOAD_TYPE:
                if len(self.rx_buffer) >= 2:
                    self.payload_type = self.rx_buffer.pop(0) << 8
                    self.payload_type |= self.rx_buffer.pop(0)
                    self._state = Parser.ParserState.READ_PAYLOAD_SIZE
                else:
                    break
            elif self._state == Parser.ParserState.READ_PAYLOAD_SIZE:
                if len(self.rx_buffer) >= 4:
                    self.payload_size = self.rx_buffer.pop(0) << 24
                    self.payload_size |= self.rx_buffer.pop(0) << 16
                    self.payload_size |= self.rx_buffer.pop(0) << 8
                    self.payload_size |= self.rx_buffer.pop(0)
                    self._state = Parser.ParserState.READ_PAYLOAD
                else:
                    break
            elif self._state == Parser.ParserState.READ_PAYLOAD:
                remaining_bytes = self.payload_size - len(self.payload)
                self.payload += self.rx_buffer[:remaining_bytes]
                self.rx_buffer = self.rx_buffer[remaining_bytes:]
                if len(self.payload) == self.payload_size:
                    self._state = Parser.ParserState.READ_PROTOCOL_VERSION
                    logger.debug(
                        "Received DoIP Message. Type: 0x{:x}, Size: {} bytes, Payload: {}".format(
                            self.payload_type,
                            self.payload_size,
                            [hex(x) for x in data_bytes],
                        )
                    )
                    try:
                        return payload_type_to_message[self.payload_type].unpack(
                            self.payload, self.payload_size
                        )
                    except KeyError:
                        return ReservedMessage.unpack(
                            self.payload_type, self.payload, self.payload_size
                        )
                else:
                    break


class DoIPClient:
    """A Diagnostic over IP (DoIP) Client implementing the majority of ISO-13400-2:2019 (E).

    This is a basic DoIP client which was designed primarily for use with the python-udsoncan package for UDS communication
    with ECU's over automotive ethernet. Certain parts of the specification would require threaded operation to
    maintain the time-based state described by the ISO document. However, in practice these are rarely important,
    particularly for use with UDS - especially with scripts that tend to go through instructions as fast as possible.

    :param ecu_ip_address: This is the IP address of the target ECU. This should be a string representing an IPv4
        address like "192.168.1.1". Like the logical_address, if you don't know the value for your ECU, utilize the
        await_vehicle_announcement() method.
    :type ecu_ip_address: str
    :param ecu_logical_address: The logical address of the target ECU. This should be an integer. According to the
        specification, the correct range is 0x0001 to 0x0DFF ("VM specific"). If you don't know the logical address,
        use the await_vehicle_announcement() method and power cycle the ECU - it should identify itself on bootup.
    :type ecu_logical_address: int
    :param tcp_port: The destination TCP port for DoIP data communication. By default this is 13400 for unsecure and
        3496 when using TLS.
    :type tcp_port: int, optional
    :param activation_type: The activation type to use on initial connection. Most ECU's require an activation request
        before they'll respond, and typically the default activation type will do. The type can be changed later using
        request_activation() method. Use `None` to disable activation at startup.
    :type activation_type: RoutingActivationRequest.ActivationType, optional
    :param protocol_version: The DoIP protocol version to use for communication. Represents the version of the ISO 13400
        specification to follow. 0x02 (2012) is probably correct for most ECU's at the time of writing, though technically
        this implementation is against 0x03 (2019).
    :type protocol_version: int
    :param client_logical_address: The logical address that this DoIP client will use to identify itself. Per the spec,
        this should be 0x0E00 to 0x0FFF. Can typically be left as default.
    :type client_logical_address: int
    :param client_ip_address: If specified, attempts to bind to this IP as the source for both UDP and TCP communication.
        Useful if you have multiple network adapters.
    :type client_ip_address: str, optional
    :param use_secure: Enables TLS if True. Untested. Should be combined with changing tcp_port to 3496.
    :type use_secure: bool
    :param log_level: Logging level
    :type log_level: int

    :raises ConnectionRefusedError: If the activation request fails
    """

    def __init__(
        self,
        ecu_ip_address,
        ecu_logical_address,
        tcp_port=TCP_DATA_UNSECURED,
        udp_port=UDP_DISCOVERY,
        activation_type=RoutingActivationRequest.ActivationType.Default,
        protocol_version=0x02,
        client_logical_address=0x0E00,
        client_ip_address=None,
        use_secure=False,
    ):
        self._ecu_logical_address = ecu_logical_address
        self._client_logical_address = client_logical_address
        self._client_ip_address = client_ip_address
        self._use_secure = use_secure
        self._ecu_ip_address = ecu_ip_address
        self._tcp_port = tcp_port
        self._udp_port = udp_port
        self._activation_type = activation_type
        self._udp_parser = Parser()
        self._tcp_parser = Parser()
        self._protocol_version = protocol_version
        self._connect()
        if self._activation_type is not None:
            result = self.request_activation(self._activation_type)
            if result.response_code != RoutingActivationResponse.ResponseCode.Success:
                raise ConnectionRefusedError(
                    f"Activation Request failed with code {result.response_code}"
                )

    class TransportType(IntEnum):
        TRANSPORT_UDP = 1
        TRANSPORT_TCP = 2

    @classmethod
    def await_vehicle_announcement(cls, udp_port=UDP_DISCOVERY, timeout=None):
        """Receive Vehicle Announcement Message

        When an ECU first turns on, it's supposed to broadcast a Vehicle Announcement Message over UDP 3 times
        to assist DoIP clients in determining ECU IP's and Logical Addresses.

        :param udp_port: The UDP port to listen on. Per the spec this should be 13400, but some VM's use a custom
            one.
        :type udp_port: int, optional
        :param timeout: Maximum amount of time to wait for message
        :type timeout: float, optional
        :return: IP Address of ECU and VehicleAnnouncementMessage object
        :rtype: tuple
        :raises TimeoutError: If vehicle announcement not received in time
        """
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if timeout is not None:
            sock.settimeout(timeout)
        sock.bind(("", udp_port))
        parser = Parser()

        while True:
            remaining = None
            if timeout:
                duration = time.time() - start_time
                if duration >= timeout:
                    raise TimeoutError(
                        "Timed out waiting for Vehicle Announcement broadcast"
                    )
                else:
                    remaining = timeout - duration
                    sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(1024)
                if data[0] != 0:
                    print(data)
            except socket.timeout as ex:
                raise TimeoutError(
                    "Timed out waiting for Vehicle Announcement broadcast"
                )
            result = parser.read_message(data)
            if result:
                return addr, result

    def empty_rxqueue(self):
        """Implemented for compatibility with udsoncan library. Nothing useful to be done yet"""
        pass

    def empty_txqueue(self):
        """Implemented for compatibility with udsoncan library. Nothing useful to be done yet"""
        pass

    def read_doip(self, timeout=A_PROCESSING_TIME, transport=TransportType.TRANSPORT_TCP):
        """Helper function to read from the DoIP socket.

        :param timeout: Maximum time allowed for response from ECU
        :type timeout: float, optional
        :param transport: The IP transport layer to read from, either UDP or TCP
        :type transport: DoIPClient.TransportType, optional
        :raises IOError: If DoIP layer fails with negative acknowledgement
        :raises TimeoutException: If ECU fails to respond in time
        """
        start_time = time.time()
        data = bytearray()
        while (time.time() - start_time) <= timeout:
            if transport == DoIPClient.TransportType.TRANSPORT_TCP:
                response = self._tcp_parser.read_message(data)
            else:
                response = self._udp_parser.read_message(data)                
            data = bytearray()
            if type(response) == GenericDoIPNegativeAcknowledge:
                raise IOError(
                    f"DoIP Negative Acknowledge. NACK Code: {response.nack_code}"
                )
            elif type(response) == AliveCheckRequest:
                logger.warning("Responding to an alive check")
                self.send_doip_message(AliveCheckResponse(self._client_logical_address))
            elif response:
                return response
            else:
                try:
                    if transport == DoIPClient.TransportType.TRANSPORT_TCP:
                        data = self._tcp_sock.recv(1024)
                    else:
                        data = self._udp_sock.recv(1024)
                except socket.timeout:
                    pass
        raise TimeoutError("ECU failed to respond in time")

    def send_doip(self, payload_type, payload_data, transport=TransportType.TRANSPORT_TCP):
        """Helper function to send to the DoIP socket.

        Adds the correct DoIP header to the payload and sends to the socket.

        :param payload_type: The payload type (see Table 17 "Overview of DoIP payload types" in ISO-13400
        :type payload_type: int
        :param transport: The IP transport layer to send to, either UDP or TCP
        :type transport: DoIPClient.TransportType, optional
        """
        data_bytes = struct.pack(
            "!BBHL",
            self._protocol_version,
            0xFF ^ self._protocol_version,
            payload_type,
            len(payload_data),
        )
        data_bytes += payload_data
        logger.debug(
            "Sending DoIP Message: Type: 0x{:x}, Size: {}, Payload: {}".format(
                payload_type, len(payload_data), [hex(x) for x in data_bytes]
            )
        )
        if transport == DoIPClient.TransportType.TRANSPORT_TCP:
            self._tcp_sock.send(data_bytes)
        else:
            self._udp_sock.sendto(data_bytes, (self._ecu_ip_address, self._udp_port))

    def send_doip_message(self, doip_message, transport=TransportType.TRANSPORT_TCP.TRANSPORT_TCP):
        """Helper function to send an unpacked message to the DoIP socket.

        Packs the given message and adds the correct DoIP header before sending to the socket

        :param doip_message: DoIP message object
        :type doip_message: object
        :param transport: The IP transport layer to send to, either UDP or TCP
        :type transport: DoIPClient.TransportType, optional
        """
        payload_type = payload_message_to_type[type(doip_message)]
        payload_data = doip_message.pack()
        self.send_doip(payload_type, payload_data, transport=transport)

    def request_activation(self, activation_type, vm_specific=None):
        """Requests a given activation type from the ECU for this connection using payload type 0x0005

        :param activation_type: The type of activation to request - see Table 47 ("Routing
            activation request activation types") of ISO-13400, but should generally be 0 (default)
            or 1 (regulatory diagnostics)
        :type activation_type: RoutingActivationRequest.ActivationType
        :param vm_specific: Optional 4 byte long int
        :type vm_specific: int, optional
        :return: The resulting activation response object
        :rtype: RoutingActivationResponse
        """
        message = RoutingActivationRequest(
            self._client_logical_address, activation_type, vm_specific=vm_specific
        )
        self.send_doip_message(message)
        while True:
            result = self.read_doip()
            if type(result) == RoutingActivationResponse:
                return result
            elif result:
                logger.warning(
                    "Received unexpected DoIP message type {}. Ignoring".format(
                        type(result)
                    )
                )

    def request_vehicle_identification(self, eid=None, vin=None):
        """Requests a VehicleIdentificationResponse from the ECU, either with a specified VIN, EIN,
        or nothing.

        :param eid: EID of the Vehicle
        :type eid: bytes, optional
        :param vin: VIN of the Vehicle
        :type vin: str, optional
        :return: The vehicle identification response message
        :rtype: VehicleIdentificationResponse
        """
        if eid:
            message = VehicleIdentificationRequestWithEID(eid)
        elif vin:
            message = VehicleIdentificationRequestWithVIN(vin)
        else:
            message = VehicleIdentificationRequest()
        self.send_doip_message(message, transport=DoIPClient.TransportType.TRANSPORT_UDP)
        while True:
            result = self.read_doip(transport=DoIPClient.TransportType.TRANSPORT_UDP)
            if type(result) == VehicleIdentificationResponse:
                return result
            elif result:
                logger.warning(
                    "Received unexpected DoIP message type {}. Ignoring".format(
                        type(result)
                    )
                )

    def request_alive_check(self):
        """Request that the ECU send an alive check response

        :return: Alive Check Response object
        :rtype: AliveCheckResopnse
        """
        message = AliveCheckRequest()
        self.send_doip_message(message, transport=DoIPClient.TransportType.TRANSPORT_UDP)
        while True:
            result = self.read_doip(transport=DoIPClient.TransportType.TRANSPORT_UDP)
            if type(result) == AliveCheckResponse:
                return result
            elif result:
                logger.warning(
                    "Received unexpected DoIP message type {}. Ignoring".format(
                        type(result)
                    )
                )

    def request_diagnostic_power_mode(self):
        """Request that the ECU send a Diagnostic Power Mode response

        :return: Diagnostic Power Mode Response object
        :rtype: DiagnosticPowerModeResponse
        """
        message = DiagnosticPowerModeRequest()
        self.send_doip_message(message, transport=DoIPClient.TransportType.TRANSPORT_UDP)
        while True:
            result = self.read_doip(transport=DoIPClient.TransportType.TRANSPORT_UDP)
            if type(result) == DiagnosticPowerModeResponse:
                return result
            elif result:
                logger.warning(
                    "Received unexpected DoIP message type {}. Ignoring".format(
                        type(result)
                    )
                )

    def request_entity_status(self):
        """Request that the ECU send a DoIP Entity Status Response

        :return: DoIP Entity Status Response
        :rtype: EntityStatusResponse
        """
        message = DoipEntityStatusRequest()
        self.send_doip_message(message, transport=DoIPClient.TransportType.TRANSPORT_UDP)
        while True:
            result = self.read_doip(transport=DoIPClient.TransportType.TRANSPORT_UDP)
            if type(result) == EntityStatusResponse:
                return result
            elif result:
                logger.warning(
                    "Received unexpected DoIP message type {}. Ignoring".format(
                        type(result)
                    )
                )

    def send_diagnostic(self, diagnostic_payload):
        """Send a raw diagnostic payload (ie: UDS) to the ECU.

        :param diagnostic_payload: UDS payload to transmit to the ECU
        :type diagnostic_payload: bytearray
        :raises IOError: DoIP negative acknowledgement received
        """
        message = DiagnosticMessage(
            self._client_logical_address, self._ecu_logical_address, diagnostic_payload
        )
        self.send_doip_message(message)
        while True:
            result = self.read_doip()
            if type(result) == DiagnosticMessageNegativeAcknowledgement:
                raise IOError(
                    "Diagnostic request rejected with negative acknowledge code: {}".format(
                        result.nack_code
                    )
                )
            elif type(result) == DiagnosticMessagePositiveAcknowledgement:
                return
            elif result:
                logger.warning(
                    "Received unexpected DoIP message type {}. Ignoring".format(
                        type(result)
                    )
                )

    def receive_diagnostic(self, timeout=None):
        """Receive a raw diagnostic payload (ie: UDS) from the ECU.

        :return: Raw UDS payload
        :rtype: bytearray
        :raises TimeoutError: No diagnostic response received in time
        """
        start_time = time.time()
        while True:
            if timeout and (time.time() - start_time) > timeout:
                raise TimeoutError("Timed out waiting for diagnostic response")
            if timeout:
                result = self.read_doip(timeout=timeout)
            else:
                result = self.read_doip()
            if type(result) == DiagnosticMessage:
                return result.user_data
            elif result:
                logger.warning(
                    "Received unexpected DoIP message type {}. Ignoring".format(
                        type(result)
                    )
                )

    def _connect(self):
        """Helper to establish socket communication"""
        self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self._tcp_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        if self._client_ip_address is not None:
            self._tcp_sock.bind((self._client_ip_address, 0))
        self._tcp_sock.connect((self._ecu_ip_address, self._tcp_port))
        self._tcp_sock.settimeout(A_PROCESSING_TIME)

        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_sock.settimeout(A_PROCESSING_TIME)
        if self._client_ip_address is not None:
            self._udp_sock.bind((self._client_ip_address, 0))

        if self._use_secure:
            self._tcp_sock = ssl.wrap_socket(self._tcp_sock)

    def close(self):
        """Close the DoIP client"""
        self._tcp_sock.close()
        self._udp_sock.close()

    def reconnect(self, close_delay=A_PROCESSING_TIME):
        """Attempts to re-establish the connection. Useful after an ECU reset
        :param close_delay: Time to wait between closing and re-opening socket
        :type close_delay: float, optional
        """
        # Close the sockets
        self.close()
        # Reset the parser state machines
        self._udp_parser = Parser()
        self._tcp_parser = Parser()
        # Allow the ECU time time to cleanup the DoIP session/socket before re-establishing
        time.sleep(close_delay)
        self._connect()
        if self._activation_type is not None:
            result = self.request_activation(self._activation_type)
            if result.response_code != RoutingActivationResponse.ResponseCode.Success:
                raise ConnectionRefusedError(
                    f"Activation Request failed with code {result.response_code}"
                )