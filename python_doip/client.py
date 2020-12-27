import socket
import struct
import time
from enum import IntEnum
from .constants import TCP_DATA_UNSECURED, UDP_DISCOVERY, A_PROCESSING_TIME
from .messages import (payload_type_to_message, payload_message_to_type,
                       RoutingActivationRequest, RoutingActivationResponse, GenericDoIPNegativeAcknowledge,
                       VehicleIdentificationResponse, VehicleIdentificationRequest, VehicleIdentificationRequestWithEID,
                       VehicleIdentificationRequestWithVIN, AliveCheckRequest, AliveCheckResponse, DiagnosticPowerModeRequest,
                       DiagnosticPowerModeResponse, DoipEntityStatusRequest, EntityStatusResponse)

class Parser:
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
                self.protocol_version = int(self.rx_buffer.pop(0))
                self._state = Parser.ParserState.READ_INVERSE_PROTOCOL_VERSION
            if self._state == Parser.ParserState.READ_INVERSE_PROTOCOL_VERSION:
                inverse_protocol_version = int(self.rx_buffer.pop(0))
                if inverse_protocol_version != (0xff ^ self.protocol_version):
                    # Bad protocol version inverse - shift the buffer forward
                    self.protocol_version = inverse_protocol_version
                else:
                    self._state = Parser.ParserState.READ_PAYLOAD_TYPE
            if self._state == Parser.ParserState.READ_PAYLOAD_TYPE:
                if len(self.rx_buffer) >= 2:
                    self.payload_type = self.rx_buffer.pop(0) << 8
                    self.payload_type |= self.rx_buffer.pop(0)
                    self._state = Parser.ParserState.READ_PAYLOAD_SIZE
                else:
                    break
            if self._state == Parser.ParserState.READ_PAYLOAD_SIZE:
                if len(self.rx_buffer) >= 4:
                    self.payload_size  = self.rx_buffer.pop(0) << 24
                    self.payload_size |= self.rx_buffer.pop(0) << 16
                    self.payload_size |= self.rx_buffer.pop(0) << 8
                    self.payload_size |= self.rx_buffer.pop(0)
                    self._state = Parser.ParserState.READ_PAYLOAD
                else:
                    break
            if self._state == Parser.ParserState.READ_PAYLOAD:
                remaining_bytes = self.payload_size - len(self.payload)
                self.payload += self.rx_buffer[:remaining_bytes]
                self.rx_buffer = self.rx_buffer[remaining_bytes:]
                if len(self.payload) == self.payload_size:
                    self._state == Parser.ParserState.READ_PROTOCOL_VERSION
                    return payload_type_to_message[self.payload_type].unpack(self.payload, self.payload_size)


class DoIPClient:
    @classmethod
    def unpack_from_header(cls, payload):
        protocol_version, inverse_protocol_version, payload_type, payload_length = struct.unpack('!BBHL', payload)
        
    @classmethod
    def await_vehicle_announcement(cls, udp_port=UDP_DISCOVERY, timeout=None):
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if timeout is not None:
            sock.settimeout(timeout)
        sock.bind(('', udp_port))
        parser = Parser()

        while True:
            remaining = None
            if timeout:
                duration = time.time() - start_time
                if duration >= timeout:
                    raise TimeoutError()
                else:
                    remaining = timeout - duration
                    sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout as ex:
                raise TimeoutError(ex)
            result = parser.read_message(data)
            if result:
                return result

    def read_doip(self):
        start_time = time.time()
        data = bytearray()
        while (time.time() - start_time) < A_PROCESSING_TIME:
            response = self._parser.read_message(data)
            if type(response) == GenericDoIPNegativeAcknowledge:
                raise IOError(f"DoIP Negative Acknowledge. NACK Code: {response.nack_code}")
            elif type(response) == AliveCheckRequest:
                self.send_doip(AliveCheckResponse(self._client_logical_address))
            elif response:
                return response
            else:
                try:
                    data = self._sock.recv(1024)
                except socket.timeout as ex:
                    pass
        raise TimeoutError("ECU failed to respond in time")

    def send_doip(self, payload_type, payload_data):
        data_bytes = struct.pack('!BBHL', self._protocol_version, 0xff ^ self._protocol_version,
                                 payload_type, len(payload_data))
        data_bytes += payload_data
        self._sock.send(data_bytes)

    def send_doip_message(self, doip_message):
        payload_type = payload_message_to_type[type(doip_message)]
        payload_data = doip_message.pack()
        self.send_doip(payload_type, payload_data)

    def request_activation(self, source_address, activation_type):
        message = RoutingActivationRequest(source_address, activation_type)
        self.send_doip_message(message)
        while True:
            result = self.read_doip()
            if type(result) == RoutingActivationResponse:
                return result

    def request_vehicle_identification(self, eid=None, vin=None):
        if eid:
            message = VehicleIdentificationRequestWithEID(eid)
        elif vin:
            message = VehicleIdentificationRequestWithVIN(vin)
        else:
            message = VehicleIdentificationRequest()
        self.send_doip_message(message)
        while True:
            result = self.read_doip()
            if type(result) == VehicleIdentificationResponse:
                return result

    def request_alive_check(self):
        message = AliveCheckRequest()
        self.send_doip_message(message)
        while True:
            result = self.read_doip()
            if type(result) == AliveCheckResponse:
                return result

    def request_diagnostic_power_mode(self):
        message = DiagnosticPowerModeRequest()
        self.send_doip_message(message)
        while True:
            result = self.read_doip()
            if type(result) == DiagnosticPowerModeResponse:
                return result

    def request_entity_status(self):
        message = DoipEntityStatusRequest()
        self.send_doip_message(message)
        while True:
            result = self.read_doip()
            if type(result) == EntityStatusResponse:
                return result        

    def send_diagnostic(self, diagnostic_payload):
        message = DiagnosticMessage(self._client_logical_address, self._ecu_logical_address, diagnostic_payload)
        self.send_doip_message(message)
        while True:
            result = self.read_doip()
            if type(result) == DiagnosticMessageNegativeAcknowledgement:
                raise IOError(result.nack_code)
            elif type(result) == DiagnosticMessagePositiveAcknowledgement:
                return
    
    def receive_diagnostic(self):
        while True:
            result = self.read_doip()
            if type(result) == DiagnosticMessage:
                return result.user_data

    def _connect(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        self._sock.connect((self._ecu_ip_address, self._tcp_port))
        self._sock.settimeout(A_PROCESSING_TIME)
        if self._use_secure:
            self._sock = ssl.wrap_socket(self._sock)

    def close(self):
        self._sock.close()

    def __init__(self, ecu_logical_address, ecu_ip_address, tcp_port=TCP_DATA_UNSECURED,
                 activation_type=RoutingActivationRequest.ActivationType.Default, protocol_version=0x02,
                 client_logical_address=0x00, use_secure=False):
        self._ecu_logical_address = ecu_logical_address
        self._client_logical_address = client_logical_address
        self._use_secure = use_secure
        self._ecu_ip_address = ecu_ip_address
        self._tcp_port = tcp_port
        self._activation_type = activation_type
        self._parser = Parser()
        self._protocol_version = protocol_version
        self._connect()
        self.request_activation(self._client_logical_address, self._activation_type)