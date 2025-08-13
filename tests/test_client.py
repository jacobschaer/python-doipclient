import socket
import ssl
import pytest
import logging
from doipclient import DoIPClient
from doipclient.client import Parser
from doipclient.messages import *

try:
    from socket import IPPROTO_IPV6
except ImportError:
    IPPROTO_IPV6 = 41

test_logical_address = 1
test_ip = "127.0.0.1"

activation_request = bytearray(
    [int(x, 16) for x in "02 fd 00 05 00 00 00 07 0e 00 00 00 00 00 00".split(" ")]
)
activation_request_with_vm = bytearray(
    [
        int(x, 16)
        for x in "02 fd 00 05 00 00 00 0b 0e 00 00 00 00 00 00 01 02 03 04".split(" ")
    ]
)
successful_activation_response = bytearray(
    [
        int(x, 16)
        for x in "02 fd 00 06 00 00 00 09 0e 00 00 37 10 00 00 00 00".split(" ")
    ]
)
unsuccessful_activation_response = bytearray(
    [
        int(x, 16)
        for x in "02 fd 00 06 00 00 00 09 0e 00 00 37 00 00 00 00 00".split(" ")
    ]
)
successful_activation_response_with_vm = bytearray(
    [
        int(x, 16)
        for x in "02 fd 00 06 00 00 00 0d 0e 00 00 37 10 00 00 00 00 04 03 02 01".split(
            " "
        )
    ]
)
nack_response = bytearray([int(x, 16) for x in "02 fd 00 00 00 00 00 01 04".split(" ")])
alive_check_request = bytearray(
    [int(x, 16) for x in "02 fd 00 07 00 00 00 00".split(" ")]
)
alive_check_response = bytearray(
    [int(x, 16) for x in "02 fd 00 08 00 00 00 02 0e 00".split(" ")]
)
diagnostic_negative_response = bytearray(
    [int(x, 16) for x in "02 fd 80 03 00 00 00 05 00 00 00 00 05".split(" ")]
)
diagnostic_positive_response = bytearray(
    [int(x, 16) for x in "02 fd 80 02 00 00 00 05 00 00 00 00 00".split(" ")]
)
diagnostic_result = bytearray(
    [int(x, 16) for x in "02 fd 80 01 00 00 00 08 00 e0 00 55 00 01 02 03".split(" ")]
)
entity_status_response = bytearray(
    [int(x, 16) for x in "02 fd 40 02 00 00 00 03 01 10 1".split(" ")]
)
entity_status_response_with_mds = bytearray(
    [int(x, 16) for x in "02 fd 40 02 00 00 00 07 01 10 01 00 00 10 00".split(" ")]
)
entity_status_request = bytearray(
    [int(x, 16) for x in "02 fd 40 01 00 00 00 00".split(" ")]
)
vehicle_identification_request = bytearray(
    [int(x, 16) for x in "02 fd 00 01 00 00 00 00".split(" ")]
)
vehicle_identification_request_with_ein = bytearray(
    [int(x, 16) for x in "02 fd 00 02 00 00 00 06 31 31 31 31 31 31".split(" ")]
)
vehicle_identification_request_with_vin = bytearray(
    [
        int(x, 16)
        for x in "02 fd 00 03 00 00 00 11 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31".split(
            " "
        )
    ]
)
vehicle_identification_response = bytearray(
    [
        int(x, 16)
        for x in "02 fd 00 04 00 00 00 21 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31 12 34 31 31 31 31 31 31 32 32 32 32 32 32 00 00".split(
            " "
        )
    ]
)
diagnostic_power_mode_request = bytearray(
    [int(x, 16) for x in "02 fd 40 03 00 00 00 00".split(" ")]
)
diagnostic_power_mode_response = bytearray(
    [int(x, 16) for x in "02 fd 40 04 00 00 00 01 01".split(" ")]
)
diagnostic_request = bytearray(
    [int(x, 16) for x in "02 fd 80 01 00 00 00 07 0e 00 00 01 00 01 02".split(" ")]
)
diagnostic_request_to_address = bytearray(
    [int(x, 16) for x in "02 fd 80 01 00 00 00 07 0e 00 12 34 00 01 02".split(" ")]
)
unknown_mercedes_message = bytearray(
    [
        int(x, 16)
        for x in "02 fd f0 10 00 00 00 38 00 00 06 00 0c 0c 00 00 00 00 00 00 56 39 34 58 44 30 30 30 31 35 00 00 44 6f 49 50 2d 56 43 49 2d 34 44 35 36 00 00 00 31 32 33 34 35 36 37 38 00 00 00 00 00 00 00 00".split(
            " "
        )
    ]
)

logger = logging.getLogger("doipclient")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)


class MockSocket:
    def __init__(self):
        self.rx_queue = [successful_activation_response]
        self.tx_queue = []
        self._bound_ip = None
        self._bound_port = None
        self.timeout = None
        self.opts = {}

    def construct(self, network, type):
        self._network = network
        self._type = type

    def connect(self, address):
        self._ip, self._port = address

    def setsockopt(self, socket_type, opt_type, opt_value):
        self.opts[socket_type] = self.opts.get(socket_type, {})
        self.opts[socket_type][opt_type] = opt_value

    def settimeout(self, timeout):
        self.timeout = timeout

    def gettimeout(self):
        return self.timeout

    def bind(self, address):
        self._bound_ip, self._bound_port = address

    def recv(self, bufflen):
        try:
            result = self.rx_queue.pop(0)
            if type(result) == bytearray:
                return result
            else:
                raise (result)
        except IndexError:
            raise socket.timeout()

    def recvfrom(self, bufflen):
        try:
            result = self.rx_queue.pop(0)
            if type(result) == bytearray:
                return result, None
            else:
                raise (result)
        except IndexError:
            raise socket.timeout()

    def send(self, buffer):
        self.tx_queue.append(buffer)
        return len(buffer)

    def sendto(self, data_bytes, destination):
        self.tx_queue.append(data_bytes)
        return len(data_bytes)

    def close(self):
        pass


@pytest.fixture
def mock_socket(monkeypatch):
    a = MockSocket()

    def mock_construct(*args, **kwargs):
        a.construct(*args, **kwargs)
        return a

    monkeypatch.setattr(socket, "socket", mock_construct)
    yield a


parameterized_class_fields = [
    (
        VehicleIdentificationResponse,
        [
            ("vin", "1" * 17),
            ("logical_address", 1234),
            ("eid", b"1" * 6),
            ("gid", b"1" * 6),
            ("further_action_required", 0x10),
        ],
    ),
    (
        VehicleIdentificationResponse,
        [
            ("vin", "1" * 17),
            ("logical_address", 1234),
            ("eid", b"1" * 6),
            ("gid", b"1" * 6),
            ("further_action_required", 0x10),
            ("vin_sync_status", None),
        ],
    ),
    (
        VehicleIdentificationResponse,
        [
            ("vin", "1" * 17),
            ("logical_address", 1234),
            ("eid", b"2" * 6),
            ("gid", b"2" * 6),
            ("further_action_required", 0x00),
            ("vin_sync_status", 0x10),
        ],
    ),
    (
        EntityStatusResponse,
        [
            ("node_type", 0x01),
            ("max_concurrent_sockets", 13),
            ("currently_open_sockets", 5),
        ],
    ),
    (
        EntityStatusResponse,
        [
            ("node_type", 0x00),
            ("max_concurrent_sockets", 1),
            ("currently_open_sockets", 28),
            ("max_data_size", 0xFFF),
        ],
    ),
    (GenericDoIPNegativeAcknowledge, [("nack_code", 1)]),
    (VehicleIdentificationRequest, []),
    (VehicleIdentificationRequestWithEID, [("eid", b"2" * 6)]),
    (VehicleIdentificationRequestWithVIN, [("vin", "1" * 17)]),
    (
        RoutingActivationRequest,
        [
            ("source_address", 0x00E0),
            ("activation_type", 1),
        ],
    ),
    (
        RoutingActivationRequest,
        [
            ("source_address", 0x00E0),
            ("activation_type", 1),
            ("reserved", 0),
            ("vm_specific", 0x1234),
        ],
    ),
    (
        RoutingActivationResponse,
        [
            ("client_logical_address", 0x00E0),
            ("logical_address", 1),
            ("response_code", 0),
        ],
    ),
    (
        RoutingActivationResponse,
        [
            ("client_logical_address", 0x00E0),
            ("logical_address", 1),
            ("response_code", 0),
            ("reserved", 0),
            ("vm_specific", 0x1234),
        ],
    ),
    (AliveCheckRequest, []),
    (AliveCheckResponse, [("source_address", 0x00E0)]),
    (DoipEntityStatusRequest, []),
    (DiagnosticPowerModeRequest, []),
    (DiagnosticPowerModeResponse, [("diagnostic_power_mode", 0x01)]),
    (
        DiagnosticMessage,
        [
            ("source_address", 0x00E0),
            ("target_address", 0x00E0),
            ("user_data", bytearray([0, 1, 2, 3])),
        ],
    ),
    (
        DiagnosticMessagePositiveAcknowledgement,
        [
            ("source_address", 0x00E0),
            ("target_address", 0x00E0),
            ("ack_code", 0),
        ],
    ),
    (
        DiagnosticMessagePositiveAcknowledgement,
        [
            ("source_address", 0x00E0),
            ("target_address", 0x00E0),
            ("ack_code", 0),
            ("previous_message_data", bytearray([1, 2, 3])),
        ],
    ),
    (
        DiagnosticMessageNegativeAcknowledgement,
        [
            ("source_address", 0x00E0),
            ("target_address", 0x00E0),
            ("nack_code", 2),
        ],
    ),
    (
        DiagnosticMessageNegativeAcknowledgement,
        [
            ("source_address", 0x00E0),
            ("target_address", 0x00E0),
            ("nack_code", 2),
            ("previous_message_data", bytearray([1, 2, 3])),
        ],
    ),
]


@pytest.mark.parametrize("message, fields", parameterized_class_fields)
def test_packer_unpackers(mock_socket, message, fields):
    values = [x for _, x in fields]
    a = message(*values)
    packed = a.pack()
    b = message.unpack(packed, len(packed))
    for field_name, field_value in fields:
        assert getattr(b, field_name) == field_value


@pytest.mark.parametrize("message, fields", parameterized_class_fields)
def test_repr(mock_socket, message, fields):
    values = [x for _, x in fields]
    a = message(*values)
    print(repr(a))
    print(str(a))
    assert eval(repr(a)) == a


def test_does_not_activate_with_none(mock_socket, mocker):
    spy = mocker.spy(DoIPClient, "request_activation")
    mock_socket.rx_queue = []
    sut = DoIPClient(test_ip, test_logical_address, activation_type=None)
    assert spy.call_count == 0


def test_resend_reactivate_closed_socket(mock_socket, mocker):
    request_activation_spy = mocker.spy(DoIPClient, "request_activation")
    reconnect_spy = mocker.spy(DoIPClient, "reconnect")
    sut = DoIPClient(test_ip, test_logical_address, auto_reconnect_tcp=True)
    mock_socket.rx_queue.append(bytearray())
    mock_socket.rx_queue.append(successful_activation_response)
    mock_socket.rx_queue.append(diagnostic_positive_response)
    assert None == sut.send_diagnostic(bytearray([0, 1, 2]))
    assert request_activation_spy.call_count == 2
    assert reconnect_spy.call_count == 1
    assert mock_socket.timeout == 2


def test_resend_reactivate_broken_socket(mock_socket, mocker):
    request_activation_spy = mocker.spy(DoIPClient, "request_activation")
    reconnect_spy = mocker.spy(DoIPClient, "reconnect")
    sut = DoIPClient(test_ip, test_logical_address, auto_reconnect_tcp=True)
    mock_socket.rx_queue.append(ConnectionResetError(""))
    mock_socket.rx_queue.append(successful_activation_response)
    mock_socket.rx_queue.append(diagnostic_positive_response)
    assert None == sut.send_diagnostic(bytearray([0, 1, 2]))
    assert request_activation_spy.call_count == 2
    assert reconnect_spy.call_count == 1


def test_no_resend_reactivate_broken_socket(mock_socket, mocker):
    request_activation_spy = mocker.spy(DoIPClient, "request_activation")
    reconnect_spy = mocker.spy(DoIPClient, "reconnect")
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(ConnectionResetError(""))
    mock_socket.rx_queue.append(successful_activation_response)
    mock_socket.rx_queue.append(diagnostic_positive_response)
    with pytest.raises(ConnectionResetError):
        sut.send_diagnostic(bytearray([0, 1, 2]))
    assert request_activation_spy.call_count == 1
    assert reconnect_spy.call_count == 0


def test_connect_with_bind(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address, client_ip_address="192.168.1.1")
    assert mock_socket._bound_ip == "192.168.1.1"
    assert mock_socket._bound_port == 0


def test_context_manager(mock_socket, mocker):
    close_spy = mocker.spy(DoIPClient, "close")
    mock_socket.rx_queue.append(diagnostic_positive_response)

    with DoIPClient(test_ip, test_logical_address) as sut:
        assert None == sut.send_diagnostic(bytearray([0, 1, 2]))
    assert close_spy.call_count == 1


def test_send_good_activation_request(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(successful_activation_response)
    result = sut.request_activation(0)
    assert mock_socket._bound_ip == None
    assert mock_socket._bound_port == None
    assert mock_socket.tx_queue[-1] == activation_request
    assert result.client_logical_address == 0x0E00
    assert result.logical_address == 55
    assert result.response_code == 16
    assert result.vm_specific is None


def test_send_good_activation_request_with_vm(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(successful_activation_response_with_vm)
    result = sut.request_activation(0, 0x01020304)
    assert mock_socket.tx_queue[-1] == activation_request_with_vm
    assert result.client_logical_address == 0x0E00
    assert result.logical_address == 55
    assert result.response_code == 16
    assert result.vm_specific == 0x04030201


def test_activation_with_nack(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(nack_response)
    with pytest.raises(IOError, match=r"DoIP Negative Acknowledge. NACK Code: "):
        result = sut.request_activation(0)


def test_activation_with_alive_check(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(alive_check_request)
    mock_socket.rx_queue.append(successful_activation_response)
    result = sut.request_activation(0)
    assert result.client_logical_address == 0x0E00
    assert mock_socket.tx_queue[-1] == alive_check_response


def test_request_alive_check(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(alive_check_response)
    result = sut.request_alive_check()
    assert result.source_address == 0x0E00
    assert mock_socket.tx_queue[-1] == alive_check_request


def test_alive_check(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(alive_check_request)
    with pytest.raises(TimeoutError):
        sut.read_doip()
    assert len(mock_socket.tx_queue) == 2
    assert mock_socket.tx_queue[-1] == alive_check_response


def test_request_entity_status_with_mds(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(entity_status_response_with_mds)
    result = sut.request_entity_status()
    assert mock_socket.tx_queue[-1] == entity_status_request
    assert result.node_type == 1
    assert result.max_concurrent_sockets == 16
    assert result.currently_open_sockets == 1
    assert result.max_data_size == 4096


def test_request_entity_status(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(entity_status_response)
    result = sut.request_entity_status()
    assert mock_socket.tx_queue[-1] == entity_status_request
    assert result.node_type == 1
    assert result.max_concurrent_sockets == 16
    assert result.currently_open_sockets == 1


def test_send_diagnostic_postive(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(diagnostic_positive_response)
    assert None == sut.send_diagnostic(bytearray([0, 1, 2]))
    assert mock_socket.tx_queue[-1] == diagnostic_request


def test_send_diagnostic_negative(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(diagnostic_negative_response)
    with pytest.raises(
        IOError, match=r"Diagnostic request rejected with negative acknowledge code"
    ):
        result = sut.send_diagnostic(bytearray([0, 1, 2]))
    assert mock_socket.tx_queue[-1] == diagnostic_request


def test_send_diagnostic_to_address_positive(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(diagnostic_positive_response)
    assert None == sut.send_diagnostic_to_address(0x1234, bytearray([0, 1, 2]))
    assert mock_socket.tx_queue[-1] == diagnostic_request_to_address


def test_send_diagnostic_to_address_negative(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(diagnostic_negative_response)
    with pytest.raises(
        IOError, match=r"Diagnostic request rejected with negative acknowledge code"
    ):
        result = sut.send_diagnostic_to_address(0x1234, bytearray([0, 1, 2]))
    assert mock_socket.tx_queue[-1] == diagnostic_request_to_address


def test_receive_diagnostic(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(diagnostic_result)
    result = sut.receive_diagnostic()
    assert result == bytearray([0, 1, 2, 3])


def test_request_vehicle_identification(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(vehicle_identification_response)
    result = sut.request_vehicle_identification()
    assert mock_socket.tx_queue[-1] == vehicle_identification_request
    assert result.vin == "1" * 17
    assert result.logical_address == 0x1234
    assert result.eid == b"1" * 6
    assert result.gid == b"2" * 6
    assert result.further_action_required == 0x00
    assert result.vin_sync_status == 0x00


def test_request_vehicle_identification_with_ein(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(vehicle_identification_response)
    result = sut.request_vehicle_identification(eid=b"1" * 6)
    assert mock_socket.tx_queue[-1] == vehicle_identification_request_with_ein
    assert result.vin == "1" * 17
    assert result.logical_address == 0x1234


def test_request_vehicle_identification_with_vin(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(vehicle_identification_response)
    result = sut.request_vehicle_identification(vin="1" * 17)
    assert mock_socket.tx_queue[-1] == vehicle_identification_request_with_vin
    assert result.vin == "1" * 17
    assert result.logical_address == 0x1234
    assert result.eid == b"1" * 6
    assert result.gid == b"2" * 6
    assert result.further_action_required == 0x00
    assert result.vin_sync_status == 0x00


def test_get_entity(mock_socket):
    mock_socket.rx_queue.append(vehicle_identification_response)
    _, result = DoIPClient.get_entity()
    assert mock_socket.tx_queue[-1] == vehicle_identification_request
    assert result.vin == "1" * 17
    assert result.logical_address == 0x1234
    assert result.eid == b"1" * 6
    assert result.gid == b"2" * 6
    assert result.further_action_required == 0x00
    assert result.vin_sync_status == 0x00


def test_get_entity_with_ein(mock_socket):
    mock_socket.rx_queue.append(vehicle_identification_response)
    _, result = DoIPClient.get_entity(eid=b"1" * 6)
    assert mock_socket.tx_queue[-1] == vehicle_identification_request_with_ein
    assert result.vin == "1" * 17
    assert result.logical_address == 0x1234
    assert result.eid == b"1" * 6
    assert result.gid == b"2" * 6
    assert result.further_action_required == 0x00
    assert result.vin_sync_status == 0x00


def test_get_entity_with_vin(mock_socket):
    mock_socket.rx_queue.append(vehicle_identification_response)
    _, result = DoIPClient.get_entity(vin="1" * 17)
    assert mock_socket.tx_queue[-1] == vehicle_identification_request_with_vin
    assert result.vin == "1" * 17
    assert result.logical_address == 0x1234
    assert result.eid == b"1" * 6
    assert result.gid == b"2" * 6
    assert result.further_action_required == 0x00
    assert result.vin_sync_status == 0x00


def test_request_diagnostic_power_mode(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(diagnostic_power_mode_response)
    result = sut.request_diagnostic_power_mode()
    assert mock_socket.tx_queue[-1] == diagnostic_power_mode_request
    assert result.diagnostic_power_mode == 0x01


def test_failed_activation_constructor(mock_socket):
    # Swap out the default good response with a bad one
    mock_socket.rx_queue[-1] = unsuccessful_activation_response
    with pytest.raises(
        ConnectionRefusedError, match=r"Activation Request failed with code"
    ):
        sut = DoIPClient(test_ip, test_logical_address)


def test_read_generic(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(unknown_mercedes_message)
    result = sut.read_doip()
    assert type(result) == ReservedMessage
    assert result.payload_type == 0xF010
    assert result.payload == unknown_mercedes_message[8:]


def test_send_generic(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    result = sut.send_doip(0xF010, unknown_mercedes_message[8:])
    assert mock_socket.tx_queue[-1] == unknown_mercedes_message


def test_message_ids():
    for payload_type, message in payload_type_to_message.items():
        assert payload_type == message.payload_type


def test_invalid_ip():
    with pytest.raises(
        ValueError, match=r"does not appear to be an IPv4 or IPv6 address"
    ):
        sut = DoIPClient(test_ip + "a", test_logical_address)


def test_ipv4(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    assert mock_socket._network == socket.AF_INET
    assert mock_socket.opts == {
        socket.SOL_SOCKET: {socket.SO_REUSEADDR: True},
        socket.IPPROTO_TCP: {socket.TCP_NODELAY: True},
    }


def test_ipv6(mock_socket):
    sut = DoIPClient("2001:db8::", test_logical_address)
    assert mock_socket._network == socket.AF_INET6
    assert mock_socket.opts == {
        socket.SOL_SOCKET: {socket.SO_REUSEADDR: True},
        socket.IPPROTO_TCP: {socket.TCP_NODELAY: True},
    }


def test_await_ipv6(mock_socket):
    mock_socket.rx_queue.clear()
    try:
        DoIPClient.await_vehicle_announcement(
            udp_port=13400, timeout=0.1, ipv6=True, source_interface=None
        )
    except TimeoutError:
        pass
    assert mock_socket._network == socket.AF_INET6
    assert mock_socket._bound_ip == "ff02::1"
    assert mock_socket._bound_port == 13400
    assert mock_socket.opts == {
        socket.SOL_SOCKET: {socket.SO_REUSEADDR: True},
        IPPROTO_IPV6: {
            socket.IPV6_JOIN_GROUP: b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
        },
    }


def test_await_ipv4(mock_socket):
    mock_socket.rx_queue.clear()
    try:
        DoIPClient.await_vehicle_announcement(
            udp_port=13400, timeout=0.1, ipv6=False, source_interface=None
        )
    except TimeoutError:
        pass
    assert mock_socket._network == socket.AF_INET
    assert mock_socket._bound_ip == ""
    assert mock_socket._bound_port == 13400
    assert mock_socket.opts == {
        socket.SOL_SOCKET: {socket.SO_REUSEADDR: True, socket.SO_BROADCAST: True},
    }


def test_exception_from_blocking_ssl_socket(mock_socket, mocker):
    """SSL sockets behave slightly different than regular sockets in
    non-blocking mode. They won't raise BlockingIOError but SSLWantWriteError
    or SSLWantReadError instead.

    See: https://docs.python.org/3/library/ssl.html#notes-on-non-blocking-sockets
    """
    sut = DoIPClient(test_ip, test_logical_address)

    try:
        sut._tcp_sock.recv = mocker.Mock(side_effect=ssl.SSLWantReadError)
        sut._tcp_socket_check()
        sut._tcp_sock.recv = mocker.Mock(side_effect=ssl.SSLWantWriteError)
        sut._tcp_socket_check()
    except (ssl.SSLWantReadError, ssl.SSLWantWriteError) as exc:
        pytest.fail(f"Should not raise exception: {exc.__class__.__name__}")


def test_use_secure_uses_default_ssl_context(mock_socket, mocker):
    """Wrap socket with default SSL-context when use_secure=True"""
    mocked_default_context = mocker.patch.object(
        ssl, "create_default_context", autospec=True
    )
    sut = DoIPClient(
        test_ip, test_logical_address, use_secure=True, activation_type=None
    )
    mocked_default_wrap_socket = mocked_default_context.return_value.wrap_socket
    mocked_default_wrap_socket.assert_called_once_with(mock_socket)


def test_use_secure_with_external_ssl_context(mock_socket, mocker):
    """Wrap socket with user provided SSL-context when use_secure=ssl_context"""
    original_context = ssl.SSLContext
    mocked_external_context = mocker.patch.object(ssl, "SSLContext", autospec=True)
    mocked_default_context = mocker.patch.object(
        ssl, "create_default_context", autospec=True
    )

    # Unmock the SSLContext
    ssl.SSLContext = original_context

    sut = DoIPClient(
        test_ip,
        test_logical_address,
        use_secure=mocked_external_context,
        activation_type=None,
    )

    mocked_default_wrap_socket = mocked_default_context.return_value.wrap_socket
    assert (
        not mocked_default_wrap_socket.called
    ), "Socket should *not* get wrapped using default context."

    mocked_external_wrap_socket = mocked_external_context.wrap_socket
    mocked_external_wrap_socket.assert_called_once_with(mock_socket)


@pytest.mark.parametrize(
    "vm_specific, exc",
    (
        (None, False),
        (0, False),
        (-1, True),
        (0xFFFFFFFF, False),
        (0x100000000, True),
        ("0x1", True),
        (10.0, True),
    ),
)
def test_vm_specific_setter(mock_socket, mocker, vm_specific, exc):
    sut = DoIPClient(test_ip, test_logical_address, auto_reconnect_tcp=True)
    if exc:
        with pytest.raises(ValueError):
            sut.vm_specific = vm_specific
    else:
        sut.vm_specific = vm_specific
        assert sut.vm_specific == vm_specific


def test_vm_specific_static_value(mock_socket, mocker):
    request_activation_spy = mocker.spy(DoIPClient, "request_activation")
    mock_socket.rx_queue.append(successful_activation_response_with_vm)

    sut = DoIPClient(
        test_ip,
        test_logical_address,
        auto_reconnect_tcp=True,
        activation_type=None,
        vm_specific=0x01020304,
    )
    sut.request_activation(
        activation_type=RoutingActivationRequest.ActivationType.Default
    )
    assert mock_socket.tx_queue[-1] == activation_request_with_vm
    assert request_activation_spy.call_count == 1


def test_vm_specific_request_activation_bad_value(mock_socket, mocker):
    request_activation_spy = mocker.spy(DoIPClient, "request_activation")
    mock_socket.rx_queue.append(successful_activation_response_with_vm)

    sut = DoIPClient(
        test_ip,
        test_logical_address,
        auto_reconnect_tcp=True,
        activation_type=None,
        vm_specific=0x01020304,
    )
    with pytest.raises(ValueError):
        sut.request_activation(
            activation_type=RoutingActivationRequest.ActivationType.Default,
            vm_specific=-1,
        )


def test_vm_specific_verification_in_init(mock_socket, mocker):
    request_activation_spy = mocker.spy(DoIPClient, "request_activation")
    mock_socket.rx_queue.append(successful_activation_response_with_vm)
    with pytest.raises(ValueError):
        sut = DoIPClient(
            test_ip,
            test_logical_address,
            auto_reconnect_tcp=True,
            activation_type=None,
            vm_specific=-1,
        )
