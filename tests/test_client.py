import socket
import pytest
import logging
from doipclient import DoIPClient
from doipclient.messages import *

test_logical_address = 1
test_ip = '127.0.0.1'

activation_request = bytearray([int(x, 16) for x in '02 fd 00 05 00 00 00 07 0e 00 00 00 00 00 00'.split(' ')])
activation_request_with_vm = bytearray([int(x, 16) for x in '02 fd 00 05 00 00 00 0b 0e 00 00 00 00 00 00 01 02 03 04'.split(' ')])
successful_activation_response = bytearray([int(x, 16) for x in '02 fd 00 06 00 00 00 09 0e 00 00 37 10 00 00 00 00'.split(' ')])
unsuccessful_activation_response = bytearray([int(x, 16) for x in '02 fd 00 06 00 00 00 09 0e 00 00 37 00 00 00 00 00'.split(' ')])
successful_activation_response_with_vm = bytearray([int(x, 16) for x in '02 fd 00 06 00 00 00 0d 0e 00 00 37 10 00 00 00 00 04 03 02 01'.split(' ')])
nack_response = bytearray([int(x, 16) for x in '02 fd 00 00 00 00 00 01 04'.split(' ')])
alive_check_request = bytearray([int(x, 16) for x in '02 fd 00 07 00 00 00 00'.split(' ')])
alive_check_response = bytearray([int(x, 16) for x in '02 fd 00 08 00 00 00 02 0e 00'.split(' ')])
diagnostic_negative_response = bytearray([int(x, 16) for x in '02 fd 80 03 00 00 00 05 00 00 00 00 05'.split(' ')])
diagnostic_positive_response = bytearray([int(x, 16) for x in '02 fd 80 02 00 00 00 05 00 00 00 00 00'.split(' ')])
diagnostic_result = bytearray([int(x, 16) for x in '02 fd 80 01 00 00 00 08 00 e0 00 55 00 01 02 03'.split(' ')])
entity_status_response = bytearray([int(x, 16) for x in '02 fd 40 02 00 00 00 03 01 10 1'.split(' ')])
entity_status_response_with_mds = bytearray([int(x, 16) for x in '02 fd 40 02 00 00 00 07 01 10 01 00 00 10 00'.split(' ')])
entity_status_request = bytearray([int(x, 16) for x in '02 fd 40 01 00 00 00 00'.split(' ')])
vehicle_identification_request = bytearray([int(x, 16) for x in '02 fd 00 01 00 00 00 00'.split(' ')])
vehicle_identification_request_with_ein = bytearray([int(x, 16) for x in '02 fd 00 02 00 00 00 06 31 31 31 31 31 31'.split(' ')])
vehicle_identification_request_with_vin = bytearray([int(x, 16) for x in '02 fd 00 03 00 00 00 11 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31'.split(' ')])
vehicle_identification_response = bytearray([int(x, 16) for x in '02 fd 00 04 00 00 00 21 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31 12 34 31 31 31 31 31 31 32 32 32 32 32 32 00 00'.split(' ')])
diagnostic_power_mode_request =  bytearray([int(x, 16) for x in '02 fd 40 03 00 00 00 00'.split(' ')])
diagnostic_power_mode_response = bytearray([int(x, 16) for x in '02 fd 40 04 00 00 00 01 01'.split(' ')])
diagnostic_request = bytearray([int(x, 16) for x in '02 fd 80 01 00 00 00 07 0e 00 00 01 00 01 02'.split(' ')])

logger = logging.getLogger('doipclient')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)

class MockSocket:
    def __init__(self):
        self.rx_queue = [successful_activation_response]
        self.tx_queue = []

    def construct(self, network, type):
        self._network = network
        self._type = type

    def connect(self, address):
        self._ip, self._port = address

    def setsockopt(self, socket_type, opt_type, opt_value):
        pass

    def settimeout(self, timeout):
        pass

    def recv(self, bufflen):
        try:
            return self.rx_queue.pop(0)
        except IndexError:
            raise socket.timeout()
        self.tx_queue

    def send(self, buffer):
        self.tx_queue.append(buffer)

@pytest.fixture
def mock_socket(monkeypatch):
    a = MockSocket()
    def mock_construct(*args, **kwargs):
        a.construct(*args, **kwargs)
        return a

    monkeypatch.setattr(socket, 'socket', mock_construct)
    yield a

@pytest.mark.parametrize("message, fields", [
    (VehicleIdentificationResponse, [
        ('vin', '1'* 17),
        ('logical_address', 1234),
        ('eid', b'1' * 6),
        ('gid', b'1' * 6),
        ('further_action_required', 0x10),
    ]),    
    (VehicleIdentificationResponse, [
        ('vin', '1'* 17),
        ('logical_address', 1234),
        ('eid', b'1' * 6),
        ('gid', b'1' * 6),
        ('further_action_required', 0x10),
        ('vin_sync_status', None)
    ]),
    (VehicleIdentificationResponse, [
        ('vin', '1'* 17),
        ('logical_address', 1234),
        ('eid', b'2' * 6),
        ('gid', b'2' * 6),
        ('further_action_required', 0x00),
        ('vin_sync_status', 0x10)
    ]),
    (EntityStatusResponse, [
        ('node_type' , 0x01),
        ('max_concurrent_sockets' , 13),
        ('currently_open_sockets' , 5),
    ]),
    (EntityStatusResponse, [
        ('node_type' , 0x00),
        ('max_concurrent_sockets' , 1),
        ('currently_open_sockets' , 28),
        ('max_data_size', 0xfff)
    ]),
    (GenericDoIPNegativeAcknowledge, [
        ('nack_code', 1)
    ]),
    (VehicleIdentificationRequest, []),
    (VehicleIdentificationRequestWithEID, [
        ('eid', b'2' * 6)
    ]),
    (VehicleIdentificationRequestWithVIN, [
        ('vin', '1' * 17)
    ]),
    (RoutingActivationRequest, [
        ('source_address', 0x00e0),
        ('activation_type', 1),
    ]),
    (RoutingActivationRequest, [
        ('source_address', 0x00e0),
        ('activation_type', 1),
        ('reserved', 0),
        ('vm_specific', 0x1234)
    ]),
    (RoutingActivationResponse, [
        ('client_logical_address', 0x00e0),
        ('logical_address', 1),
        ('response_code', 0),
    ]),
    (RoutingActivationResponse, [
        ('client_logical_address', 0x00e0),
        ('logical_address', 1),
        ('response_code', 0),
        ('reserved', 0),
        ('vm_specific', 0x1234)
    ]),
    (AliveCheckRequest, []),
    (AliveCheckResponse, [
        ('source_address', 0x00e0)
    ]),
    (DoipEntityStatusRequest, []),
    (DiagnosticPowerModeRequest, []),
    (DiagnosticPowerModeResponse, [
        ('diagnostic_power_mode', 0x01)
    ]),
    (DiagnosticMessage, [
        ('source_address', 0x00e0),
        ('target_address', 0x00e0),
        ('user_data', bytearray([0,1,2,3])),
    ]),
    (DiagnosticMessagePositiveAcknowledgement, [
        ('source_address', 0x00e0 ),
        ('target_address',  0x00e0),
        ('ack_code', 0),
    ]),
    (DiagnosticMessagePositiveAcknowledgement, [
        ('source_address', 0x00e0 ),
        ('target_address',  0x00e0),
        ('ack_code', 0),
        ('previous_message_data', bytearray([1,2,3]))
    ]),
    (DiagnosticMessageNegativeAcknowledgement, [
        ('source_address', 0x00e0 ),
        ('target_address',  0x00e0),
        ('nack_code', 2),
    ]),
    (DiagnosticMessageNegativeAcknowledgement, [
        ('source_address', 0x00e0 ),
        ('target_address',  0x00e0),
        ('nack_code', 2),
        ('previous_message_data', bytearray([1,2,3]))
    ]),
])

def test_packer_unpackers(mock_socket, message, fields):
    values = [x for _, x in fields]
    a = message(*values)
    packed = a.pack()
    b = message.unpack(packed, len(packed))
    for field_name, field_value in fields:
        assert getattr(b, field_name) == field_value

def test_send_good_activation_request(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(successful_activation_response)
    result = sut.request_activation(0)
    assert mock_socket.tx_queue[-1] == activation_request
    assert result.client_logical_address == 0x0e00
    assert result.logical_address == 55
    assert result.response_code == 16
    assert result.vm_specific is None

def test_send_good_activation_request_with_vm(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(successful_activation_response_with_vm)
    result = sut.request_activation(0, 0x01020304)
    assert mock_socket.tx_queue[-1] == activation_request_with_vm
    assert result.client_logical_address == 0x0e00
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
    assert result.client_logical_address == 0x0e00
    assert mock_socket.tx_queue[-1] == alive_check_response

def test_request_alive_check(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(alive_check_response)
    result = sut.request_alive_check()
    assert result.source_address == 0x0e00
    assert mock_socket.tx_queue[-1] == alive_check_request

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
    with pytest.raises(IOError, match=r'Diagnostic request rejected with negative acknowledge code'):
        result = sut.send_diagnostic(bytearray([0,1,2]))
    assert mock_socket.tx_queue[-1] == diagnostic_request

def test_receive_diagnostic(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(diagnostic_result)
    result = sut.receive_diagnostic()
    assert result == bytearray([0,1,2,3])

def test_request_vehicle_identification(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(vehicle_identification_response)
    result = sut.request_vehicle_identification()
    assert mock_socket.tx_queue[-1] == vehicle_identification_request
    assert result.vin == '1' * 17
    assert result.logical_address == 0x1234
    assert result.eid == b'1' * 6
    assert result.gid == b'2' * 6
    assert result.further_action_required == 0x00
    assert result.vin_sync_status == 0x00

def test_request_vehicle_identification_with_ein(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(vehicle_identification_response)
    result = sut.request_vehicle_identification(eid=b'1'*6)
    assert mock_socket.tx_queue[-1] == vehicle_identification_request_with_ein
    assert result.vin == '1' * 17
    assert result.logical_address == 0x1234
    assert result.eid == b'1' * 6
    assert result.gid == b'2' * 6
    assert result.further_action_required == 0x00
    assert result.vin_sync_status == 0x00

def test_request_vehicle_identification_with_vin(mock_socket):
    sut = DoIPClient(test_ip, test_logical_address)
    mock_socket.rx_queue.append(vehicle_identification_response)
    result = sut.request_vehicle_identification(vin='1'*17)
    assert mock_socket.tx_queue[-1] == vehicle_identification_request_with_vin
    assert result.vin == '1' * 17
    assert result.logical_address == 0x1234
    assert result.eid == b'1' * 6
    assert result.gid == b'2' * 6
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
    with pytest.raises(ConnectionRefusedError, match=r'Activation Request failed with code'):
        sut = DoIPClient(test_ip, test_logical_address)
