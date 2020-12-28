import socket
import pytest
import logging
from python_doip import DoIPClient
from python_doip.messages import *

test_logical_address = 1
test_ip = '127.0.0.1'

successful_activation_response = bytearray([int(x, 16) for x in '02 fd 00 06 00 00 00 09 0e 00 00 37 10 00 00 00 00'.split(' ')])
unsuccessful_activation_response = bytearray([int(x, 16) for x in '02 fd 00 06 00 00 00 09 0e 00 00 37 00 00 00 00 00'.split(' ')])
successful_activation_response_with_vm = bytearray([int(x, 16) for x in '02 fd 00 06 00 00 00 0d 0e 00 00 37 10 00 00 00 00 04 03 02 01'.split(' ')])
nack_response = bytearray([int(x, 16) for x in '02 fd 00 00 00 00 00 01 04'.split(' ')])
alive_check_request = bytearray([int(x, 16) for x in '02 fd 00 07 00 00 00 00'.split(' ')])
alive_check_response = bytearray([int(x, 16) for x in '02 fd 00 08 00 00 00 02 0e 00'.split(' ')])

logger = logging.getLogger('python_doip')
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
])

def test_packer_unpackers(mock_socket, message, fields):
    values = [x for _, x in fields]
    a = message(*values)
    packed = a.pack()
    b = message.unpack(packed, len(packed))
    for field_name, field_value in fields:
        assert getattr(b, field_name) == field_value

def test_send_good_activation_request(mock_socket):
    sut = DoIPClient(test_logical_address, test_ip)
    mock_socket.rx_queue.append(successful_activation_response)
    result = sut.request_activation(0)
    assert result.client_logical_address == 0x0e00
    assert result.logical_address == 55
    assert result.response_code == 16
    assert result.vm_specific is None

def test_send_good_activation_request_with_vm(mock_socket):
    sut = DoIPClient(test_logical_address, test_ip)
    mock_socket.rx_queue.append(successful_activation_response_with_vm)
    result = sut.request_activation(0)
    assert result.client_logical_address == 0x0e00
    assert result.logical_address == 55
    assert result.response_code == 16
    assert result.vm_specific == 0x04030201

def test_activation_with_nack(mock_socket):
    sut = DoIPClient(test_logical_address, test_ip)
    mock_socket.rx_queue.append(nack_response)
    with pytest.raises(IOError, match=r"DoIP Negative Acknowledge. NACK Code: "):
        result = sut.request_activation(0)

def test_activation_with_alive_check(mock_socket):
    sut = DoIPClient(test_logical_address, test_ip)
    mock_socket.rx_queue.append(alive_check_request)
    mock_socket.rx_queue.append(successful_activation_response)
    result = sut.request_activation(0)
    assert result.client_logical_address == 0x0e00
    assert mock_socket.tx_queue[-1] == alive_check_response

def test_request_alive_check(mock_socket):
    sut = DoIPClient(test_logical_address, test_ip)
    mock_socket.rx_queue.append(alive_check_response)
    result = sut.request_alive_check()
    assert result.source_address == 0x0e00

def test_request_entity_status(mock_socket):
    pass

def test_send_diagnostic_postive(mock_socket):
    pass

def test_send_diagnostic_negative(mock_socket):
    pass

def test_receive_diagnostic(mock_socket):
    pass

def test_request_vehicle_identification(mock_socket):
    pass

def test_request_vehicle_identification_with_ein(mock_socket):
    pass

def test_request_vehicle_identification_with_vin(mock_socket):
    pass

def test_request_diagnostic_power_mode(mock_socket):
    pass

def test_request_entity_status(mock_socket):
    pass

def test_failed_activation_constructor(mock_socket):
    # Swap out the default good response with a bad one
    mock_socket.rx_queue[-1] = unsuccessful_activation_response
    with pytest.raises(ConnectionRefusedError, match=r'Activation Request failed with code'):
        sut = DoIPClient(test_logical_address, test_ip)
