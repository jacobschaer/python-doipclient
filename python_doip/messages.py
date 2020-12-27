import struct
from enum import IntEnum

class GenericDoIPNegativeAcknowledge:
    class NackCodes(IntEnum):
        IncorrectPatternFormat = 0x00
        UnknownPayloadType = 0x01
        MessageTooLarge = 0x02
        OutOfMemory = 0x03
        InvalidPayloadLength = 0x04

    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        return GenericDoIPNegativeAcknowledge(*struct.unpack_from('!B'))

    def __init__(self, nack_code):
        self._nack_code = nack_code

    @property
    def nack_code(self):
        return self._nack_code


class AliveCheckRequest:
    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        return AliveCheckRequest()

    def pack(self):
        return bytearray()


class AliveCheckResponse:
    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        return AliveCheckResponse(*struct.unpack_from('!H'))

    def pack(self):
        return struct.pack('!H', self._source_address)

    def __init__(self, source_address):
        self._source_address = source_address

    @property
    def source_address(self):
        return self._source_address


class DoipEntityStatusRequest:
    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        return DoipEntityStatusRequest()

    def pack(self):
        return bytearray()


class DiagnosticPowerModeRequest:
    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        return DiagnosticPowerModeRequest()

    def pack(self):
        return bytearray()


class DiagnosticPowerModeResponse:
    class DiagnosticPowerMode(IntEnum):
        NotReady = 0x00
        Ready = 0x01
        NotSupported = 0x02

    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        return DiagnosticPowerModeRequest(*struct.unpack_from('!B'), payload_bytes)

    def __init__(self, diagnostic_power_mode):
        self._diagnostic_power_mode = diagnostic_power_mode

    @property
    def diagnostic_power_mode(self):
        return DiagnosticPowerModeResponse.DiagnosticPowerMode(self._diagnostic_power_mode)
    

class RoutingActivationRequest:
    """ Routing activation request. Table 47 of ISO 13400-2:2019(E) """

    class ActivationType(IntEnum):
        Default = 0x00
        DiagnosticRequiredByRegulation = 0x01
        CentralSecurity = 0xE1

    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        if payload_length == 7:
            return RoutingActivationResponse(*struct.unpack_from('!HBL'))
        else:
            return RoutingActivationResponse(*struct.unpack_from('!HBLL'))

    def pack(self):
        if self._vm_specific is not None:
            return struct.pack('!HBLL', self._source_address, self._activation_type, self._reserved, self._vm_specific)
        else:
            return struct.pack('!HBL', self._source_address, self._activation_type, self._reserved)

    def __init__(self, source_address, activation_type, reserved=0, vm_specific=None):
        self._source_address = source_address
        self._activation_type = activation_type
        self._reserved = reserved
        self._vm_specific = vm_specific

    @property
    def source_address(self):
        return self._source_address
    
    @property
    def activation_type(self):
        return self._activation_type
    
    @property
    def response_code(self):
        return self._response_code
    
    @property
    def vm_specific(self):
        return self._vm_specific


class VehicleIdentificationRequest:
    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        return VehicleIdentificationRequest()

    def pack(self):
        return bytearray()


class VehicleIdentificationRequestWithEID:
    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        return VehicleIdentificationRequestWithEID(*struct.unpack('!6s'))

    def pack(self):
        return struct.pack('!6ss', self._eid)

    def __init__(self, eid):
        self._eid = eid

    @property
    def eid(self):
        return self._eid


class VehicleIdentificationRequestWithVIN:
    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        return VehicleIdentificationRequestWithVIN(*struct.unpack('!17s'))

    def pack(self):
        return struct.pack('!17s', self._vin)

    def __init__(self, vin):
        self._vin = vin

    @property
    def vin(self):
        return self._vin


class RoutingActivationResponse:
    """ Payload type routing activation response. Table 48 of ISO 13400-2:2019(E) """
    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        if payload_length == 9:
            return RoutingActivationResponse(*struct.unpack_from('!HHBL', payload_bytes))
        else:
            return RoutingActivationResponse(*struct.unpack_from('!HHBLL', payload_bytes))

    def __init__(self, client_logical_address, logical_address, response_code, reserved=0, vm_specific=None):
        self._client_logical_address = client_logical_address
        self._logical_address = logical_address
        self._response_code = response_code
        self._reserved = reserved
        self._vm_specific = vm_specific

    @property
    def client_logical_address(self):
        """ Logical address of client DoIP entity

        Description: Logical address of the client DoIP entity that requested routing activation.
        Values: See Table 13.
        """
        return self._client_logical_address
    
    @property
    def logical_address(self):
        return self._logical_address
    
    @property
    def response_code(self):
        return self._response_code

    @property
    def vm_specific(self):
        return self._vm_specific


class DiagnosticMessage:
    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        return DiagnosticMessage(*struct.unpack_from('!HH'), payload_bytes[4:payload_length])

    def __init__(self, source_address, target_address, user_data):
        self._source_address = source_address
        self._target_address = target_address
        self._user_data = user_data

    @property
    def source_address(self):
        return self._source_address
    
    @property
    def target_address(self):
        return self._target_address
    
    @property
    def user_data(self):
        return self._user_data
    

class DiagnosticMessageNegativeAcknowledgement:
    class NackCodes:
        InvalidSourceAddress = 0x02
        UnknownTargetAddress = 0x03
        DiagnosticMessageTooLarge = 0x04
        OutOfMemory = 0x05
        TargetUnreachable = 0x06
        UnknownNetwork = 0x07
        TransportProtocolError = 0x08

    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        return DiagnosticMessageNegativeAcknowledgement(*struct.unpack_from('!HHB'), payload_bytes[5:payload_length])

    def __init__(self, source_address, target_address, nack_code, previous_message_data):
        self._source_address = source_address
        self._target_address = target_address
        self._nack_code = nack_code
        self._previous_message_data = previous_message_data

    @property
    def source_address(self):
        return self._source_address
    
    @property
    def target_address(self):
        return self._target_address
    
    @property
    def nack_code(self):
        return DiagnosticMessageNegativeAcknowledgement.NackCodes(self._nack_code)
    
    @property
    def previous_message_data(self):
        if self._previous_message_data:
            return self._previous_message_data
        else:
            return None


class DiagnosticMessagePositiveAcknowledgement:
    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        return DiagnosticMessagePositiveAcknowledgement(*struct.unpack_from('!HHB'), payload_bytes[5:payload_length])

    def __init__(self, source_address, target_address, nack_code, previous_message_data):
        self._source_address = source_address
        self._target_address = target_address
        self._nack_code = nack_code
        self._previous_message_data = previous_message_data

    @property
    def source_address(self):
        return self._source_address
    
    @property
    def target_address(self):
        return self._target_address
    
    @property
    def ack_code(self):
        return self._ack_code
    
    @property
    def previous_message_data(self):
        if self._previous_message_data:
            return self._previous_message_data
        else:
            return None


class EntityStatusResponse:
    """ DoIP entity status response. Table 11 of ISO 13400-2:2019(E) """

    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        if payload_length == 3:
            return EntityStatusResponse(struct.unpack_from('!BBB', payload_bytes))            
        else:
            return EntityStatusResponse(struct.unpack_from('!BBBL', payload_bytes))

    def __init__(self, node_type, max_concurrent_sockets, currently_open_sockets, max_data_size=None):
        self._node_type = node_type
        self._max_concurrent_sockets = max_concurrent_sockets
        self._currently_open_sockets = currently_open_sockets
        self._max_data_size = max_data_size

    @property
    def node_type():
        """ Node type(NT)

        Description:
        Identifies whether the contacted DoIP instance is either a DoIP node or a DoIP gateway.

        Values:
        0x00: DoIP gateway
        0x01: DoIP node
        0x02 .. 0xFF: reserved by this document
        """
        return self._node_type

    @property
    def max_concurrent_sockets(self):
        """ Max. concurrent TCP_DATA sockets (MCTS)
        
        Description:
        Represents the maximum number ofconcurrent TCP_DATA sockets allowedwith this DoIP entity,
        excluding thereserve socket required for sockethandling.

        Values:
        1 to 255
        """
        return self._max_concurrent_sockets
    
    @property
    def currently_open_sockets(self):
        """ Currently open TCP_DATA sockets (NCTS)

        Description: Number of currently established sockets.

        Values:
        0 to 255
        """
        return self._currently_open_sockets
    
    @property
    def max_data_size(self):
        """ Max. data size (MDS)

        Description: Maximum size of one logical request that this DoIP entity can process.

        Values:
        0 to 4GB
        """
        return self._max_data_size

class VehicleIdentificationResponse:
    """ Payload type vehicle announcement/identification response message Table 5 of ISO 13400-2:2019(E) """

    class SynchronizationStatusCodes(IntEnum):
        SYNCHRONIZED = 0x00
        INCOMPLETE = 0x10

    @classmethod
    def unpack(cls, payload_bytes, payload_length):
        if payload_length == 33:
            return VehicleIdentificationResponse(*struct.unpack_from('!17sH6s6sBB', payload_bytes))
        else:
            return VehicleIdentificationResponse(*struct.unpack_from('!17sH6s6sB', payload_bytes))


    def __init__(self, vin, logical_address, eid, gid, further_action_required, vin_gid_sync_staus=None):
        self._vin = vin
        self._logical_address = logical_address
        self._eid = eid
        self._gid = gid
        self._further_action_required = further_action_required
        self._vin_gid_sync_status = vin_gid_sync_staus

    @property
    def vin(self):
        """ VIN

        Description: This is the vehicle’s VIN as specified in ISO 3779. If the VIN is not configured at the time
        of transmission of this message, this should be indicated using the invalidity value specified in
        Table 1. In this case, the GID is used to associate DoIP nodes with a certain vehicle (see 6.3.1).

        Values: ASCII
        """
        return self._vin.decode('ascii')

    @property
    def logical_address(self):
        """ Logical Address

        Description: This is the logical address that is assigned to the responding DoIP entity (see 7. 8 for further
        details). The logical address can be used, forexample, to address diagnostic requestsdirectly to the DoIP
        entity.
        
        Values: See Table 13.
        """
        return self._logical_address
    
    @property
    def eid(self):
        """ EID

        Description: This is a unique identification of the DoIP entities in order to separate their responses 
        even before the VIN is programmed to orrecognized by the DoIP devices (e.g. duringthe vehicle assembly
        process). It is recommended that the MAC address information of the DoIP entity's network interface be
        used (one of the interfaces ifmultiple network interfaces are implemented).
        
        Values: If MAC addressis used, it shall be in accordance with IEEE EUI-48.
        """
        return self._eid

    @property
    def gid(self):
        """ GID

        Description: This is a unique identification of a group of DoIP entities within the same vehicle in the
        case that a VIN is not configured for that vehicle. The VIN/GID synchronization process between DoIP
        nodes of a vehicle is defined in 6.3.1. If the GID is not available at the time of transmission of this
        message, this shall beindicated using the specific invalidity valueas specified in Table 1.

        Value: See Table 1
        """
        return self._gid
    
    @property
    def further_action_required(self):
        """ Further action required

        Description: This is the additional information to notify the client DoIP entity that there are either
        DoIP entities with no initial connectivity or that a centralized security approach is used.

        Values: See Table 6
        """
        return VehicleIdentificationResponse.SynchronizationStatusCodes(self._further_action_required)
    
    @property
    def vin_sync_status(self):
        """ VIN/GID sync. status

        Description: This is the additional information to notify the client DoIP entity that all DoIP entities
        have synchronized their information about the VIN or GID of the vehicle

        Values: See Table 7
        """
        return VehicleIdentificationResponse.SynchronizationStatusCodes(self._vin_sync_status)


payload_type_to_message = {
    0x0000: GenericDoIPNegativeAcknowledge,
    0x0001: VehicleIdentificationRequest,
    0x0002: VehicleIdentificationRequestWithEID,
    0x0003: VehicleIdentificationRequestWithVIN,
    0x0004: VehicleIdentificationResponse,
    0x0005: RoutingActivationRequest,
    0x0006: RoutingActivationResponse,
    0x0007: AliveCheckRequest,
    0x0008: AliveCheckResponse,
    0x4001: DoipEntityStatusRequest,
    0x4002: EntityStatusResponse,
    0x4003: DiagnosticPowerModeRequest,
    0x4004: DiagnosticPowerModeResponse,
    0x8001: DiagnosticMessage,
    0x8002: DiagnosticMessagePositiveAcknowledgement,
    0x8003: DiagnosticMessageNegativeAcknowledgement,
}

payload_message_to_type = {
    message : payload_type for payload_type, message in payload_type_to_message.items()
}