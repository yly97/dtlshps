# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: p4/bm/dataplane_interface.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1fp4/bm/dataplane_interface.proto\x12\x05p4.bm\"R\n\x13PacketStreamRequest\x12\n\n\x02id\x18\x01 \x01(\x04\x12\x11\n\tdevice_id\x18\x02 \x01(\x04\x12\x0c\n\x04port\x18\x03 \x01(\r\x12\x0e\n\x06packet\x18\x04 \x01(\x0c\"S\n\x14PacketStreamResponse\x12\n\n\x02id\x18\x01 \x01(\x04\x12\x11\n\tdevice_id\x18\x02 \x01(\x04\x12\x0c\n\x04port\x18\x03 \x01(\r\x12\x0e\n\x06packet\x18\x04 \x01(\x0c\"g\n\x18SetPortOperStatusRequest\x12\x11\n\tdevice_id\x18\x01 \x01(\x04\x12\x0c\n\x04port\x18\x02 \x01(\r\x12*\n\x0boper_status\x18\x03 \x01(\x0e\x32\x15.p4.bm.PortOperStatus\"\x1b\n\x19SetPortOperStatusResponse*S\n\x0ePortOperStatus\x12\x17\n\x13OPER_STATUS_UNKNOWN\x10\x00\x12\x14\n\x10OPER_STATUS_DOWN\x10\x01\x12\x12\n\x0eOPER_STATUS_UP\x10\x02\x32\xbd\x01\n\x12\x44\x61taplaneInterface\x12M\n\x0cPacketStream\x12\x1a.p4.bm.PacketStreamRequest\x1a\x1b.p4.bm.PacketStreamResponse\"\x00(\x01\x30\x01\x12X\n\x11SetPortOperStatus\x12\x1f.p4.bm.SetPortOperStatusRequest\x1a .p4.bm.SetPortOperStatusResponse\"\x00\x62\x06proto3')

_PORTOPERSTATUS = DESCRIPTOR.enum_types_by_name['PortOperStatus']
PortOperStatus = enum_type_wrapper.EnumTypeWrapper(_PORTOPERSTATUS)
OPER_STATUS_UNKNOWN = 0
OPER_STATUS_DOWN = 1
OPER_STATUS_UP = 2


_PACKETSTREAMREQUEST = DESCRIPTOR.message_types_by_name['PacketStreamRequest']
_PACKETSTREAMRESPONSE = DESCRIPTOR.message_types_by_name['PacketStreamResponse']
_SETPORTOPERSTATUSREQUEST = DESCRIPTOR.message_types_by_name['SetPortOperStatusRequest']
_SETPORTOPERSTATUSRESPONSE = DESCRIPTOR.message_types_by_name['SetPortOperStatusResponse']
PacketStreamRequest = _reflection.GeneratedProtocolMessageType('PacketStreamRequest', (_message.Message,), {
  'DESCRIPTOR' : _PACKETSTREAMREQUEST,
  '__module__' : 'p4.bm.dataplane_interface_pb2'
  # @@protoc_insertion_point(class_scope:p4.bm.PacketStreamRequest)
  })
_sym_db.RegisterMessage(PacketStreamRequest)

PacketStreamResponse = _reflection.GeneratedProtocolMessageType('PacketStreamResponse', (_message.Message,), {
  'DESCRIPTOR' : _PACKETSTREAMRESPONSE,
  '__module__' : 'p4.bm.dataplane_interface_pb2'
  # @@protoc_insertion_point(class_scope:p4.bm.PacketStreamResponse)
  })
_sym_db.RegisterMessage(PacketStreamResponse)

SetPortOperStatusRequest = _reflection.GeneratedProtocolMessageType('SetPortOperStatusRequest', (_message.Message,), {
  'DESCRIPTOR' : _SETPORTOPERSTATUSREQUEST,
  '__module__' : 'p4.bm.dataplane_interface_pb2'
  # @@protoc_insertion_point(class_scope:p4.bm.SetPortOperStatusRequest)
  })
_sym_db.RegisterMessage(SetPortOperStatusRequest)

SetPortOperStatusResponse = _reflection.GeneratedProtocolMessageType('SetPortOperStatusResponse', (_message.Message,), {
  'DESCRIPTOR' : _SETPORTOPERSTATUSRESPONSE,
  '__module__' : 'p4.bm.dataplane_interface_pb2'
  # @@protoc_insertion_point(class_scope:p4.bm.SetPortOperStatusResponse)
  })
_sym_db.RegisterMessage(SetPortOperStatusResponse)

_DATAPLANEINTERFACE = DESCRIPTOR.services_by_name['DataplaneInterface']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _PORTOPERSTATUS._serialized_start=345
  _PORTOPERSTATUS._serialized_end=428
  _PACKETSTREAMREQUEST._serialized_start=42
  _PACKETSTREAMREQUEST._serialized_end=124
  _PACKETSTREAMRESPONSE._serialized_start=126
  _PACKETSTREAMRESPONSE._serialized_end=209
  _SETPORTOPERSTATUSREQUEST._serialized_start=211
  _SETPORTOPERSTATUSREQUEST._serialized_end=314
  _SETPORTOPERSTATUSRESPONSE._serialized_start=316
  _SETPORTOPERSTATUSRESPONSE._serialized_end=343
  _DATAPLANEINTERFACE._serialized_start=431
  _DATAPLANEINTERFACE._serialized_end=620
# @@protoc_insertion_point(module_scope)
