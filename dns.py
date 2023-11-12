from dataclasses import dataclass
import dataclasses
import struct

@dataclass
class DNSHeader:
	id: int
	flags: int
	num_questions: int = 0
	num_answers: int = 0
	num_authorities: int = 0
	num_additionals: int = 0

@dataclass
class DNSQuestion:
	name: bytes
	type_: int
	class_: int

def header_to_bytes(header):
	fields = dataclasses.astuple(header)

	# there are six fields in this class
	return struct.pack("!HHHHHH", *fields)

def question_to_bytes(question):
	return question.name + struct.pack("!HH", question.type_, question.class_)

def encode_dns_name(domain_name):
	encoded = b""

	for part in domain_name.encode("ascii").split(b"."):
		encoded += bytes([len(part)]) + part

	return encoded + b"\x00"

###
### pragma mark - queries 
###

import random
random.seed(1)

TYPE_A = 1
CLASS_IN = 1

def build_query(domain_name, record_type):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    RECURSION_DESIRED = 1 << 8

    header = DNSHeader(id=id, num_questions=1, flags=RECURSION_DESIRED)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)

    return header_to_bytes(header) + question_to_bytes(question)

###
### pragma mark - parsing responses
###

from dataclasses import dataclass

@dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes



### 
### pragma mark - Part 2
###

@dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes

import struct
def parse_header(reader):
    items = struct.unpack("!HHHHHH", reader.read(12))
    # see "a note on BytesIO" for an explanation of `reader` here ;)
    return DNSHeader(*items)

def decode_name_simple(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        parts.append(reader.read(length))
    return b".".join(parts)

def decode_name(reader):
    parts = []
    while(length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)

def decode_compressed_name(length, reader):
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result



def parse_question(reader):
    name = decode_name_simple(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack("!HH", data)
    return DNSQuestion(name, type_, class_)

def parse_record(reader):
    name = decode_name(reader)
    data = reader.read(10)
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
    data = reader.read(data_len)
    return DNSRecord(name, type_, class_, ttl, data)

from typing import List

@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]

from io import BytesIO

def parse_dns_packet(data):
    reader = BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]

    return DNSPacket(header, questions, answers, authorities, additionals)

def ip_to_string(ip):
    return  ".".join([str(x) for x in ip])

###
### pragma mark - testing
###

TYPE_A = 1

import socket

def lookup_domain(domain_name):
    query = build_query(domain_name, TYPE_A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))

    # get the response
    data, _ = sock.recvfrom(1024)
    response = parse_dns_packet(data)
    return ip_to_string(response.answers[0].data)


