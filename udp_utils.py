"""Utilities for UDP operations"""
import binascii
import os

from google.protobuf import timestamp_pb2

from Crypto import Random
from Crypto.Cipher import AES

import packet_pb2

sequence = 1

def create_packet(packet_type, message, player_id=None):
    """Create a packet
    This function abstracts the creation process to add a checksum,
    timestamp, etc

    :param packet_type: the packet type, check protobuf for possible values
    """
    global sequence

    packet = packet_pb2.Packet()
    packet.type = packet_type
    packet.sequence = sequence
    sequence += 1

    if player_id is not None:
        packet.playerID = player_id

    packet.message = message

    timestamp = timestamp_pb2.Timestamp()
    timestamp.GetCurrentTime()
    packet.timestamp.CopyFrom(timestamp)

    packet.messageLength = len(packet.message)

    crc_data = packet.SerializePartialToString()
    packet.crc = (binascii.crc32(crc_data) & 0xFFFFFFFF)

    return packet

class AESTool():
    """A class to do AES operations"""
    @staticmethod
    def create_key():
        """Creates an AES key"""
        return os.urandom(32)

    @staticmethod
    def encrypt(key, message):
        """Encrypts a message

        :param key: the key to use to encrypt
        :param message: the message to encrypt
        """

        message = AESTool.pad(message)
        init_vector = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        return init_vector + cipher.encrypt(message)

    @staticmethod
    def decrypt(key, message):
        """Decrypts a message

        :param key: the key to use to decrypt
        :param message: the message to decrypt
        """
        init_vector = message[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        return AESTool.unpad(cipher.decrypt(message[AES.block_size:]))

    @staticmethod
    def pad(message):
        """Pads a message

        AES can only use 16 bit blocks, so if a message doesn't meet that, we have to pad it
        :param message: the message to pad
        """
        num_bytes_to_pad = AES.block_size - len(message) % AES.block_size
        message = message + num_bytes_to_pad * chr(num_bytes_to_pad).encode('utf-8')
        return message

    @staticmethod
    def unpad(message):
        """Unpads a message

        :param message: the message to unpad
        """
        return message[:-ord(message[len(message)-1:])]
