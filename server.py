"""A sever that's threaded to handle UDP game messages"""
import binascii
import os
import socket
import threading

import Crypto
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import redis

import packet_pb2
from udp_utils import create_packet

THREAD_TIMEOUT = 3
PACKET_TYPE_TO_CHANNEL = {
    packet_pb2.Packet.GAME: 'gamemessages',
    packet_pb2.Packet.DATA: 'datamessages'
}

class ThreadedServer():
    """A sever that's threaded to handle UDP game messages"""
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.redis = redis.Redis(host=os.environ.get('REDIS_HOST'))
        with open('private.key', 'r') as keyfile:
            rsa = keyfile.read()
        self.rsa_key = PKCS1_OAEP.new(RSA.importKey(rsa), hashAlgo=Crypto.Hash.SHA256)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("Opening Server Socket at {} on port {}".format(self.host, self.port))
        self.sock.bind((self.host, self.port))
        self.listen_thread = threading.Thread(target=self.listen_to_client)
        self.response_thread = threading.Thread(target=self.send_responses)

        for channel in PACKET_TYPE_TO_CHANNEL.values():
            self.prime_channel(channel)

    def listen(self):
        """Starts the listener thread the response thread"""
        self.listen_thread.start()
        self.response_thread.start()

    def stop(self):
        """Stops the spinning threads"""
        self.listen_thread.join(THREAD_TIMEOUT)
        self.response_thread.join(THREAD_TIMEOUT)

    def listen_to_client(self):
        """The listener thread
        It listenes to packets, and spawns a new thread to handle them
        This needs to drop back to sock.recvfrom as fast as possible
        to avoid socket overflow. Avoid heavy tasks in this thread
        """
        size = 4096
        while True:
            data, address = self.sock.recvfrom(size)
            print('received {} bytes from {}'.format(len(data), address))
            if data:
                # Spawn a new thread so we don't interrupt server flow
                threading.Thread(target=self.handle_packet, args=(data, address)).start()
            else:
                print('Client disconnected')

    def handle_packet(self, data, address):
        """Packer handler thread

        This is where the packet is checked for validity and
        put into the appropriate redis queue

        :param data: the data from the packet
        :address: a tuple with the (ip_address, port_number)
        """
        packet = packet_pb2.Packet()
        packet.ParseFromString(data)

        if packet.type != packet_pb2.Packet.HEARTBEAT:
            print(packet)

        packet_crc = packet.crc
        packet.ClearField('crc')
        crc_data = packet.SerializePartialToString()
        crc = binascii.crc32(crc_data) & 0xFFFFFFFF
        if packet_crc != crc:
            print('Given CRC: {}'.format(packet.crc))
            print('Calculated CRC: {}'.format((binascii.crc32(crc_data) & 0xFFFFFFFF)))
            print("Dropped packet for bad checksum")
            return
        # put the crc back in there!
        packet.crc = packet_crc
        if packet.type == packet_pb2.Packet.HEARTBEAT:
            packet = create_packet(packet_pb2.Packet.HEARTBEAT, b"Pong")
            self.sock.sendto(packet.SerializeToString(), address)
        elif packet.type == packet_pb2.Packet.AUTH:
            decrypted_aes_key = self.rsa_key.decrypt(packet.message)
            print('DECRYPTED AES KEY:', [x for x in decrypted_aes_key])
            print('PLAYER ID AUTH: ', packet.playerID)
            self.redis.set(packet.playerID, decrypted_aes_key)
            packet = create_packet(packet_pb2.Packet.HEARTBEAT, b"Pong")
            self.sock.sendto(packet.SerializeToString(), address)
        elif packet.type in PACKET_TYPE_TO_CHANNEL:
            packet.address = address[0]
            packet.port = address[1]
            self.forward_packet(packet, PACKET_TYPE_TO_CHANNEL[packet.type])

    def prime_channel(self, redis_queue_name):
        """ Primes the workers to start processing any
        objects in the queue.

        :param redis_queue_name: the redis queue
        """
        self.redis.publish('queue:'+redis_queue_name, '')

    def forward_packet(self, packet, redis_queue_name):
        """forwards the specified packet to the specified redis queue.

        :param packet: the packet to push onto the queue
        :param redis_queue_name: the redis queue
        """
        self.redis.lpush('queue:'+redis_queue_name+':list', packet.SerializeToString())
        self.redis.publish('queue:'+redis_queue_name, '')

    def send_responses(self):
        """Thread to send responses to the client

        We subscribe to a redis queue to get the packets
        the worker wants to send to the client
        """
        pubsub = self.redis.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe('queue:packetreplies')
        while True:
            response = pubsub.get_message()
            if response is not None:
                packet = packet_pb2.Packet()
                data = response['data']
                packet.ParseFromString(data)

                self.sock.sendto(packet.SerializeToString(), (packet.address, packet.port))
                print('sent {} bytes to {}'.format(
                    len(packet.SerializeToString()),
                    packet.address))

if __name__ == '__main__':
    import worker
    worker.main()
    ThreadedServer('0.0.0.0', 1234).listen()