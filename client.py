import random
import socket
import threading
import time

import Crypto
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from udp_utils import AESTool, create_packet
import client_pb2, packet_pb2, server_pb2

THREAD_TIMEOUT = 3

class Client():
    def __init__(self, server_host, server_port, key, debug=True):
        self.debug = debug
        self.server_host = server_host
        self.server_port = server_port
        self.key = key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("Opening Client Socket")
        self.sock.settimeout(10)
        self.heartbeat_thread = threading.Thread(target=self.start_heartbeat)
        self.heartbeat_thread.setDaemon(True)
        self.listen_thread = threading.Thread(target=self.listen_to_server)
        self.listen_thread.setDaemon(True)

    def start(self):
        """Starts the listening thread"""
        self.listen_thread.start()

    def stop(self):
        """Stops the client"""
        print("Joining listen_thread")
        self.listen_thread.join(THREAD_TIMEOUT)
        print("Joined listen_thread")

        print("Joining heartbeat_thread")
        self.heartbeat_thread.join(THREAD_TIMEOUT)
        print("Joined heartbeat_thread")

    def listen_to_server(self):
        """Thread to listen to the server"""
        size = 4096
        while True:
            data, address = self.sock.recvfrom(size)
            if self.debug:
                print('received {} bytes from {}'.format(len(data), address))
            if data:
                packet = packet_pb2.Packet()
                packet.ParseFromString(data)
                if self.debug:
                    print(packet)
                if packet.type == packet_pb2.Packet.HEARTBEAT and not \
                   self.heartbeat_thread.is_alive():
                    print("Starting Heartbeat Thread")
                    self.heartbeat_thread.start()
                if packet.type == packet_pb2.Packet.GAME:
                    game_packet = server_pb2.ServerGameMessage()
                    game_packet.ParseFromString(AESTool.decrypt(self.key, packet.message))
                    print(game_packet)
                if packet.type == packet_pb2.Packet.DATA:
                    data_packet = server_pb2.ServerDataMessage()
                    data_packet.ParseFromString(AESTool.decrypt(self.key, packet.message))
                    print(data_packet)
            else:
                print('Client disconnected')

    def send_to_server(self, packet):
        """Sends a packet to the server
        :param packet: the packet to send
        """
        data = packet.SerializeToString()
        self.sock.sendto(data, (self.server_host, self.server_port))
        if self.debug:
            print('sent {} bytes to {}'.format(len(data), (self.server_host, self.server_port)))

    def start_heartbeat(self):
        """Starts the heartbeat"""
        player_id = "1111"
        while True:
            packet = create_packet(packet_pb2.Packet.HEARTBEAT, b"Ping", player_id)
            self.sock.sendto(packet.SerializeToString(), (self.server_host, self.server_port))
            time.sleep(1)

client_socket = None

def data_thread(key, player_id):
    """The thread to create dummy data packets
    :param player_id: the player id
    """
    while True:
        data_packet = client_pb2.ClientDataMessage()
        data_packet.lostHealth = 12
        data_packet.usedCoins = 1032
        data_packet.usedMana = 1

        message = AESTool.encrypt(key, data_packet.SerializeToString())
        packet = create_packet(packet_pb2.Packet.DATA, message, player_id)

        client_socket.send_to_server(packet)
        sleep_time = random.randint(300, 1500)
        time.sleep(sleep_time/1000)


def game_thread(key, player_id):
    """The thread to create dummy game packets
    :param player_id: the player id
    """
    count = 0
    while count < 3:
        try:
            game_packet = client_pb2.ClientGameMessage()
            game_packet.xDelta = 2
            game_packet.yDelta = -14
            game_packet.zDelta = 0

            message = AESTool.encrypt(key, game_packet.SerializeToString())
            print('message len', len(message))
            packet = create_packet(packet_pb2.Packet.GAME, message, player_id)
            client_socket.send_to_server(packet)
            sleep_time = random.randint(300, 1500)
            time.sleep(sleep_time / 1000)
            count += 1
            # pylint: disable=broad-except
        except Exception as exception:
            # pylint: enable=broad-except
            print(exception)


def main():
    """The main client method"""
    # pylint: disable=global-statement
    # pylint: disable=invalid-name
    global client_socket
    # pylint: enable=invalid-name
    # pylint: enable=global-statement
    try:
        key = AESTool.create_key()

        client_socket = Client('127.0.0.1', 1234, key)
        client_socket.start()

        with open('public.key', 'r') as keyfile:
            rsa_key = PKCS1_OAEP.new(RSA.importKey(keyfile.read()), hashAlgo=Crypto.Hash.SHA256)

        # Apparently the encrypt message has a dummy second param and
        # second item in the return tuple that are to be ignored per the docs
        encrypted_key = rsa_key.encrypt(key)

        player_id = "1111"

        auth_packet = create_packet(packet_pb2.Packet.AUTH, encrypted_key, player_id)
        client_socket.send_to_server(auth_packet)


        while not client_socket.heartbeat_thread.is_alive():
            time.sleep(0)

        print('starting game threads')
        threading.Thread(target=data_thread, args=(key, player_id,)).start()
        threading.Thread(target=game_thread, args=(key, player_id,)).start()

    except KeyboardInterrupt:
        client_socket.stop()
        client_socket.join(THREAD_TIMEOUT)


if __name__ == '__main__':
    main()