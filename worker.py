import os
import threading

import redis

import packet_pb2, client_pb2, server_pb2
from udp_utils import AESTool, create_packet
from server import PACKET_TYPE_TO_CHANNEL

redisConnection = None

def work(pubsub, channel):
    pubsub.subscribe('queue:'+channel)
    while True:
        message = pubsub.get_message()
        if message is not None:
            data = redisConnection.rpop('queue:'+channel+":list")
            if data is not None:
                packet = packet_pb2.Packet()
                packet.ParseFromString(data)
                aes_key = redisConnection.get(packet.playerID)
                if aes_key is not None:
                    reply = None
                    if channel is "gamemessages":
                        game_packet = client_pb2.ClientGameMessage()
                        game_packet.ParseFromString(AESTool.decrypt(aes_key, packet.message))
                        print("Worker got GAME: ", game_packet)
                        reply_packet = server_pb2.ServerGameMessage()
                        # Here's where you would do the heavy tasks to calculate that data
                        reply_packet.xPos = 12
                        reply_packet.yPos = 1032
                        reply_packet.zPos = 1

                        message = AESTool.encrypt(aes_key, reply_packet.SerializeToString())
                        reply = create_packet(packet_pb2.Packet.GAME, message, packet.playerID)

                    elif channel is "datamessages":
                        data_packet = client_pb2.ClientDataMessage()
                        data_packet.ParseFromString(AESTool.decrypt(aes_key, packet.message))
                        print("Worker got DATA: ", data_packet)
                        # Here's where you would do the heavy tasks to calculate that data
                        reply_packet = server_pb2.ServerDataMessage()
                        reply_packet.health = 12
                        reply_packet.coins = 1032
                        reply_packet.mana = 1

                        message = AESTool.encrypt(aes_key, reply_packet.SerializeToString())
                        reply = create_packet(packet_pb2.Packet.DATA, message, packet.playerID)
                    reply.address = packet.address
                    reply.port = packet.port
                    redisConnection.publish('queue:packetreplies', reply.SerializeToString())

def main():
    global redisConnection
    redisConnection = redis.Redis(host=os.environ.get('REDIS_HOST'))
    pubsub = redisConnection.pubsub(ignore_subscribe_messages=True)

    for channel in PACKET_TYPE_TO_CHANNEL.values():
        threading.Thread(target=work, args=(pubsub, channel,)).start()

if __name__ == '__main__':
    main()