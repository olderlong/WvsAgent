#! /usr/bin/env python
# _*_coding:utf-8 -*_
import socket
import time
import threading
import json


class UDPEndPoint(threading.Thread):
    def __init__(self, port=8888, handler=None):
        self.buff_size = 4096
        self.handler = handler

        self.port = port
        self.udp_socket = self.init_socket(self.port)
        if self.udp_socket is None:
            print("create socket error, port is used.")
        self.address = self.udp_socket.getsockname()
        self.ip = self.address[0]
        self.__running = threading.Event()  # 用于停止线程的标识
        super(UDPEndPoint, self).__init__()

    def start(self):
        self.__running.set()
        self.daemon = True
        super(UDPEndPoint, self).start()

    def run(self):
        print("udp server is listen at {}".format(self.address))
        while self.__running and self.udp_socket.fileno()>0:
            try:
                data, address = self.udp_socket.recvfrom(self.buff_size)
                threading.Thread(target=self.handler, args=(data, address,)).start()
            except Exception as e:
                # print(e)
                pass

    def stop(self):
        self.udp_socket.close()
        self.__running.clear()

    def init_socket(self, port):
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            host = socket.gethostname()
            udp_socket.bind((host, port))
            # self.address = (self.ip, self.port)
            # udp_socket.bind(self.address)
            return udp_socket
        except Exception as e:
            print(e)
            return None

    def send_msg_to(self, str_msg, address):
        if self.udp_socket.fileno() > 0:
            self.udp_socket.sendto(bytes(str_msg, 'utf-8'), address)

    def send_json_to(self, json_obj, address):
        json_str = json.dumps(json_obj)
        if self.udp_socket.fileno() > 0:
            self.udp_socket.sendto(bytes(json_str, 'utf-8'), address)



class Test(object):
    def print_recv_data(self, data, address):
        print("收到来自%s的数据-----%s" % (address, data.decode()))


if __name__ == '__main__':
    test = Test()

    udp_server = UDPEndPoint(handler=test.print_recv_data)
    # udp_server.daemon = True
    udp_server.start()
    udp_client = UDPEndPoint(port=5555, handler=test.print_recv_data)
    udp_client.start()

    for index in range(5):
        udp_client.send_msg_to("Hello world# {} ".format(index), udp_server.address)
        time.sleep(0.5)
        udp_server.send_msg_to("Hello world# {} ".format(index), udp_client.address)
        time.sleep(1)


    udp_server.stop()
    udp_client.stop()
    # udp_server.join()


