#! /usr/bin/env python
# _*_coding:utf-8 -*_
from queue import Queue, Empty
from threading import *


def singleton(cls):
    _instance = {}

    def _singleton(*args, **kargs):
        if cls not in _instance:
            _instance[cls] = cls(*args, **kargs)
        return _instance[cls]

    return _singleton


@singleton
class MessageBus(object):
    def __init__(self):
        """初始化事件管理器"""
        # 对象列表
        self.__msg_queue = Queue()
        # 事件管理器开关
        self.__active = False
        self.__queue_lock = Lock()
        # 事件处理线程
        self.__thread = Thread(target=self.___run)

        # 这里的__handlers是一个字典，用来保存对应的事件的响应函数
        # 其中每个键对应的值是一个列表，列表中保存了对该事件监听的响应函数，一对多
        self.__handlers = {}

    def ___run(self):
        """引擎运行"""
        while self.__active:
            try:
                # self.__queue_lock.acquire(timeout=0.1)
                # 获取事件的阻塞时间设为1秒
                msg = self.__msg_queue.get(block=True, timeout=0.1)
                # self.__queue_lock.release()
                self.___msg_process(msg)
            except Empty:
                pass

    def ___msg_process(self, msg):
        """处理事件"""
        # 检查是否存在对该事件进行监听的处理函数

        if msg.subject in self.__handlers:
            # 若存在，则按顺序将事件传递给处理函数执行
            for handler in self.__handlers[msg.subject]:
                Thread(target=handler, args=(msg, )).start()

    def start(self):
        """启动"""
        # 将事件管理器设为启动
        self.__active = True
        self.__thread.daemon = True
        # 启动事件处理线程
        self.__thread.start()

    def stop(self):
        """停止"""
        # 将事件管理器设为停止
        self.__active = False
        # 等待事件处理线程退出
        # self.__thread.join()

    def add_msg_listener(self, subject, handler):
        """
        绑定事件和监听器处理函数
        :param subject:   事件类型，字符串
        :param handler: 事件处理函数
        :return:
        """
        # 尝试获取该事件类型对应的处理函数列表，若无则创建
        try:
            handler_list = self.__handlers[subject]
        except KeyError:
            handler_list = []

        self.__handlers[subject] = handler_list
        # 若要注册的处理器不在该事件的处理器列表中，则注册该事件
        if handler not in handler_list:
            handler_list.append(handler)

    def remove_msg_listener(self, subject, handler):
        """
        移除监听器的处理函数
        :param subject:   事件类型，字符串
        :param handler: 事件处理函数
        :return:
        """
        try:
            self.__handlers[subject].remove(handler)
        except:
            pass

    def send_msg(self, msg):
        """
        发送事件，向事件队列中存入事件
        """
        self.__msg_queue.put(msg)


class Message:
    """
    事件对象
    """
    def __init__(self, subject=None):
        self.subject = subject      # 事件类型
        self.data = {}          # 字典用于保存具体的事件数据


if __name__ == '__main__':
    msg_bus = MessageBus()


