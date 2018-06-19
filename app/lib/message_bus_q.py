#! /usr/bin/env python
# _*_coding:utf-8 -*_
"""
    基于优先队列的消息总线
"""
import time
from queue import PriorityQueue, Empty
import threading
from threading import Thread


class MessageBus(object):
    # 对象列表
    __msg_queue = PriorityQueue()
    # 事件管理器开关
    __active = False
    is_stopped = False
    # __queue_lock = Lock()
    # 事件处理线程
    __thread = None
    # 这里的__handlers是一个字典，用来保存对应的事件的响应函数
    # 其中每个键对应的值是一个列表，列表中保存了对该事件监听的响应函数，一对多
    __handlers = {}

    @staticmethod
    def __run():
        """引擎运行"""
        while MessageBus.__active:
            try:
                # 获取事件的阻塞时间设为0.1秒
                msg = MessageBus.__msg_queue.get(block=True, timeout=0.1)
                MessageBus.___msg_process(msg)
            except Empty:
                pass

    @staticmethod
    def ___msg_process(msg):
        """处理事件"""
        # 检查是否存在对该事件进行监听的处理函数
        if msg.subject in MessageBus.__handlers:
            # 若存在，则按顺序将事件传递给处理函数执行
            for handler in MessageBus.__handlers[msg.subject]:
                Thread(target=handler, args=(msg, )).start()

    @staticmethod
    def start():
        """启动"""
        MessageBus.add_msg_listener("MessageBusStop", MessageBus.stop)
        # 将事件管理器设为启动
        MessageBus.__thread = Thread(target=MessageBus.__run)
        MessageBus.__active = True
        MessageBus.__thread.daemon = True
        # 启动事件处理线程
        MessageBus.__thread.start()

    @staticmethod
    def stop():
        """停止"""
        # 将事件管理器设为停止
        MessageBus.__active = False
        MessageBus.is_stopped = True
        # 等待事件处理线程退出
        # self.__thread.join()

    @staticmethod
    def add_msg_listener(subject, handler):
        """
        绑定事件和监听器处理函数
        :param subject:   事件类型，字符串
        :param handler: 事件处理函数
        :return:
        """
        # 尝试获取该事件类型对应的处理函数列表，若无则创建
        try:
            handler_list = MessageBus.__handlers[subject]
        except KeyError:
            handler_list = []

        MessageBus.__handlers[subject] = handler_list
        # 若要注册的处理器不在该事件的处理器列表中，则注册该事件
        if handler not in handler_list:
            handler_list.append(handler)

    @staticmethod
    def remove_msg_listener(subject, handler):
        """
        移除监听器的处理函数
        :param subject:   事件类型，字符串
        :param handler: 事件处理函数
        :return:
        """
        # 尝试获取该事件类型对应的处理函数列表，若无则创建
        try:
            handler_list = MessageBus.__handlers[subject]
            if handler_list:
                try:
                    handler_list.remove(handler)
                except:
                    print("函数{}未注册".format(handler.__name__))
        except KeyError:
            print("消息主题'{}'不存在".format(subject))

    @staticmethod
    def send_msg(msg):
        """
        发送事件，向事件队列中存入事件
        """
        MessageBus.__msg_queue.put(msg)


class Message(object):
    def __init__(self, priority=1, subject=None, data={}):
        self.priority = priority    # 消息优先级
        self.subject = subject      # 消息类型
        self.data = data            # 消息数据，字典类型

    def __lt__(self, other):    # operator <
        # return self.priority < other.priority   # 小的在前
        return self.priority > other.priority   # 大的在前

    def __str__(self):
        return '(' + str(self.priority)+', \'' + self.subject + '\', ' + str(self.data)+')'


if __name__ == '__main__':
    def fn(msg):
        print("Time: {}\t\tThread ID: {}\t\t Data: {}".format(time.time(), threading.get_ident(), str(msg)))
        # time.sleep(1)

    MessageBus.add_msg_listener("C", fn)
    MessageBus.add_msg_listener("B", fn)
    MessageBus.add_msg_listener("A", fn)
    MessageBus.add_msg_listener("D", fn)

    MessageBus.start()
    msg = Message(3, "B", {"b": 1})
    MessageBus.send_msg(msg)
    msg = Message(3, "B", {"b": 1})
    MessageBus.send_msg(msg)
    for _ in range(50):
        msg = Message(1, "C", {"c": 1})
        MessageBus.send_msg(msg)
        time.sleep(0.01)

    msg = Message(5, "D", {"d": 1})
    MessageBus.send_msg(msg)
    import time
    time.sleep(1)
    MessageBus.stop()