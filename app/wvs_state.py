#! /usr/bin/env python
# _*_ coding:utf-8 _*_
import time, threading, logging, socket, psutil
from app.lib import msg_bus, common_msg

logger = logging.getLogger("Agent")

def singleton(cls):
    _instance = {}

    def _singleton(*args, **kargs):
        if cls not in _instance:
            _instance[cls] = cls(*args, **kargs)
        return _instance[cls]

    return _singleton


@singleton
class WvsState(object):
    def __init__(self, wvs_name=None, address=None):
        self.wvs_name = wvs_name
        if address:
            self.address = address
        else:
            self.address = (self.get_host_ip(), 5555)

        self.state = {
            "Type": "WVSState",
            "Data": {
                "Name": self.wvs_name,
                "Address": self.address,
                "Timestamp": time.time(),
                "State": u"初始化"
            }
        }

    def update_state(self, state_str=u"初始化"):
        self.state["Data"]["Name"] = self.wvs_name
        self.state["Data"]["Address"] = self.address
        self.state["Data"]["State"] = state_str
        self.state["Data"]["Timestamp"] = time.time()
        common_msg.msg_wvs_state.data = self.state
        msg_bus.send_msg(common_msg.msg_wvs_state)

        # threading.Thread(target=msg_bus.send_msg, args=(common_msg.msg_wvs_state,)).start()

    def get_host_ip(self):
        """
        获取以太网eth的ip地址
        :return: ip地址
        """
        info = psutil.net_if_addrs()
        for k, v in info.items():
            if str(k).startswith("以太网") or str(k).startswith("eth") or str(k).startswith("本地连接"):
                for item in v:
                    if item[0] == 2 and not item[1] == '127.0.0.1':
                        return item[1]
            else:
                return socket.gethostname()

def print_msg(msg):
    print(msg.data)


if __name__ == '__main__':
    wvs_state = WvsState(wvs_name="Appscan", address=("192.168.3.10", 5555))
    msg_bus.add_msg_listener(common_msg.MSG_WVS_STATE, print_msg)
    wvs_state.update_state(u"开始扫描")
    time.sleep(5)





