#! /usr/bin/env python
# _*_ coding:utf-8 _*_
import time, threading, logging
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
        self.address = address
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
        self.state["Data"]["Name"] = self.address
        self.state["Data"]["Address"] = self.wvs_name
        self.state["Data"]["State"] = state_str
        self.state["Data"]["Timestamp"] = time.time()
        common_msg.msg_wvs_state.data = self.state
        msg_bus.send_msg(common_msg.msg_wvs_state)

        # threading.Thread(target=msg_bus.send_msg, args=(common_msg.msg_wvs_state,)).start()


def print_msg(msg):
    print(msg.data)


if __name__ == '__main__':
    wvs_state = WvsState(wvs_name="Appscan", address=("192.168.3.10", 5555))
    msg_bus.add_msg_listener(common_msg.MSG_WVS_STATE, print_msg)
    wvs_state.update_state(u"开始扫描")
    time.sleep(5)





