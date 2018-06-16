#! /usr/bin/env python
# _*_ coding:utf-8 _*_

from app import CCAgent, AppScanControl
from app.lib import common_msg, msg_bus

agent = CCAgent(name="AppScan", port=5555, cc_server_address=("192.168.3.2", 6666))
appscan = AppScanControl()


def agent_run():
    agent = CCAgent(name="AppScan", port=4444, cc_server_address=("192.168.3.2", 6666))
    appscan = AppScanControl()
    print("Agent running...")
    agent.start()
    agent.join()


def agent_stop(msg):
    # print(event.dict)
    print("agent exit...")
    appscan.stop_scan()
    agent.stop()
    msg_bus.stop()

msg_bus.add_msg_listener(common_msg.MSG_AGENT_EXIT, agent_stop)

if __name__ == '__main__':

    agent_run()