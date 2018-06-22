#! /usr/bin/env python
# _*_ coding:utf-8 _*_
import logging

from app import CCAgent, AppScanControl
from app.lib import common_msg, msg_bus

logger = logging.getLogger("Agent")
agent = CCAgent(name="AppScanAgent", port=5000, cc_server_address=("192.168.1.31", 6000))

appscan = AppScanControl()


def agent_run():
    logger.info("Agent running...")
    agent.start()


def agent_stop():
    print("agent exit...")
    appscan.stop_scan()
    agent.stop()
    msg_bus.stop()


msg_bus.add_msg_listener(common_msg.MSG_AGENT_EXIT, agent_stop)

if __name__ == '__main__':
    agent_run()
    agent.join()
