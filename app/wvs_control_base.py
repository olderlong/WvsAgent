#! /usr/bin/env python
# _*_ coding:utf-8 _*_
import logging
from app.lib import msg_bus, common_msg

logger = logging.getLogger("Agent")


class WVSControlBase(object):
    def __init__(self):
        msg_bus.add_msg_listener(common_msg.MSG_WVS_COMMAND, self.wvs_command_handler)
        self.wvs_action = "StartNewScan"
        self.scan_config = {}

    def wvs_command_handler(self, msg):
        """
        wvs 控制命令处理
        命令格式：
        command = {
            "Action": "Operation",
            "Config": {}    #可选，当命令为StartNewScan时需提供该字段作为扫描参数
            }
        :param event: WVS控制命令事件
        :return:
        """
        command_data = msg.data
        try:
            self.wvs_action = command_data["Action"]
            if self.wvs_action == "StartNewScan":
                self.scan_config = command_data["Config"]
                self.start_new_scan(self.scan_config)
            elif self.wvs_action == "StopScan":
                self.stop_scan()
            else:
                self.other_action(command_data)
        except KeyError as e:
            pass

    def start_new_scan(self, config):
        pass

    def stop_scan(self):
        pass

    def other_action(self, command):
        pass