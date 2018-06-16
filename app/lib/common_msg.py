#! /usr/bin/env python
# _*_coding:utf-8 -*_
from app.lib import Message


def singleton(cls):
    _instance = {}

    def _singleton(*args, **kargs):
        if cls not in _instance:
            _instance[cls] = cls(*args, **kargs)
        return _instance[cls]

    return _singleton


@singleton
class CommonMsg(object):
    def __init__(self):
        self.MSG_HEARTBEAT = "Heartbeat"
        self.msg_heartbeat = Message(subject=self.MSG_HEARTBEAT)

        self.MSG_WVS_STATE = "WVSState"
        self.msg_wvs_state = Message(subject=self.MSG_WVS_STATE)

        self.MSG_WVS_RESULT_RECEIVE = "ScanResultReceive"
        self.msg_scan_result_receive = Message(subject=self.MSG_WVS_RESULT_RECEIVE)

        self.MSG_WVS_COMMAND = "WVSCommand"
        self.msg_wvs_command = Message(subject=self.MSG_WVS_COMMAND)

        self.MSG_SERVER_COMMAND = "ServerCommand"
        self.msg_server_command = Message(subject=self.MSG_SERVER_COMMAND)

        self.MSG_AGENT_EXIT = "AgentExit"
        self.msg_agent_exit = Message(subject=self.MSG_AGENT_EXIT)

        self.MSG_SCAN_RESULT_SEND = "ScanResultSend"
        self.msg_scan_result_send = Message(subject=self.MSG_SCAN_RESULT_SEND)

