#! /usr/bin/env python
# _*_ coding:utf-8 _*_

import logging
import time
import sys
import os

from .cc_agent import CCAgent
from .wvs_control_base import WVSControlBase
from .app_scan_control import AppScanControl


def __init_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s >>> %(message)s')
    # 文件日志
    app_path = os.getcwd()
    file_handler = logging.FileHandler(os.path.join(app_path, "log/{}.log".format(time.time())))
    file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式

    # 控制台日志
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.formatter = formatter  # 也可以直接给formatter赋值

    # 为logger添加的日志处理器
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


__init_logger("Agent")



__all__ = ["CCAgent", "WVSControlBase", "AppScanControl"]