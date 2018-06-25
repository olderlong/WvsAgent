#! /usr/bin/env python
# _*_ coding:utf-8 _*_
import os
import shutil
import logging
import subprocess
import time
import threading
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from app.lib import msg_bus, common_msg
from app import WVSControlBase
from .wvs_state import WvsState

logger = logging.getLogger("Agent")


APPSCAN_RETCODE=["成功完成", "启动失败", "命令行错误", "许可证无效",
                 "装入失败", "扫描失败", "报告失败", "保存失败", "常见错误"]

wvsstate = WvsState(wvs_name="Appscan")


class AppScanControl(WVSControlBase):
    def __init__(self):
        self.appscan_path = "appscancmd"
        wvsstate.update_state(u"等待接受命令")
        super(AppScanControl, self).__init__()

    def start_new_scan(self, config):
        """
        开始一个新的扫描，首先提取扫描配置参数，主要包括起始URL、扫描策略；其次基于StartURL创建扫描项目目录，copy配置文
        件到该目录，针对APPScan 用StartURL替换扫描配置模板模板中的StartUrl， 生成结果文件名等参数；最后构造命令行参数，
        启动扫描
        :param config:
        :return:
        """
        self.start_urls = config["StartURL"]
        self.scan_policy = config["ScanPolicy"]
        logger.info("Start a scan to website <{}> with a policy <{}>".format(self.start_urls, self.scan_policy))
        self.__create_scan_project_dir(self.start_urls)

        self.__init_scan_config()

        self.appscan_shell_cmd = "{} /e /st {} /d {} /rt xml /rf {} /v".format(
            self.appscan_path,
            self.scan_template_file,
            self.scan_result_file,
            self.scan_result_xml_file
        )

        logger.info("Appscan shell command is: {}".format(self.appscan_shell_cmd))
        # for debug
        # self.appscan_shell_cmd = "ping www.baidu.com"
        # for debug
        self.__start_appscan(self.appscan_shell_cmd)

    def stop_scan(self):
        if self.appscan_process:
            logger.info("Appscan is terminated.")
            self.appscan_process.terminate()

    def __start_appscan(self, cmd):
        wvsstate.update_state(u"开始扫描")
        # self.appscan_process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.appscan_process = subprocess.Popen(cmd, shell=True)

        while self.appscan_process.poll() is None:
            wvsstate.update_state(u"正在扫描")
            time.sleep(5)
        # self.appscan_process.wait()

        # while self.appscan_process.poll() is None:
        #     line = self.appscan_process.stdout.readline()
        #     line_str = str(line, 'gbk')
        #     line_str = line_str.strip()
        #     if line_str:
        #         print("Appscan扫描进程输出：{}".format(line_str))
        #     # time.sleep(0.1)

        if self.appscan_process.returncode == 0:
            logger.info("Appscan扫描进程成功结束")
            wvsstate.update_state(u"扫描结束")
            self.__process_scan_result()
        else:
            logger.error("Appscan {}".format(APPSCAN_RETCODE[self.appscan_process.returncode]))
            wvsstate.update_state(u"{}".format(APPSCAN_RETCODE[self.appscan_process.returncode]))

    def __process_scan_result(self):
        res_list = self.__gen_scan_result()
        if res_list:
            wvsstate.update_state(u"结果上报")
            for res in res_list:
                result = {
                    "Type": "ScanResult",
                    "Data": res
                }
                common_msg.msg_scan_result_send.data = result
                msg_bus.send_msg(common_msg.msg_scan_result_send)
                self.__print_scan_result(res)
                time.sleep(1)
        else:
            wvsstate.update_state(u"结果为空")
            time.sleep(5)
            wvsstate.update_state(u"任务结束")

    def __print_scan_result(self, vul_result):
        result_str = "漏洞类型:\t{}\n漏洞URL:\t{}\n漏洞等级:\t{}\n漏洞信息:\t".format(
            vul_result["VulType"],
            vul_result["VulUrl"],
            vul_result["VulSeverity"]
        )
        print(result_str)
        for info in vul_result["VulDetails"]:
            result_str = "\tURL参数变异:\t{}\n\t漏洞原因:\t{}\n\tCWE:\t{}\n\tCVE:\t{}".format(
                info["url_param_variant"],
                info["vul_reasoning"],
                info["CWE"],
                info["CVE"]
            )
            print(result_str)
        print("\r\n")

    def __gen_scan_result(self):
        wvsstate.update_state(u"处理结果")
        try:
            vul_result_list = []
            tree = ET.ElementTree(file=self.scan_result_xml_file)
            issue_list_nodes = tree.findall("Results/Issues/Issue")
            # print(len(issue_list_nodes))

            for issue_node in issue_list_nodes:
                vul_type_ID = issue_node.attrib["IssueTypeID"]
                vul_url = issue_node.find("Url").text
                vul_severity = issue_node.find("Severity").text
                vul_details = []
                cwe_list = []
                cve_list = []
                vul_info_nodes = issue_node.findall("Variant")
                for info_node in vul_info_nodes:
                    url_param_variant = info_node.find("Difference").text
                    vul_reasoning = info_node.find("Reasoning").text
                    cwe = info_node.find("CWE").text
                    cve = info_node.find("CVE").text
                    vul_info = {
                        "url_param_variant": url_param_variant,
                        "vul_reasoning": vul_reasoning,
                        "CWE": cwe,
                        "CVE": cve
                    }
                    vul_details.append(vul_info)
                vul_result = {
                    "VulType": vul_type_ID,
                    "VulUrl": vul_url,
                    "VulSeverity": vul_severity,
                    "VulDetails": vul_details
                }
                vul_result_list.append(vul_result)
            return vul_result_list
        except Exception as e:
            print(e)
            return None

    def __init_scan_config(self):
        """
        根据配置信息，修改扫描模板文件
        :return:
        """
        try:
            tree = ET.ElementTree(file=self.scan_template_file)

            starting_urls_node = tree.find("Application/StartingUrls")
            old_starting_url_nodes = tree.findall("Application/StartingUrls/StartingUrl")

            # 删除原有URL
            for node in old_starting_url_nodes:
                starting_urls_node.remove(node)

            if type(self.start_urls)==type(list()):
                logger.info("扫描多个链接")
                for url in self.start_urls:
                    starting_url_node = ET.Element("StartingUrl")
                    starting_url_node.text = url
                    starting_urls_node.append(starting_url_node)
            else:
                logger.info("扫描单个链接")
                starting_url_node = ET.Element("StartingUrl")
                starting_url_node.text = self.start_urls
                starting_urls_node.append(starting_url_node)

            tree.write(self.scan_template_file)
        except Exception as e:
            logger.error(e)

    def __create_scan_project_dir(self, start_url):
        hostname = start_url.split("//")[1].split("/")[0].split(":")[0]
        self.current_dir = os.getcwd()

        self.scan_project_dir = os.path.join(self.current_dir, "scan_prj", hostname) # 该方法针对单链接有效
        if not os.path.exists(self.scan_project_dir):
            os.makedirs(self.scan_project_dir)
            logger.info("扫描项目目录>>{}\t创建成功".format(self.scan_project_dir))
        else:
            logger.info("扫描项目目录>>{}\t已存在".format(self.scan_project_dir))

        self.scan_result_file = os.path.join(self.scan_project_dir, hostname + ".scan")
        if os.path.exists(self.scan_result_file):
            os.remove(self.scan_result_file)

        self.scan_result_xml_file = os.path.join(self.scan_project_dir, "result.xml")
        if os.path.exists(self.scan_result_xml_file):
            # os.remove(self.scan_result_xml_file)
            pass

        self.scan_template_file = os.path.join(self.scan_project_dir, "template.scant")
        if os.path.exists(self.scan_template_file):
            os.remove(self.scan_template_file)

        self.__gen_scan_template_file()

    def __gen_scan_template_file(self):

        if self.scan_policy == "Normal":
            scan_template_file = "default.scant"
            # scan_template_file = "quick.scant"
        elif self.scan_policy == "Quick":
            scan_template_file = "quick.scant"
        elif self.scan_policy == "Full":
            scan_template_file = "full.scant"
        else:
            scan_template_file = "default.scant"

        source_file = os.path.join(os.getcwd(), "templates", scan_template_file)
        logger.info("template file is {}".format(source_file))

        if os.path.exists(source_file):
            if not os.path.exists(self.scan_template_file):
                shutil.copy(source_file, self.scan_template_file)
            else:
                logger.error("扫描项目中模板文件已经存在")
        else:
            logger.error("模板文件不存在")




