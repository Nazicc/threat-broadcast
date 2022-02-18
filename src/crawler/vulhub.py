#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/28 14:34
# @File   : anquanke.py
# -----------------------------------------------
# 安全客：https://www.anquanke.com/vul
# -----------------------------------------------
from lxml import etree
from html import unescape

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils import log
import time
import requests
import re


class Vulhub(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '信息安全漏洞门户'
        self.name_en = 'vulhub'
        self.home_page = 'http://cve.scap.org.cn'
        self.url = 'http://cve.scap.org.cn/vulns?view=global'


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    def get_cves(self):
        response = requests.get(
            self.url,
            headers = self.headers(),
            timeout = self.timeout
        )
        cves = []
        if response.status_code == 200:
            html = response.content.decode(self.charset)
            vul_table = re.findall(r'<tr>(.*?)</tr>', html, re.DOTALL)
            if vul_table:
                del vul_table[0]
                for vul in vul_table:
                    cve = self.to_cve(vul)
                    if cve.is_vaild():
                        cves.append(cve)
        else:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.name_ch, response.status_code))
        return cves


    def to_cve(self, xml):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        html = etree.HTML(xml)
        cve.title = unescape(etree.tostring(html.xpath("//td")[3],encoding="utf-8").decode().replace("<td>","").replace("</td>",""))
        rst = re.findall(r'href="/vuln/(.*?)">(.*?)</a>', xml, re.DOTALL)
        if rst:
            cve.url = "{}/vuln/{}".format(self.home_page,rst[0][0])

        rst = re.findall(r'(CVE-\d+-\d+)', xml)
        if rst:
            cve.id = rst[0]
        else:
            lists = cve.url.split("=")
            if len(lists)>=2:
                cve.id = lists[1]
            else:
                vulids = cve.url.split("/")
                cve.id = vulids[len(vulids)-1]

        rst = re.findall(r'(\d\d\d\d-\d\d-\d\d)', xml)
        if rst:
            cve.time = rst[0] + time.strftime(" %H:%M:%S", time.localtime())
        return cve


