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


class AliCloud(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '阿里云'
        self.name_en = 'AliCloud'
        self.home_page = 'https://avd.aliyun.com/'
        self.url = 'https://avd.aliyun.com/high-risk/list?page=1'


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
        cve.title = unescape(etree.tostring(html.xpath("//td")[1],encoding="utf-8").decode().replace("<td>","").replace("</td>",""))
        rst = re.findall(r'href="/detail\?id=(.*?)"\s*target="_blank">(.*?)</a>', xml, re.DOTALL)
        if rst:
            cve.url = "{}detail?id={}".format(self.home_page,rst[0][0])

        rst = re.findall(r'(CVE-\d+-\d+)', xml)
        if rst:
            cve.id = rst[0]
        else:
            cve.id = cve.url.split("=")[1]

        rst = re.findall(r'(\d\d\d\d-\d\d-\d\d)', xml)
        if rst:
            cve.time = rst[0] + time.strftime(" %H:%M:%S", time.localtime())
        return cve


