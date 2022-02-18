#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/28 14:34
# @File   : anquanke.py
# -----------------------------------------------
# 安全客：https://www.anquanke.com/vul
# -----------------------------------------------
import json

from lxml import etree
from html import unescape

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils import log
import time
import requests
import re


class PocPlus(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '数字观星POC++'
        self.name_en = 'pocplus'
        self.home_page = 'https://poc.shuziguanxing.com/'
        self.url = 'https://poc.shuziguanxing.com/pocweb/issueWarehouse/list'
        self.vulurl="https://poc.shuziguanxing.com/#/publicIssueInfo#issueId={}"


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    def get_cves(self):
        params = {"issueExtWhere":{"peopleSortType":"null","timeSortType":2,"type":"null"},"pageBasic":{"numPerPage":30,"pageNum":1}}
        response = requests.post(
            self.url,
            headers = self.headers(),
            timeout = self.timeout,
            data=json.dumps(params)
        )
        cves = []
        if response.status_code == 200:
            json_obj = json.loads(response.text)
            for obj in json_obj['info']["result"]:
                cve = self.to_cve(obj)
                if cve.is_vaild():
                    cves.append(cve)
        else:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.name_ch, response.status_code))
        return cves

    def to_cve(self, json_obj):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        cve.url = self.vulurl.format(json_obj["id"])

        cve.time = json_obj["addTime"]

        cve.title = json_obj.get('name') or ''
        if json_obj.get("isCve") == 1:
            cve.id = json_obj.get("cveId")
        else:
            res = re.findall("(CNVD-\d{4}-\d{4})",cve.title)
            if len(res)>0:
                cve.id = res[0]
        return cve


