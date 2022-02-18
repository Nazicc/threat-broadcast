#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/12/01 23:21
# @File   : cnvd.py
# -----------------------------------------------
# cnvd: https://www.cnvd.org.cn/
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils import log
import requests
from requests.utils import add_dict_to_cookiejar
import execjs
import hashlib
import json
import re
import time


class CNVD(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '国家信息安全漏洞共享平台（CNVD）'
        self.name_en = 'CNVD'
        self.home_page = 'https://www.cnvd.org.cn/'
        self.url_list = 'https://www.cnvd.org.cn/flaw/list?flag=true'
        self.url_cve = 'https://www.cnvd.org.cn/flaw/show/'
        self.header = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
        }
        self.session = requests.session()
        self._set_cookie()


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    # CNVD 采用加速乐反爬机制
    # 破解方式参考：
    #    两次 JS 动态混淆反爬虫策略导致的 521 响应码，如果破？：https://blog.csdn.net/wojiushiwo945you/article/details/110952579
    #    爬虫CNVD构建漏洞库：https://blog.csdn.net/weixin_40502018/article/details/112581719?share_token=236ffb43-0fe7-4d2e-b3e9-0f0163f62558
    def _set_cookie(self):
        response1 = self.session.get(self.home_page,headers=self.header)
        jsl_clearance_s = re.findall(r'cookie=(.*?);location', response1.text)[0]
        jsl_clearance_s = str(execjs.eval(jsl_clearance_s)).split('=')[1].split(';')[0]
        add_dict_to_cookiejar(self.session.cookies, {'__jsl_clearance_s': jsl_clearance_s})
        response2 = self.session.get(self.home_page,headers=self.header)
        data = json.loads(re.findall(r';go\((.*?)\)', response2.text)[0])
        jsl_clearance_s = self._get__jsl_clearance_s(data)
        add_dict_to_cookiejar(self.session.cookies, {'__jsl_clearance_s': jsl_clearance_s})


    def _get__jsl_clearance_s(self, data):
        chars = len(data['chars'])
        for i in range(chars):
            for j in range(chars):
                clearance = data['bts'][0] + data['chars'][i] + data['chars'][j] + data['bts'][1]
                encrypt = None
                if data['ha'] == 'md5':
                    encrypt = hashlib.md5()
                elif data['ha'] == 'sha1':
                    encrypt = hashlib.sha1()
                elif data['ha'] == 'sha256':
                    encrypt = hashlib.sha256()
                encrypt.update(clearance.encode())
                result = encrypt.hexdigest()
                if result == data['ct']:
                    return clearance


    def get_cves(self, limit = 6):
        # data = {
        #     "number":"请输入精确编号",
        #     "startDate":"2022-02-18",
        #     "endDate":"2022-02-18",
        #     "flag":"true",
        #     "field":"",
        #     "order":"",
        #     "serverity":18,
        #     "numPerPage":30,
        #     "offset":10,
        #     "max":30
        # }
        # data = {
        #     "keyword": "",
        #     "condition": 1,
        #     "keywordFlag": 0,
        #     "cnvdId": "",
        #     "cnvdIdFlag": 0,
        #     "baseinfoBeanbeginTime": "2022 - 02 - 18",
        #     "baseinfoBeanendTime": "2022 - 02 - 18",
        #     "baseinfoBeanFlag": 0,
        #     "refenceInfo": "",
        #     "referenceScope": -1,
        #     "manufacturerId": -1,
        #     "categoryId": -1,
        #     "editionId": -1,
        #     "serverity": 18,
        #     "causeIdStr": "",
        #     "threadIdStr": "",
        #     "serverityIdStr": 18,
        #     "positionIdStr": ""
        # }
        response = self.session.get(
            self.url_list,
            timeout = self.timeout,
            headers = self.header
        )
        response.encoding = 'utf-8'
        cves = []
        if response.status_code == 200:
            ids = re.findall(r'\thref="/flaw/show/([^"]+)"', response.text)
            for id in ids :
                cve = self.to_cve(id)
                if cve.is_vaild():
                    cves.append(cve)
                    # log.debug(cve)
        else:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
        return cves


    def to_cve(self, id):
        cve = CVEInfo()
        cve.id = id
        cve.src = self.NAME_CH()
        cve.url = self.url_cve + id
        self.get_cve_info(cve, cve.url)
        return cve


    def get_cve_info(self, cve, url) :
        try :
            response = self.session.get(
                url,
                timeout = self.timeout,
                headers=self.header
            )
            time.sleep(1)
            response.encoding = 'utf-8'

            if response.status_code == 200:
                _title = re.findall(r'>(.*?)</h1>', response.text)[0].strip()
                cve.title = re.sub(r'（CNVD-\d+-\d+）', '', _title).strip()
                kvs = re.findall(r'<td class="alignRight">(.*?)</td>.*?<td>(.*?)</td>', response.text, re.DOTALL)
                for kv in kvs :
                    key = kv[0].replace('\t', '').strip()
                    val = kv[1].replace('\t', '').strip()
                    
                    if key == 'CVE ID' :
                        id = re.findall(r'>(.*?)</a>', val)[0].strip()
                        cve.id = "%s (%s)" % (cve.id, id)

                    elif key == '公开日期' :
                        cve.time = val + time.strftime(" %H:%M:%S", time.localtime())

                    elif key == '漏洞描述' :
                        cve.info = val.replace('\r', '').replace('\n', '').replace('<br/>', '')
        except :
            pass  # 漏洞信息页面不存在

        time.sleep(1)
