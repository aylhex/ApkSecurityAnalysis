# coding:utf-8
__author__ = 'An'

from SaveResult import SaveResult
import sys
import os
import time
import hashlib
import uitls
from pyfiglet import Figlet
from MatchRule import MatchRule
from AnalysisXMLS.ManifestParser import GetMainfestBasicInfo
class GetAPKInfo():
    def __init__(self):
        #self.tempFile = tempfile.gettempdir()
        self.apks_info_dict = {}
        self.webview = {}
        self.logdict = {}
        self.allowallhostnameverifier = {}
        self.onreceivedsslerror = {}
        self.dexclassloader = {}
        self.https = {}

    def getSha1AndMd5(self, filepath):
        apk = open(filepath, 'rb').read()
        sha1_obj = hashlib.sha1()
        sha1_obj.update(apk)
        sha1 = sha1_obj.hexdigest()

        md5_obj = hashlib.md5()
        md5_obj.update(apk)
        md5 = md5_obj.hexdigest()
        return (sha1, md5)

    def getApkDetailInfo(self, apk_info, apk):
        basicinfo = GetMainfestBasicInfo(apk)
        apk_info_list = apk_info.readlines()
        apk_info_dict = {}
        package = ''
        for line in apk_info_list:

            if ('application-label' not in line) and ('versionCode' not in line):
                continue
            if 'versionCode' in line:
                package = line.strip().split('\'')[1]
                apk_info_dict['versioncode'] = line.strip().split('\'')[3]
                apk_info_dict['versionname'] = line.strip().split('\'')[5]
                #检测是否获取所有信息  提高效率
                if apk_info_dict.has_key('application'):
                    break
                continue

            if 'application-label' in line:
                apk_info_dict['application'] = line.split('\'')[1]
                if apk_info_dict.has_key('application'):
                    break
                continue
        apk_info_dict['apk'] = apk.split('\\')[-1]
        apk_sha1_md5 = self.getSha1AndMd5(apk)
        apk_info_dict['sha1'] = apk_sha1_md5[0]
        apk_info_dict['md5'] = apk_sha1_md5[1]

        apk_info_dict["文件大小"] = basicinfo.getSize() + " 字节"
        apk_info_dict["系统要求"] = basicinfo.getMinSdkVersion()
        apk_info_dict["序列号"] = basicinfo.getCertificateSN()
        apk_info_dict["发行者"] = basicinfo.getCertificateIDN()
        apk_info_dict["签发人"] = basicinfo.getCertificateSDN()
        apk_info_dict["ApkMd5"] = basicinfo.getApkMd5()
        apk_info_dict["DexMd5"] = basicinfo.getDexMd5()
        apk_info_dict["DexDigest"] = basicinfo.getDexDigest()
        apk_info_dict["ManifestDigest"] = basicinfo.getManifestDigest()
        apk_info_dict["测试建议"] = basicinfo.getRiskPermission()

        date = time.strftime('%Y/%m/%d/ %H:%M', time.localtime(time.time()))
        apk_info_dict['date'] = date

        self.apks_info_dict[package] = apk_info_dict

    def get_apk_info(self, path):
        '''
        Get apk info package, versioncode, versionname,
        application name, sha1, md5
        :return:apks_info_dict include above informations
        '''
        # info = os.popen(r"tools\aapt.exe d badging " + path)
        # self.getApkDetailInfo(info, path)
        try:
            info = os.popen(r"tools\aapt.exe d badging " + path)
            self.getApkDetailInfo(info, path)
            #break
        except:

            print "Failed to get Apk information!"

    def source_analysis(self, path):
        apk, d, dx = uitls.AnalyzeAPK(path, decompiler="dad")
        source = MatchRule(d, dx)
        source.webview_audit()
        source.log_audit()
        source.https_audit()
        source.allowallhostnameverifier_audit()
        source.dexclassloader_audit()
        source.onreceivedsslerror_audit()

        self.webview = source.get_webview_res()
        self.logdict = source.get_logs()
        self.allowallhostnameverifier = source.get_allowallhostnameverifier()
        self.dexclassloader = source.get_dexclassloader()
        self.onreceivedsslerror = source.get_onreceivedsslerror()
        self.https = source.get_https()


    def saveResult(self, path):
        obj = SaveResult(path)
        obj.saveBasicInfo(self.apks_info_dict)
        #清空上次数据
        self.apks_info_dict = {}
        obj.saveAttackSurface(path)
        obj.SourceVulnerability(self.webview, self.logdict, self.https, self.allowallhostnameverifier, self.dexclassloader, self.onreceivedsslerror)
        obj.Close()



    def start(self, path):
        try:
            self.get_apk_info(path)
            self.source_analysis(path)
            self.saveResult(path)
        except:
            error_result = open("ERROR.txt", 'a')
            error_result.write(path+" 解析失败\n")
            print path +" 解析失败"
            error_result.close()



if __name__ == "__main__":
    f = Figlet(font='colossal')
    print f.renderText('A N D Y')
    choice = 0
    path_list = []
    obj = GetAPKInfo()

    while True:
        try:
            '''Do you want to examine:
            [1] APK
            [2] Source'''
            print str('Do you want to examine:\n[1] APK\n[2] APKS\n[3] QUIT\n').decode('string-escape').format()
            choice = str(raw_input('Enter your choice:')).strip()
            if int(choice) in (1, 2):
                break
            if int(choice) == 3:
                exit()
        except Exception as e:
            print e

    if int(choice) == 1:
        print str('Please enter the full path to your APK (ex. g:\sample\sample.apk):').decode('string-escape').format()
        apkPath = str(raw_input('Path:')).strip()
        obj.start(apkPath)
    elif int(choice) == 2:
        print str('Please enter the full path to your APK (ex. g:\sample):').decode('string-escape').format()
        apkPath = str(raw_input('Path:')).strip()

        for rt, dirs, files in os.walk(apkPath):
            for f in files:
                if f.endswith(".apk"):
                    path_list.append(os.path.join(rt, f))
        for path in path_list:
            obj.start(path)


