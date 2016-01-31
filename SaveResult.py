# coding:utf-8
__author__ = 'An'

from AnalysisXML import Xml
from platform import system, architecture

def separator(OPT):
    '''设置标题'''
    value = "=" * 55 + "\n" + OPT + "\n" + "=" * 55 + "\n"
    return value

class SaveResult():
    def __init__(self, path):
        #file_name = path.split("\\")[-1]
        #self.file_result = open(r"g:\APK\result\\"+ file_name + r".txt", 'w')
        self.file_result = open(path.replace(".apk", '') + r".txt", 'w')
        #self.tempFile = tempfile.gettempdir()
        self.apks_info_dict = {}

    # def getLog(log, flag, val):
    #     SYS = system()
    #     if SYS == "Darwin":
    #         print str(flag) + str(val)
    #     if SYS == "Windows":
    #         print str(flag).decode('utf-8', 'ignore').encode('cp936', 'ignore') + str(val).decode('utf-8', 'ignore').encode('cp936', 'ignore')
    #
    #     log.write(str(flag))
    #     log.write(str(val) + '\n')
    #     log.flush()


    def saveBasicInfo(self, apks_info_dict):

        for (key, value) in apks_info_dict.items():

            self.file_result.write(separator('基本信息'))
            self.file_result.write('检测日期:\t' + value['date'] + '\n')
            self.file_result.write('APK 文件:\t' + value['apk'] + '\n')
            self.file_result.write('软件名称:\t' + value['application'] + '\n')
            self.file_result.write('软件包名:\t' + key + '\n')
            self.file_result.write('版    本:\t' + value['versionname'] + '\n')
            self.file_result.write('版 本 号:\t' + value['versioncode'] + '\n')
            self.file_result.write('系统要求:\t' + value['系统要求'] + '\n')
            self.file_result.write('序 列 号:\t' + value['序列号'] + '\n')

            self.file_result.write("-" * 55 + '\n')
            self.file_result.write('ApkMd5:\t' + value['md5'] + '\n')
            self.file_result.write('SHA1:\t' + value['sha1'] + '\n')
            self.file_result.write('DexMd5:\t' + value['DexMd5'] + '\n')
            self.file_result.write('DexDigest:\t' + value['DexDigest'] + '\n')
            self.file_result.write('ManifestDigest:\t' + value['ManifestDigest'] + '\n')
            self.file_result.write("-" * 55 + '\n\n')

            self.file_result.write(separator('敏感权限'))
            [self.file_result.write("\t" + i +"\n") for i in value['测试建议']]

            self.file_result.write('\n')

    def saveAttackSurface(self, path):
        obj = Xml(path)
        activities_dict = obj.get_activities()
        services_dict = obj.get_services()
        receivers_dict = obj.get_receivers()
        providers_dict = obj.get_providers()
        configuration_dict = obj.get_configuration()

        activity_list = []
        services_list = []
        receivers_list = []
        providers_list = []

        for (key, value) in activities_dict.items():
            if value == "true":
                activity_list.append(key)

        for (key, value) in services_dict.items():
            if value == "true":
                services_list.append(key)

        for (key, value) in receivers_dict.items():
            if value == "true":
                receivers_list.append(key)

        for (key, value) in providers_dict.items():
            if value == "true":
                providers_list.append(key)


        self.file_result.write(separator('关键配置Configuration'))

        if configuration_dict["debuggable"] == "true":
            self.file_result.write('debuggable:\t' + "存在风险，应用程序可被任意调试" + '\n')
        elif configuration_dict["debuggable"] == "false":
            self.file_result.write('debuggable:\t' + "安全" + '\n')

        if configuration_dict["allowBackup"] == "true":
            self.file_result.write('allowBackup:\t' + "存在风险，应用程序数据可以备份和恢复" + '\n')
        elif configuration_dict["allowBackup"] == "false":
            self.file_result.write('allowBackup:\t' + "安全" + '\n')

        if len(activity_list) != 0:
            self.file_result.write('activity:\t' + "存在风险，Activity组件暴露" + '\n')
        elif len(activity_list) == 0:
            self.file_result.write('activity:\t' + "安全" + '\n')

        if len(services_list) != 0:
            self.file_result.write('service:\t' + "存在风险，Service组件暴露" + '\n')
        elif len(services_list) == 0:
            self.file_result.write('service:\t' + "安全" + '\n')

        if len(receivers_list) != 0:
            self.file_result.write('receiver:\t' + "存在风险，BroadcastReceiver组件暴露"+ '\n')
        elif len(receivers_list) == 0:
            self.file_result.write('receiver:\t' + "安全" + '\n')

        if len(providers_list) != 0:
            self.file_result.write('provider:\t' + "存在风险，ContentProvider组件暴露"  + '\n\n')
        elif len(providers_list) == 0:
            self.file_result.write('provider:\t' + "安全" + '\n\n')

        self.file_result.write(separator('攻击入口Attacksurface'))
        self.file_result.write('Activity('+str(len(activity_list))+'):\n')
        for tmp in activity_list:
            self.file_result.write('\t' + tmp + '\n')
        self.file_result.write('\n')

        self.file_result.write('Service('+str(len(services_list))+'):\n')
        for tmp in services_list:
            self.file_result.write('\t' + tmp + '\n')
        self.file_result.write('\n')

        self.file_result.write('ContentProvider('+str(len(providers_list))+'):\n')
        for tmp in providers_list:
            self.file_result.write('\t' + tmp + '\n')
        self.file_result.write('\n')

        self.file_result.write('BroadcastReceiver('+str(len(receivers_list))+'):\n')
        for tmp in receivers_list:
            self.file_result.write('\t' + tmp + '\n')
        self.file_result.write('\n')


    def SourceVulnerability(self, webview, logdict, https, allowallhostnameverifier, dexclassloader, onreceivedsslerror):
        self.file_result.write(separator('安全漏洞Vulnerability'))

        self.file_result.write("################################ Webview组件远程代码执行漏洞 ######################################\n")
        if webview:
            for key in webview:
                self.file_result.write(key + '\n')
                self.file_result.write(webview[key] + '\n')
        else:
            self.file_result.write("None\n")
        self.file_result.write("\n")

        self.file_result.write("################################ HTTPS关闭主机名验证 ######################################\n")
        flag = 0
        if https:
            for key in https:
                if "SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER" in https[key]:
                    flag = 1
                    self.file_result.write(key + '\n')
                    self.file_result.write(https[key] + '\n')

        if allowallhostnameverifier:
            for key in allowallhostnameverifier:
                self.file_result.write(key + '\n')
                self.file_result.write(allowallhostnameverifier[key] + '\n')
        elif flag == 0:
            self.file_result.write("None\n")
        self.file_result.write("\n")

        self.file_result.write("################################ Dex文件动态加载风险 ######################################\n")
        if dexclassloader:
            for key in dexclassloader:
                self.file_result.write(key + '\n')
                self.file_result.write(dexclassloader[key] + '\n')
        else:
            self.file_result.write("None\n")
        self.file_result.write("\n")

        self.file_result.write("################################ WebView忽略SSL证书错误 ######################################\n")
        if onreceivedsslerror:
            for key in onreceivedsslerror:
                self.file_result.write(key + '\n')
                self.file_result.write(onreceivedsslerror[key] + '\n')
        else:
            self.file_result.write("None\n")
        self.file_result.write("\n")

        self.file_result.write(separator('安全编码提醒Warning'))
        self.file_result.write("################################ logcat可能泄露程序隐私信息和敏感信息 ######################################\n")
        if logdict:
            for key in logdict:
                self.file_result.write(key + '\n')
                self.file_result.write(logdict[key] + '\n')
        else:
            self.file_result.write("None\n")
        self.file_result.write("\n")


    def Close(self):
        self.file_result.close()


