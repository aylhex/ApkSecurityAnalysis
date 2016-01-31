# -*- coding:utf-8 -*-
import os
import zipfile
from hashlib import md5, sha1, sha256
from base64 import b64encode
from platform import system, architecture
from xml.dom import minidom

from core import extraTools
from androguard.core.bytecodes import apk
from androguard.core.bytecodes.dvm import *
from androguard.core.analysis.analysis import *



TOOLS = extraTools.myTools()
SYS = system()

if SYS == "Darwin":
    from core.chilkatCert.mac import chilkat
if SYS == "Windows":
    if architecture()[0] == "32bit":
        from core.chilkatCert.win32 import chilkat
    elif architecture()[0] == "64bit":
        from core.chilkatCert.win64 import chilkat

CHILKATKEY = "ZIP87654321_135D44EDpH3I"


def GetZipFileChilkat(filename, OPT, savePath):
    zip = chilkat.CkZip()
    zip.UnlockComponent(CHILKATKEY)
    success = zip.OpenZip(filename)
    n = zip.get_NumEntries()

    for i in range(0, n):
        entry = zip.GetEntryByIndex(i)
        if re.compile(OPT).search(entry.fileName()):
            entry.ExtractInto(savePath)


def GetZipFile(filename, OPT, savePath):
    try:
        f = zipfile.ZipFile(filename, 'r')
        for i in f.namelist():
            if OPT in i:
                f.extract(i, savePath)
    except Exception, e:
        print e


MIN_SDK_VERSION = {
    "1": "Android 1.0",
    "2": "Android 1.1",
    "3": "Android 1.5",
    "4": "Android 1.6",
    "5": "Android 2.0",
    "6": "Android 2.0.1",
    "7": "Android 2.1-update1",
    "8": "Android 2.2",
    "9": "Android 2.3 - 2.3.2",
    "10": "Android 2.3.3 - 2.3.4",
    "11": "Android 3.0",
    "12": "Android 3.1",
    "13": "Android 3.2",
    "14": "Android 4.0.0 - 4.0.2",
    "15": "Android 4.0.3 - 4.0.4",
    "16": "Android 4.1 - 4.1.x",
    "17": "Android 4.2 - 4.2.x",
    "18": "Android 4.3 - 4.3.x",
    "19": "Android 4.4 - 4.4.4",
    "21": "Android 5.0",
    "22": "Android 5.1",
}

RISK_PERMISSION = {
    "android.permission.SEND_SMS": "可无提示直接发送短信",
    "android.permission.RECEIVE_SMS": "可监控短信接收",
    "android.permission.CALL_PRIVILEGED": "可无提示直接拨打电话",
    "android.permission.INTERNET": "具有完全的互联网访问权限",
    "android.permission.READ_CONTACTS": "可读取联系人信息",
    "android.permission.WRITE_CONTACTS": "可修改联系人信息",
    "android.permission.CHANGE_WIFI_STATE": "可修改设备当前WIFI设置",
    "android.permission.WRITE_EXTERNAL_STORAGE": "可对存储卡进行读写操作",
    "com.android.launcher.permission.INSTALL_SHORTCUT": "可创建程序快捷方式",
    "android.permission.READ_PHONE_STATE": "可读取设备状态和身份",
    "android.permission.INSTALL_PACKAGES": "可安装其它程序",
    "android.permission.READ_SMS": "读取短信或彩信",
    "android.permission.WRITE_SMS": "编辑短信或彩信",
    "android.permission.RESTART_PACKAGES": "重启应用程序",
    "android.permission.CALL_PHONE": "直接拨打电话",
    "android.permission.ACCESS_COARSE_LOCATION": "可获取当前粗略位置信息",
    "android.permission.ACCESS_FINE_LOCATION": "可获取当前精确位置信息",
    "android.permission.ACCESS_CHECKIN_PROPERTIES": "允许读写访问”properties”表在checkin数据库中，改值可以修改上传",
    "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS": "允许应用程序访问额外的位置提供命令",
    "android.permission.ACCESS_MOCK_LOCATION": "允许程序创建模拟位置提供用于测试",
    "android.permission.ACCESS_NETWORK_STATE": "允许程序访问有关GSM网络信息",
    "android.permission.ACCESS_SURFACE_FLINGER": "允许程序使用SurfaceFlinger底层特性",
    "android.permission.ACCESS_WIFI_STATE": "允许程序访问Wi-Fi网络状态信息",
    "android.permission.ADD_SYSTEM_SERVICE": "允许程序发布系统级服务",
    "android.permission.BATTERY_STATS": "允许程序更新设备电池统计信息",
    "android.permission.BLUETOOTH": "允许程序连接到已配对的蓝牙设备",
    "android.permission.BLUETOOTH_ADMIN": "允许程序发现和配对蓝牙设备",
    "android.permission.BRICK": "请求能够禁用设备",
    "android.permission.BROADCAST_PACKAGE_REMOVED": "允许程序广播一个提示消息在一个应用程序包已经移除后",
    "android.permission.BROADCAST_STICKY": "允许一个程序广播常用intents",
    "android.permission.CAMERA": "请求访问使用照相设备",
    "android.permission.CHANGE_COMPONENT_ENABLED_STATE": "允许一个程序是否改变一个组件或其他的启用或禁用",
    "android.permission.CHANGE_CONFIGURATION": "允许一个程序修改当前设置，如本地化",
    "android.permission.CHANGE_NETWORK_STATE": "允许程序改变网络连接状态",
    "android.permission.CLEAR_APP_CACHE": "允许一个程序清楚缓存从所有安装的程序在设备中",
    "android.permission.CLEAR_APP_USER_DATA": "允许一个程序清除用户设置",
    "android.permission.CONTROL_LOCATION_UPDATES": "允许启用禁止位置更新提示从无线模块",
    "android.permission.DELETE_CACHE_FILES": "允许程序删除缓存文件",
    "android.permission.DELETE_PACKAGES": "允许一个程序删除包",
    "android.permission.DEVICE_POWER": "允许访问底层电源管理",
    "android.permission.DIAGNOSTIC": "允许程序RW诊断资源",
    "android.permission.DISABLE_KEYGUARD": "允许程序禁用键盘锁",
    "android.permission.DUMP": "允许程序返回状态抓取信息从系统服务",
    "android.permission.EXPAND_STATUS_BAR": "允许一个程序扩展收缩在状态栏,android开发网提示应该是一个类似windows mobile中的托盘程序",
    "android.permission.FACTORY_TEST": "作为一个工厂测试程序，运行在root用户",
    "android.permission.FLASHLIGHT": "访问闪光灯,android开发网提示htc Dream不包含闪光灯",
    "android.permission.FORCE_BACK": "允许程序强行一个后退操作是否在顶层activities",
    "android.permission.FOTA_UPDATE": "暂时不了解这是做什么使用的，android开发网分析可能是一个预留权限.",
    "android.permission.GET_ACCOUNTS": "访问一个帐户列表在Accounts Service中",
    "android.permission.GET_PACKAGE_SIZE": "允许一个程序获取任何package占用空间容量",
    "android.permission.GET_TASKS": "允许一个程序获取信息有关当前或最近运行的任务，一个缩略的任务状态，是否活动等等",
    "android.permission.HARDWARE_TEST": "允许访问硬件",
    "android.permission.INJECT_EVENTS": "允许一个程序截获用户事件如按键、触摸、轨迹球等等到一个时间流，android 开发网提醒算是hook技术吧",
    "android.permission.INTERNAL_SYSTEM_WINDOW": "允许打开窗口使用系统用户界面",
    "android.permission.MANAGE_APP_TOKENS": "允许程序管理",
    "android.permission.MASTER_CLEAR ": "目前还没有明确的解释，android开发网分析可能是清除一切数据，类似硬格机",
    "android.permission.MODIFY_AUDIO_SETTINGS": "允许程序修改全局音频设置",
    "android.permission.MODIFY_PHONE_STATE": "允许修改话机状态，如电源，人机接口等",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": "允许挂载和反挂载文件系统可移动存储",
    "android.permission.PERSISTENT_ACTIVITY": "允许一个程序设置他的activities显示",
    "android.permission.PROCESS_OUTGOING_CALLS": "允许程序监视、修改有关播出电话",
    "android.permission.READ_CALENDAR": "允许程序读取用户日历数据",
    "android.permission.READ_FRAME_BUFFER": "允许程序屏幕波或和更多常规的访问帧缓冲数据",
    "android.permission.READ_INPUT_STATE": "允许程序返回当前按键状态",
    "android.permission.READ_LOGS": "允许程序读取底层系统日志文件",
    "android.permission.READ_OWNER_DATA": "允许程序读取所有者数据",
    "android.permission.READ_SYNC_SETTINGS": "允许程序读取同步设置",
    "android.permission.READ_SYNC_STATS": "允许程序读取同步状态",
    "android.permission.REBOOT": "请求能够重新启动设备",
    "android.permission.RECEIVE_BOOT_COMPLETED": "允许一个程序接收到 ACTION_BOOT_COMPLETED广播在系统完成启动",
    "android.permission.RECEIVE_MMS": "允许一个程序监控将收到MMS彩信,记录或处理",
    "android.permission.RECEIVE_WAP_PUSH": "允许程序监控将收到WAP PUSH信息",
    "android.permission.RECORD_AUDIO": "允许程序录制音频",
    "android.permission.REORDER_TASKS": "允许程序改变Z轴排列任务",
    "android.permission.SET_ACTIVITY_WATCHER": "允许程序监控或控制activities",
    "android.permission.SET_ALWAYS_FINISH": "允许程序控制是否活动间接完成在处于后台时",
    "android.permission.SET_ANIMATION_SCALE": "修改全局信息比例",
    "android.permission.SET_DEBUG_APP": "配置一个程序用于调试",
    "android.permission.SET_ORIENTATION": "允许底层访问设置屏幕方向和实际旋转",
    "android.permission.SET_PREFERRED_APPLICATIONS": "允许一个程序修改列表参数PackageManager.addPackageToPreferred 和PackageManager.removePackageFromPreferred方法",
    "android.permission.SET_PROCESS_FOREGROUND": "允许程序当前运行程序强行到前台",
    "android.permission.SET_PROCESS_LIMIT": "允许设置最大的运行进程数量",
    "android.permission.SET_TIME_ZONE": "允许程序设置时间区域",
    "android.permission.SET_WALLPAPER": "允许程序设置壁纸",
    "android.permission.SET_WALLPAPER_HINTS": "允许程序设置壁纸hits",
    "android.permission.SIGNAL_PERSISTENT_PROCESSES": "允许程序请求发送信号到所有显示的进程中",
    "android.permission.STATUS_BAR": "允许程序打开、关闭或禁用状态栏及图标",
    "android.permission.SUBSCRIBED_FEEDS_READ": "允许一个程序访问订阅RSS Feed内容提供",
    "android.permission.SUBSCRIBED_FEEDS_WRITE": "系统暂时保留改设置,android开发网认为未来版本会加入该功能。",
    "android.permission.SYSTEM_ALERT_WINDOW": "允许一个程序打开窗口使用 TYPE_SYSTEM_ALERT，显示在其他所有程序的顶层",
    "android.permission.VIBRATE": "允许访问振动设备",
    "android.permission.WAKE_LOCK": "允许使用PowerManager的 WakeLocks保持进程在休眠时从屏幕消失",
    "android.permission.WRITE_APN_SETTINGS": "允许程序写入API设置",
    "android.permission.WRITE_CALENDAR": "允许一个程序写入但不读取用户日历数据",
    "android.permission.WRITE_GSERVICES": "允许程序修改Google服务地图",
    "android.permission.WRITE_OWNER_DATA": "允许一个程序写入但不读取所有者数据",
    "android.permission.WRITE_SETTINGS": "允许程序读取或写入系统设置",
    "android.permission+A1:A95.WRITE_SYNC_SETTINGS": "允许程序写入同步设置"
}




class GetMainfestBasicInfo(apk.APK):
    # print a.get_android_manifest_axml().get_xml() #获取xml

    def getSize(self):
        return str(os.path.getsize(self.get_filename()))

    def getMd5(self, filename):
        return md5(open(filename, "rb").read()).hexdigest()

    def getSha1(self, filename):
        return sha1(open(filename, "rb").read()).hexdigest()

    def getSha256(self, filename):
        return sha256(open(filename, "rb").read()).hexdigest()

    def getDigest(self, filename):
        return b64encode(sha1(open(filename, "rb").read()).digest())

    def getListMd5(self, f, OPT):
        return md5(f.read(OPT, "rb")).hexdigest()

    def getListSha1(self, f, OPT):
        return sha1(f.read(OPT, "rb")).hexdigest()

    def getListSha256(self, f, OPT):
        return sha256(f.read(OPT, "rb")).hexdigest()

    def getListDigest(self, f, OPT):
        return b64encode(sha1(f.read(OPT, "rb")).digest())

    def getApkMd5(self):
        return self.getMd5(self.get_filename())

    def getApkSha1(self):
        return self.getSha1(self.get_filename())

    def getApkSha256(self):
        return self.getSha256(self.get_filename())

    def getDexMd5(self):
        OPT = "classes.dex"
        f = zipfile.ZipFile(self.get_filename(), 'r')
        return self.getListMd5(f, OPT)

    def getDexSha1(self):
        OPT = "classes.dex"
        f = zipfile.ZipFile(self.get_filename(), 'r')
        return self.getListSha1(f, OPT)

    def getDexSha256(self):
        OPT = "classes.dex"
        f = zipfile.ZipFile(self.get_filename(), 'r')
        return self.getListSha256(f, OPT)

    def getDexDigest(self):
        OPT = "classes.dex"
        f = zipfile.ZipFile(self.get_filename(), 'r')
        return self.getListDigest(f, OPT)

    def getManifestDigest(self):
        OPT = "META-INF/MANIFEST.MF"
        f = zipfile.ZipFile(self.get_filename(), 'r')
        return self.getListDigest(f, OPT)

    def getMinSdkVersion(self):
        minSdk = self.get_element("uses-sdk", "android:minSdkVersion")
        if minSdk:
            try:
                return MIN_SDK_VERSION[minSdk]
            except KeyError:
                return minSdk
        else:
            return "None"

    def getPermission(self):
        for i in self.xml:
            x = []
            if not self.xml[i].getElementsByTagName('uses-permission'):
                return []
            else:
                for item in self.xml[i].getElementsByTagName('uses-permission'):
                    x.append(item.getAttribute("android:name"))

            if len(x) > 0:
                return x

    def getRiskPermission(self):
        x = []
        permission = self.getPermission()

        if len(permission) == 0:
            return ["该程序未发现含有权限"]
        else:
            for i in permission:
                # if RISK_PERMISSION[i] not in x:
                #     x.append(i + "\t" + RISK_PERMISSION[i])
                try:
                    if RISK_PERMISSION[i] not in x:

                        info = str(i) + " " + RISK_PERMISSION[i]
                        x.append(info)
                except KeyError:
                    pass

        if len(x) > 0:
            return x
        else:
            return ["该程序未发现含有风险权限"]

    def getLogPath(self):
        savePath, fileType = os.path.splitext(self.get_filename())
        return savePath.strip(" ") + ".txt"

    def getSavePath(self):
        savePath, fileType = os.path.splitext(self.get_filename())
        return savePath.strip(" ")
        # return TOOLS.temp()

    def getFilename(self):
        filePath, filename = os.path.split(self.get_filename())
        return filename[:-4].strip(" ")

    def getMetaInf(self):
        OPT = "^(META-INF/)(.*)(\.RSA|\.DSA)$"
        GetZipFileChilkat(self.get_filename(), OPT, self.getSavePath())

    def getManifest(self):

        for parent, dirNames, fileNames in os.walk(self.getSavePath()):
            for fileName in fileNames:
                fileType = os.path.splitext(os.path.join(parent, fileName))[1]
                if fileType == "MANIFEST.MF":
                    return os.path.join(parent, fileName)

    def getSa(self):

        for parent, dirNames, fileNames in os.walk(self.getSavePath()):
            for fileName in fileNames:
                fileType = os.path.splitext(os.path.join(parent, fileName))[1]
                if fileType == ".RSA" or fileType == ".DSA":
                    return os.path.join(parent, fileName)

    def getCert(self):
        cmd = 'java -jar ' + '\"' + TOOLS.cert() + '\"' + ' \"' + self.getSa() + '\"'
        return os.popen(cmd).readlines()

    def getCertSN(self):
        cmd = 'java -jar ' + '\"' + TOOLS.certSN() + '\"' + ' \"' + self.getSa() + '\"'
        return os.popen(cmd).readlines()

    def getCertIDN(self):
        cmd = 'java -jar ' + '\"' + TOOLS.certIDN() + '\"' + ' \"' + self.getSa() + '\"'
        return os.popen(cmd).readlines()

    def getCertSDN(self):
        cmd = 'java -jar ' + '\"' + TOOLS.certSDN() + '\"' + ' \"' + self.getSa() + '\"'
        return os.popen(cmd).readlines()

    def getChilkatCertSN(self):
        self.getMetaInf()
        sa = self.getSa()

        cert = chilkat.CkCert()
        success = cert.LoadFromFile(sa)

        if success:
            return cert.serialNumber()
        else:
            return None

    def getChilkatCertIDN(self):
        sa = self.getSa()

        cert = chilkat.CkCert()
        success = cert.LoadFromFile(sa)

        if success:
            return 'C=' + cert.issuerC() + ',CN=' + cert.issuerCN() + ',DN=' + cert.issuerDN() + \
                   ',E=' + cert.issuerE() + ',L=' + cert.issuerL() + ',O=' + cert.issuerO() + \
                   ',OU=' + cert.issuerOU() + ',S=' + cert.issuerS()
        else:
            return None

    def getChilkatCertSDN(self):
        sa = self.getSa()

        cert = chilkat.CkCert()
        success = cert.LoadFromFile(sa)

        if success:
            return 'C=' + cert.subjectC() + ',CN=' + cert.subjectCN() + ',DN=' + cert.subjectDN() + \
                   ',E=' + cert.subjectE() + ',L=' + cert.subjectL() + ',O=' + cert.subjectO() + \
                   ',OU=' + cert.subjectOU() + ',S=' + cert.subjectS()
        else:
            return None

    def get_obj_certificate(self, filename):
        cert = chilkat.CkCert()
        f = self.get_file(filename)
        bytedata = chilkat.CkByteData()
        bytedata.append2(f, len(f))
        success = cert.LoadFromBinary(bytedata)
        return success, cert

    def get_certificate_loader(self):
        OPT = "^(META-INF/)(.*)(\.RSA|\.DSA)$"
        for i in self.zip.namelist():
            if re.compile(OPT).search(i):
                success, cert = self.get_obj_certificate(i)

        return success, cert

    def getCertificateSN(self):
        success, cert = self.get_certificate_loader()

        if success:
            x = []
            c = cert.serialNumber()
            for i in c:
                x.append(i)

            if x[0] == x[1] == '0':
                x = x[2:]
                return ''.join(x).lower()
            else:
                return ''.join(x).lower()

    def getCertificateIDN(self):
        success, cert = self.get_certificate_loader()
        if success:
            return 'C=' + cert.issuerC() + ', CN=' + cert.issuerCN() + ', DN=' + cert.issuerDN() + \
                   ', E=' + cert.issuerE() + ', L=' + cert.issuerL() + ', O=' + cert.issuerO() + \
                   ', OU=' + cert.issuerOU() + ', S=' + cert.issuerS()
        else:
            return None

    def getCertificateSDN(self):
        success, cert = self.get_certificate_loader()
        if success:
            return 'C=' + cert.subjectC() + ', CN=' + cert.subjectCN() + ', DN=' + cert.subjectDN() + \
                   ', E=' + cert.subjectE() + ', L=' + cert.subjectL() + ', O=' + cert.subjectO() + \
                   ', OU=' + cert.subjectOU() + ', S=' + cert.subjectS()
        else:
            return None

    def get_my_app_icon(self):
        """
            android:icon="@drawable/icon"
        """
        fp = os.path.join(self.getSavePath(), "AndroidManifest.xml")
        try:
            doc = minidom.parse(fp).documentElement
        except:
            return None

        for node in doc.childNodes:
            if node.nodeType == node.ELEMENT_NODE:
                if node.getAttribute("android:icon"):
                    label = node.getAttribute("android:icon")
                    if label[:10] != "@drawable/":
                        return None
                    else:
                        iconname = label[10:] + ".png"
                        flag = False

                        # if os.path.isdir(os.path.join(self.get_my_filepath(), "res\\drawable\\")):
                        #     icon = os.path.join(self.get_my_filepath(), "res\\drawable\\" + iconname)
                        #     shutil.copy(icon, self.get_my_filepath())
                        # elif os.path.isdir(os.path.join(self.get_my_filepath(), "res\\drawable-mdpi\\")):
                        #     icon = os.path.join(self.get_my_filepath(), "res\\drawable-mdpi\\" + iconname)
                        #     shutil.copy(icon, self.get_my_filepath())
                        # else: return 111111111111

    def getAppName(self):
        print self.get_android_resources()

    def get_my_node_date(self, fp, nodevalue):
        doc = minidom.parse(fp)
        for i in doc.getElementsByTagName("string"):
            if i.getAttribute("name") == nodevalue:
                return i.firstChild.toxml()

    def get_my_app_name_new(self):
        key = "title"
        a = self.get_android_resources()
        # print a.get_string(a.get_packages_names()[0], key)[1].decode().encode('utf8')
        print 1
        # print a.get_strings_resources()
        # print a.get_packages_names()
        s = a.get_string(a.get_packages_names()[0], key)
        print s
        # print chardet.detect(s)
        # print s.decode('ascii').encode('ascii'
        # print s.decode('ascii').encode('utf-8')
        print isinstance(s, unicode)
        print isinstance(key, unicode)
        print s
        detaillfile = open("C:\\Users\\iWork\\Desktop\\simpleApk\\detail.txt", "w")
        detaillfile.write(s)
        detaillfile.close()
        print 2
        # print sys.getdefaultencoding()
        for i in a.get_string(a.get_packages_names()[0], key):
            print len(i)
            print i
            # print  str(i).decode("utf-8")

    def get_my_app_name(self):
        #=======================================================================
        # key = "app_name"
        # a = self.get_android_resources()
        #  return a.get_string(a.get_packages_names()[0], key)[1]
        #=======================================================================
        """

        """
        fp = os.path.join(self.get_my_filepath(), "AndroidManifest.xml")
        valueszh = os.path.join(self.get_my_filepath(), "res\\values-zh\\strings.xml")
        values = os.path.join(self.get_my_filepath(), "res\\values\\strings.xml")
        try:
            doc = minidom.parse(fp).documentElement
        except:
            return None

        for node in doc.childNodes:
            if node.nodeType == node.ELEMENT_NODE:
                """
                if "@string/" not in node.getAttribute("android:label"):
                    return node.getAttribute("android:label")
                """
                if node.getAttribute("android:label"):
                    label = node.getAttribute("android:label")
                    if label[:8] != "@string/":
                        return label
                    else:
                    # if "@string/" in node.getAttribute("android:label"):
                    #     label = node.getAttribute("android:label")
                        try:
                            return self.get_my_node_date(values, label[8:])
                        except:
                            try:
                                return self.get_my_node_date(valueszh, label[8:])
                            except:
                                return None
