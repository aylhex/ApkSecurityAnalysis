#-*- coding:utf-8 -*-
__author__ = 'Andy'
import os
import shutil
import struct
import time
import tempfile

class UnzipAPK():

    def __init__(self, apkpath):
        #创建临时文件，在关闭的时候，系统会自动清除文件
        #self.unpackDir = tempfile.TemporaryFile()
        self.unpackDir = tempfile.mktemp()
        self.unzip(apkpath)
        #self.dexdump()
        #self.unpackxml()
        #self.deleteTmpDirs()


    # def getclassname(self):
    #     import codecs
    #     dexdump_str = codecs.open(self.unpackDir + '\\classes.txt', 'r', 'utf8').read()
    #     class_name_dict = {}
    #     buf_result = dexdump_str.split("Class #")
    #     for class_file in buf_result:
    #         try:
    #             class_code = class_file.split("\n")
    #             for smali in class_code:
    #                 if "  Class descriptor  :" in smali:
    #                       class_name = smali.split("'")[1][1:-1].replace("/", ".")
    #                       class_name_dict[class_name] = ""
    #                       break
    #         except:
    #             pass
    #
    #     return class_name_dict

    def unpackxml(self):
        cmd = "java -jar tools\\AXMLPrinter2.jar %s > %s"
        xmlpath = os.path.join(self.unpackDir, "AndroidManifest.xml")
        if os.path.exists(xmlpath):
            try:
                os.system(cmd % (xmlpath, self.unpackDir + "\\AndroidManifest_unpack.xml"))
                #os.remove(xmlpath)
                self.xmlPath = self.unpackDir + "\\AndroidManifest_unpack.xml"
                xmlfile_object = open(self.xmlPath)
                #self.xml_content = xmlfile_object.read()
                #return xmlfile_object
                return xmlfile_object.read()
            except:
                pass
    # def unpackxml(self):
    #     xmlpath = os.path.join(self.unpackDir, "AndroidManifest.xml")
    #     if os.path.exists(xmlpath):
    #         try:
    #             xmlfile_object = open(xmlpath)
    #             #self.xml_content = xmlfile_object.read()
    #             #return xmlfile_object
    #             return xmlfile_object.read()
    #         except:
    #             pass
    def getxmlpath(self):
        return self.unpackDir + "\\AndroidManifest.xml"

    def getdexcontent(self):

        dexcontent = open(self.unpackDir + "\\classes.txt", 'r')
        return dexcontent

    # def getpackagename(self):
    #     fr = open(self.xmlPath, 'r')
    #     packagename = ""
    #     for line in fr:
    #         pos = line.find('package="')
    #         if pos > 0:
    #             packagename = line[pos+9:-1].strip('"')
    #     return packagename


    # def unzip(self):
    #     cmd = "tool\\7z.exe x %s -y -o%s *.dex AndroidManifest.xml lib META-INF assets"
    #     print cmd % (self.apkPath, self.unpackDir)
    #     os.system(cmd % (self.apkPath, self.unpackDir))

    def getactivity(self):
        # packagename = self.getpackagename()
        # xmlfile_object = open(self.xmlPath)
        # xml_content = xmlfile_object.read().split("<application")[1:]
        # info_list = xml_content[0].split("<activity")[1:]
        activity = {}
        # for tmp in info_list:
        #     activityinfo = ""
        #     tmp = tmp.split('android:name=')[1].replace('"', "")
        #     if tmp.split('\n\t\t')[0].startswith("."):
        #         activity[packagename + tmp.split('\n\t\t')[0]] = ""
        #     elif tmp.split('\n\t\t')[0].startswith(packagename):
        #         activity[tmp.split('\n\t\t')[0]] = ""
        #     else:
        #         activity[packagename + '.' + tmp.split('\n\t\t')[0]] = ""
        return activity

    def dexdump(self):
        cmd = 'tools\\dexdump.exe -d %s > %s'
        dexpath = os.path.join(self.unpackDir, "classes.dex")
        if os.path.exists(dexpath):
            os.system(cmd % (dexpath, self.unpackDir + "\\classes.txt"))


    # def getallname(self):
    #
    #     all_file_name = {}
    #     all_dir_name = {}
    #     for dirpath, dirnames, filenames in os.walk(self.unpackDir):
    #         for file in filenames:
    #             all_file_name[file] = ""
    #
    #         for dir in dirnames:
    #             all_dir_name[dir] = ""
    #
    #     return all_file_name, all_dir_name

    def unzip(self, apkpath):
        cmd = "tools\\7z.exe x %s -y -o%s *.dex AndroidManifest.xml lib META-INF assets"
        #cmd = "tools\\apktool.jar d %s %s "
        print cmd % (apkpath, self.unpackDir)
        # os.system(cmd % (apkpath, self.unpackDir))
        try:
            os.system(cmd % (apkpath, self.unpackDir))
        except Exception, e:
            self.deleteTmpDirs()
            print e

    def deleteTmpDirs(self):
        shutil.rmtree(self.unpackDir)


# if __name__ == "__main__":
#     apkpath = r"g:\sample\XRAY-1.0.apk"
#     obj = UnzipAPK(apkpath)