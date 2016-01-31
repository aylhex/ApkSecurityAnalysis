# coding:utf-8
__author__ = 'Andy'
import re
import string
from UnzipAPK import UnzipAPK

class Xml():

    def __init__(self, path):
        #obj = UnzipAPK(r"g:\sample\com.snda.youni_181843.apk")
        obj = UnzipAPK(path)
        self.manifest_info = obj.unpackxml()
        self.packagename = ""
        self.minSdkVersion = 0

        #获取packagename、minSdkVersion
        self.get_manifest_info()

        obj.deleteTmpDirs()


    def get_manifest_info(self):
        """
        Get basic information about manifest;
        :return:versionCode, versionName, package,minSdkVersion, targetSdkVersion
        """
        infos = self.manifest_info.strip().split('>')[1]
        infos_list = []
        infos_dict = {}
        if '\n' in infos:
            infos_list = infos.split('\n')

        for line in infos_list:
            if 'versionCode' in line:
                infos_dict['versionCode'] = line.split('"')[1]
            if 'versionName' in line:
                infos_dict['versionName'] = line.split('"')[1]
            if 'package' in line:
                infos_dict['package'] = line.split('"')[1]
                self.packagename = line.split('"')[1]

        infos = self.manifest_info.strip().split('uses-sdk')[1].split('>')[0]
        infos_list = []
        if '\n' in infos:
            infos_list = infos.split('\n')


        for line in infos_list:
            if 'minSdkVersion' in line:
                infos_dict['minSdkVersion'] = line.split('"')[1]
                self.minSdkVersion = string.atoi(line.split('"')[1])
            if 'targetSdkVersion' in line:
                infos_dict['targetSdkVersion'] = line.split('"')[1]

        #print infos_dict
        return infos_dict

    def get_permission(self):
        """
        Get permission information about apk;
        :return:permission
        """

        regex = re.compile(r"<uses-permission[\s\S]*?>")
        regex_permission = re.compile(r"<permission[\s\S]*?>")

        user__permission = regex_permission.findall(self.manifest_info)
        permission = regex.findall(self.manifest_info)

        all_permission = user__permission + permission
        permission_list = []
        for tmp in all_permission:
            if 'android:name' in tmp:
                permission_list.append(tmp.split('"')[1].strip())
        permission_list = list(set(permission_list))
        #print permission_list
        return permission_list

    # def get_activities(self):
    #     """
    #     Get activitis information about apk;
    #     :return:permission
    #     """
    #     infos_list = self.manifest_info.strip().split('</activity>')
    #     activity_infos_dict = {}
    #     for info in infos_list:
    #         activity_info_dict = {}
    #         activity_name = ''
    #         if ('<activity' in info) and ('intent-filter' not in info):
    #             activity_info = info.strip().split('activity')[1].split('>')[0]
    #             info_list = []
    #             if '\n' in activity_info:
    #                 info_list = activity_info.split('\n')
    #             #获取的名字
    #             for info in info_list:
    #                 if 'android:name' in info:
    #                     activity_name = info.strip().split('"')[1]
    #                 if 'android:exported' in info:
    #                     exported_flag = info.strip().split('"')[1]
    #                     activity_info_dict['exported'] = exported_flag
    #             activity_infos_dict[activity_name] = activity_info_dict
    #
    #         if ('<activity' in info) and ('intent-filter' in info):
    #             activity_info = info.strip().split('activity')[1]
    #             info_list = []
    #             if '\n' in activity_info:
    #                 info_list = activity_info.split('\n')
    #             #获取的名字
    #             for info in info_list:
    #                 if 'android:name' in info:
    #                     activity_name = info.strip().split('"')[1]
    #                 if 'android:exported' in info:
    #                     exported_flag = info.strip().split('"')[1]
    #                     activity_info_dict['exported'] = exported_flag
    #                 if '>' in info:
    #                     break
    #
    #             info_list = []
    #             info_list = activity_info.split('</intent-filter>')
    #             action_name_list = []
    #             category_name_list = []
    #             for info in info_list:
    #                 if 'action' in info:
    #                     action_list = info.split('</action>')
    #                     for tmp in action_list:
    #                         if 'action' in tmp:
    #                             action_name = tmp.split('<action')[1].split('>')[0].split('"')[1]
    #                             action_name_list.append(action_name)
    #                 if 'category' in info:
    #                     category_list = info.split('</category>')
    #                     for tmp in category_list:
    #                         if 'category' in tmp:
    #                             category_name = tmp.split('<category')[1].split('>')[0].split('"')[1]
    #                             category_name_list.append(category_name)
    #
    #             action_name_list = list(set(action_name_list))
    #             category_name_list = list(set(category_name_list))
    #             activity_info_dict['action'] = action_name_list
    #             activity_info_dict['category'] = category_name_list
    #             activity_infos_dict[activity_name] = activity_info_dict
    #     print activity_infos_dict
    #     return activity_infos_dict

    def get_activities(self):
        """
        Get activitis information about apk;
        :return:permission
        """

        activity_infos_dict = {}

        regex = re.compile(r"<activity[\s\S]*?>[\s\S]*?</activity>")
        activities = regex.findall(self.manifest_info)

        regex_activity = re.compile(r'''<activity[\s\S]*?android:name="[\s\S]*?>''')
        regex_name = re.compile(r'''android:name="[\s\S]*?"''')
        regex_exported = re.compile(r'''android:exported="[\s\S]*?"''')

        for tmp in activities:
            flag = "false"
            activity = regex_activity.findall(tmp)
            export_flag = regex_exported.findall(activity[0])
            if len(export_flag) != 0:
                if "true" in export_flag[0].lower():
                    flag = "true"
            elif (len(export_flag) == 0) and ("intent-filter" in tmp):
                flag = "true"

            name = regex_name.findall(activity[0])[0]
            name = name.split('"')[1]

            if name.startswith("."):
                name = self.packagename + name
            #print name
            # if flag == "true":
            #     print name
            activity_infos_dict[name] = flag
        #print activity_infos_dict
        return activity_infos_dict
    # def get_services(self):
    #     """
    #     Get services information about apk;
    #     :return:services
    #     """
    #     infos_list = self.manifest_info.strip().split('</service>')
    #     service_infos_dict = {}
    #     for info in infos_list:
    #         service_info_dict = {}
    #         service_name = ''
    #         if ('<service' in info) and ('intent-filter' not in info):
    #             activity_info = info.strip().split('service')[1].split('>')[0]
    #             info_list = []
    #             if '\n' in activity_info:
    #                 info_list = activity_info.split('\n')
    #             #获取的名字
    #             for info in info_list:
    #                 if 'android:name' in info:
    #                     service_name = info.strip().split('"')[1]
    #                 if 'android:exported' in info:
    #                     exported_flag = info.strip().split('"')[1]
    #                     service_info_dict['exported'] = exported_flag
    #             service_infos_dict[service_name] = service_info_dict
    #
    #         if ('<service' in info) and ('intent-filter' in info):
    #             service_info = info.strip().split('service')[1]
    #             info_list = []
    #             if '\n' in service_info:
    #                 info_list = service_info.split('\n')
    #             #获取的名字
    #             for info in info_list:
    #                 if 'android:name' in info:
    #                     service_name = info.strip().split('"')[1]
    #                 if 'android:exported' in info:
    #                     exported_flag = info.strip().split('"')[1]
    #                     service_info_dict['exported'] = exported_flag
    #                 if '>' in info:
    #                     break
    #
    #             info_list = service_info.split('</intent-filter>')
    #             action_name_list = []
    #
    #             for info in info_list:
    #                 if 'action' in info:
    #                     action_list = info.split('</action>')
    #                     for tmp in action_list:
    #                         if 'action' in tmp:
    #                             action_name = tmp.split('<action')[1].split('>')[0].split('"')[1]
    #                             action_name_list.append(action_name)
    #
    #             action_name_list = list(set(action_name_list))
    #             service_info_dict['action'] = action_name_list
    #             service_infos_dict[service_name] = service_info_dict
    #
    #     print service_infos_dict
    #     return service_infos_dict

    def get_services(self):
        """
        Get services information about apk;
        :return:services
        """
        service_infos_dict = {}

        regex = re.compile(r"<service[\s\S]*?>[\s\S]*?</service>")
        services = regex.findall(self.manifest_info)

        regex_service = re.compile(r'''<service[\s\S]*?android:name="[\s\S]*?>''')
        regex_name = re.compile(r'''android:name="[\s\S]*?"''')
        regex_exported = re.compile(r'''android:exported="[\s\S]*?"''')

        for tmp in services:
            flag = "false"
            service = regex_service.findall(tmp)
            export_flag = regex_exported.findall(service[0])
            if len(export_flag) != 0:
                if "true" in export_flag[0].lower():
                    flag = "true"
            elif (len(export_flag) == 0) and ("intent-filter" in tmp):
                flag = "true"

            name = regex_name.findall(service[0])[0]
            name = name.split('"')[1]

            if name.startswith("."):
                name = self.packagename + name
            #print name
            # if flag == "true":
            #     print name
            service_infos_dict[name] = flag
        #print service_infos_dict
        return service_infos_dict

    # def get_receivers(self):
    #     """
    #     Get receivers information about apk;
    #     :return:receivers
    #     """
    #     infos_list = self.manifest_info.strip().split('</receiver>')
    #     receivers_infos_dict = {}
    #     for info in infos_list:
    #         receiver_info_dict = {}
    #         receiver_name = ''
    #         if ('<receiver' in info) and ('intent-filter' not in info):
    #             receiver_info = info.strip().split('receiver')[1].split('>')[0]
    #             info_list = []
    #             if '\n' in receiver_info:
    #                 info_list = receiver_info.split('\n')
    #             #获取的名字
    #             for info in info_list:
    #                 if 'android:name' in info:
    #                     receiver_name = info.strip().split('"')[1]
    #                 if 'android:exported' in info:
    #                     exported_flag = info.strip().split('"')[1]
    #                     receiver_info_dict['exported'] = exported_flag
    #             receivers_infos_dict[receiver_name] = receiver_info_dict
    #
    #         if ('<receiver' in info) and ('intent-filter' in info):
    #             if 'com.tencent.mm.booter.MountReceiver' in info:
    #                 print 'com.tencent.mm.booter.MountReceiver'
    #             receiver_info = info.strip().split('receiver')[1]
    #             info_list = []
    #             if '\n' in receiver_info:
    #                 info_list = receiver_info.split('\n')
    #             #获取的名字
    #             for info in info_list:
    #                 if 'android:name' in info:
    #                     receiver_name = info.strip().split('"')[1]
    #                 if 'android:exported' in info:
    #                     exported_flag = info.strip().split('"')[1]
    #                     receiver_info_dict['exported'] = exported_flag
    #                 if '>' in info:
    #                     break
    #
    #             info_list = receiver_info.split('</intent-filter>')
    #             action_name_list = []
    #             category_name_list = []
    #             for info in info_list:
    #                 if 'action' in info:
    #                     action_list = info.split('</action>')
    #                     for tmp in action_list:
    #                         if 'action' in tmp:
    #                             action_name = tmp.split('<action')[1].split('>')[0].split('"')[1]
    #                             action_name_list.append(action_name)
    #                 if 'category' in info:
    #                     category_list = info.split('</category>')
    #                     for tmp in category_list:
    #                         if 'category' in tmp:
    #                             category_name = tmp.split('<category')[1].split('>')[0].split('"')[1]
    #                             category_name_list.append(category_name)
    #
    #             action_name_list = list(set(action_name_list))
    #             category_name_list = list(set(category_name_list))
    #             receiver_info_dict['action'] = action_name_list
    #             receiver_info_dict['category'] = category_name_list
    #             receivers_infos_dict[receiver_name] = receiver_info_dict
    #     print receiver_info_dict
    #     return receivers_infos_dict

    def get_receivers(self):
        """
        Get receivers information about apk;
        :return:receivers
        """
        receivers_infos_dict = {}

        regex = re.compile(r"<receiver[\s\S]*?>[\s\S]*?</receiver>")
        receivers = regex.findall(self.manifest_info)

        regex_receiver = re.compile(r'''<receiver[\s\S]*?android:name="[\s\S]*?>''')
        regex_name = re.compile(r'''android:name="[\s\S]*?"''')
        regex_exported = re.compile(r'''android:exported="[\s\S]*?"''')

        for tmp in receivers:
            flag = "false"
            receiver = regex_receiver.findall(tmp)
            export_flag = regex_exported.findall(receiver[0])
            if len(export_flag) != 0:
                if "true" in export_flag[0].lower():
                    flag = "true"
            elif (len(export_flag) == 0) and ("intent-filter" in tmp):
                flag = "true"

            name = regex_name.findall(receiver[0])[0]
            name = name.split('"')[1]

            if name.startswith("."):
                name = self.packagename + name
            # if flag == "true":
            #     print name
            receivers_infos_dict[name] = flag

        #print receivers_infos_dict
        return receivers_infos_dict

    def get_providers(self):
        """
        Get providers information about apk;
        :return:receivers
        """

        providers_infos_dict = {}

        regex = re.compile(r"<provider[\s\S]*?>[\s\S]*?</provider>")
        providers = regex.findall(self.manifest_info)

        regex_receiver = re.compile(r'''<provider[\s\S]*?android:name="[\s\S]*?>''')
        regex_name = re.compile(r'''android:name="[\s\S]*?"''')
        regex_exported = re.compile(r'''android:exported="[\s\S]*?"''')

        for tmp in providers:
            flag = "false"
            provider = regex_receiver.findall(tmp)
            export_flag = regex_exported.findall(provider[0])
            if len(export_flag) != 0:
                if "true" in export_flag[0].lower():
                    flag = "true"
            elif (len(export_flag) == 0) and ("intent-filter" in tmp):
                flag = "true"
            elif (len(export_flag) == 0) and (self.minSdkVersion <= 16):
                flag = "true"
            elif (len(export_flag) == 0) and (self.minSdkVersion >= 17):
                flag = "false"

            name = regex_name.findall(provider[0])[0]
            name = name.split('"')[1]

            if name.startswith("."):
                name = self.packagename + name

            # if flag == "true":
            #     print name

            providers_infos_dict[name] = flag

        #print providers_infos_dict
        return providers_infos_dict
    # def get_configuration(self):
    #     infos = self.manifest_info.strip().split('<application')[1].split('>')[0]
    #     configuration_info = {}
    #     infos_list = []
    #     if '\n' in infos:
    #         infos_list = infos.split('\n')
    #     for line in infos_list:
    #         #AndroidManifest.xml文件中配置allowBackup标志(默认为true)
    #         if 'allowBackup' in line:
    #             configuration_info['allowBackup'] = line.split('"')[1]
    #         if 'debuggable' in line:
    #             configuration_info['debuggable'] = line.split('"')[1]
    #     print configuration_info
    #     return configuration_info

    def get_configuration(self):
        configuration_info = {}
        regex = re.compile(r"<application[\s\S]*?>")
        regex_allowbackup = re.compile(r'''android:allowBackup="[\s\S]*?"''')
        regex_debuggable = re.compile(r'''android:debuggable="[\s\S]*?"''')
        configuration = regex.findall(self.manifest_info)

        if len(configuration) != 0:
            allowbackup = regex_allowbackup.findall(configuration[0])
            debuggable = regex_debuggable.findall(configuration[0])

            if len(allowbackup) == 0:
                #AndroidManifest.xml文件中配置allowBackup标志(默认为true)
                configuration_info['allowBackup'] = "true"
            elif allowbackup[0].split('"')[1].lower() == "true":
                configuration_info['allowBackup'] = "true"
            else:
                configuration_info['allowBackup'] = "false"

            if len(debuggable) == 0:
                #AndroidManifest.xml文件中配置debuggable标志(默认为false)
                configuration_info['debuggable'] = "false"
            elif debuggable[0].split('"')[1].lower() == "true":
                configuration_info['debuggable'] = "true"
            else:
                configuration_info['debuggable'] = "false"

        #print configuration_info
        return configuration_info

    def start(self):
        self.get_manifest_info()
        self.get_permission()
        self.get_activities()
        self.get_receivers()
        self.get_services()
        self.get_providers()
        self.get_configuration()


# if __name__ == "__main__":
#     obj = Xml()
#     obj.start()
