import re
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis


class MatchRule(object):
    '''
        This class is analysis source to audit 
    
        :param d: specify the DalvikVMFormat object
        :param dx: specify the VMAnalysis object
        :type d: androguard.core.bytecodes.dvm.DalvikVMFormat
        :type dx: androguard.core.analysis.VMAnalysis
        :Example SourceAudit(d, dx)
    
    '''
    def __init__(self, d, dx):

        self.d = d
        self.dx = dx
        self.webview = {}
        self.register_receiver = {}
        self.allowallhostnameverifier = {}
        self.onreceivedsslerror = {}
        self.dexclassloader = {}
        self.https = {}
        self.log = {}
    
    def webview_audit(self):
        self.webview = self.__mathods_search(".", "addJavascriptInterface", ".")
        #self.webview = self.__mathods_search("", "webview", ".")
        #self.webview = self.__mathods_search(".", "removeJavascriptInterface", ".")

    def register_receiver_audit(self):  
        self.register_receiver = self.__mathods_search(".", "registerReceiver", ".")

    def allowallhostnameverifier_audit(self):
        self.allowallhostnameverifier = self.__mathods_search(".", "AllowAllHostnameVerifier", ".")

    def onreceivedsslerror_audit(self):
        self.onreceivedsslerror = self.__mathods_search(".", "OnReceivedSslError", ".")

    def dexclassloader_audit(self):
        self.dexclassloader = self.__mathods_search("Ldalvik/system/DexClassLoader", "loadClass", ".")

    def https_audit(self):
        self.https = self.__mathods_search("Lorg/apache/http/conn/ssl/SSLSocketFactory;", "setHostnameVerifier", ".")

    def intent_scheme_audit(self):
        self.intent_scheme = self.__mathods_search("Landroid/content/Intent;", "parseUri", ".")

    def log_audit(self):
        self.log = self.__mathods_search_log("Landroid/util/Log;", "i", ".")
        #pass



    
    def __mathods_search(self, package_name, method_name, descriptor):
        '''
            This method is search method's ref and get the method's java source

            :param package_name: specify the taint class name
            :param method_name: specify the taint mathod name
            :param package_name: string
            :param method_name: string
        '''
        nodes = []
        names = {}
        analysis_res = {}
        tainted_packages = self.dx.get_tainted_packages()
        
        paths = tainted_packages.search_methods(package_name, method_name, descriptor)
        if not paths:
            return
    
        #analysis.show_Paths(self.d, paths)
        #path's struct {'src': 'Lclass; method(parm_type;parm_type;)ret_type;', 'dst': 'Lclass; method(parm_type;parm_type;)ret_type;', 'idx': 170}
        #nodes containt many path's struct
        
        for path in paths:
            nodes.append(analysis.get_Path(self.d, path))
    
        for node in nodes:
            tmp = node["src"].split(" ")
            #names struct : {'class':['method_name']['method_name']}
            if names.has_key(tmp[0]):
                names[tmp[0]].append(tmp[1])
            else:
                names[tmp[0]] = []
                names[tmp[0]].append(tmp[1])
    
        #print names :src class and method

        for current_class in self.d.get_classes():
            class_name = current_class.get_name()
            #this class is the src class for tainted method
            if names.has_key(class_name):
                for method in current_class.get_methods():
                    name = method.get_name()
                    #src method to call tainted method
                    if name in names[class_name]:
                        java = method.get_source()
                        java_code = java.split("\n")
                        for code in java_code:
                            if code.find(method_name) != -1:
                                analysis_res["%s->%s.java:%s" % (class_name, name, code.lstrip())]=java

        return analysis_res


    def __mathods_search_log(self, package_name, method_name, descriptor):
        '''
            This method is search method's ref and get the method's java source

            :param package_name: specify the taint class name
            :param method_name: specify the taint mathod name
            :param package_name: string
            :param method_name: string
        '''
        nodes = []
        names = {}
        analysis_res = {}
        tainted_packages = self.dx.get_tainted_packages()

        paths = tainted_packages.search_methods(package_name, method_name, descriptor)
        if not paths:
            return

        #analysis.show_Paths(self.d, paths)
        #path's struct {'src': 'Lclass; method(parm_type;parm_type;)ret_type;', 'dst': 'Lclass; method(parm_type;parm_type;)ret_type;', 'idx': 170}
        #nodes containt many path's struct

        for path in paths:
            nodes.append(analysis.get_Path(self.d, path))

        for node in nodes:
            tmp = node["src"].split(" ")
            #names struct : {'class':['method_name']['method_name']}
            if names.has_key(tmp[0]):
                names[tmp[0]].append(tmp[1])
            else:
                names[tmp[0]] = []
                names[tmp[0]].append(tmp[1])

        #print names :src class and method

        for current_class in self.d.get_classes():
            class_name = current_class.get_name()
            #this class is the src class for tainted method
            if names.has_key(class_name):
                for method in current_class.get_methods():
                    name = method.get_name()
                    #src method to call tainted method
                    if name in names[class_name]:
                        java = method.get_source()
                        java_code = java.split("\n")
                        for code in java_code:
                            if code.lower().find("log.i") != -1:
                                analysis_res["%s->%s.java:%s" % (class_name, name, code.lstrip())]=java

        return analysis_res

    def get_webview_res(self):
        return self.webview

    def get_register_receiver(self):
        return self.register_receiver

    def get_allowallhostnameverifier(self):
        return self.allowallhostnameverifier

    def get_onreceivedsslerror(self):
        return self.onreceivedsslerror

    def get_dexclassloader(self):
        return self.dexclassloader

    def get_https(self):
        return self.https

    def get_intent_scheme(self):
        return self.intent_scheme

    def get_logs(self):
        return self.log
