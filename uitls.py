from androguard.core import *
from androguard.core.androgen import *
from androguard.core.androconf import *
from androguard.core.bytecode import *
from androguard.core.bytecodes.jvm import *
from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes.apk import *

from androguard.core.analysis.analysis import *
from androguard.core.analysis.ganalysis import *
from androguard.core.analysis.risk import *
from androguard.decompiler.decompiler import *


from androguard.core import androconf

def AnalyzeAPK(filename, raw=False, decompiler=None):
    """
        Analyze an android application and setup all stuff for a more quickly analysis !

        :param filename: the filename of the android application or a buffer which represents the application
        :type filename: string
        :param raw: True is you would like to use a buffer (optional)
        :type raw: boolean
        :param decompiler: ded, dex2jad, dad (optional)
        :type decompiler: string
        
        :rtype: return the :class:`APK`, :class:`DalvikVMFormat`, and :class:`VMAnalysis` objects
    """
    androconf.debug("APK ...")
    a = APK(filename, raw)

    d, dx = AnalyzeDex(a.get_dex(), raw=True, decompiler=decompiler)

    return a, d, dx


def AnalyzeDex(filename, raw=False, decompiler=None) :
    """
        Analyze an android dex file and setup all stuff for a more quickly analysis !

        :param filename: the filename of the android dex file or a buffer which represents the dex file
        :type filename: string
        :param raw: True is you would like to use a buffer (optional)
        :type raw: boolean

        :rtype: return the :class:`DalvikVMFormat`, and :class:`VMAnalysis` objects
    """
    androconf.debug("DalvikVMFormat ...")
    d = None
    if raw == False :
        d = DalvikVMFormat( open(filename, "rb").read())
    else :
        d = DalvikVMFormat( filename )

    androconf.debug("Export VM to python namespace")
    d.create_python_export()

    androconf.debug("VMAnalysis ...")
    dx = uVMAnalysis( d )

    androconf.debug("GVMAnalysis ...")
    gx = GVMAnalysis( dx, None )

    d.set_vmanalysis( dx )
    d.set_gvmanalysis( gx )

    RunDecompiler( d, dx, decompiler )

    androconf.debug("XREF ...")
    d.create_xref()
    androconf.debug("DREF ...")
    d.create_dref()

    return d, dx

def RunDecompiler(d, dx, decompiler) :
    """
        Run the decompiler on a specific analysis

        :param d: the DalvikVMFormat object
        :type d: :class:`DalvikVMFormat` object
        :param dx: the analysis of the format
        :type dx: :class:`VMAnalysis` object 
        :param decompiler: the type of decompiler to use ("dad", "dex2jad", "ded")
        :type decompiler: string
    """
    if decompiler != None :
        androconf.debug("Decompiler ...")
        decompiler = decompiler.lower()
        if decompiler == "dex2jad" :
            d.set_decompiler( DecompilerDex2Jad( d, androconf.CONF["PATH_DEX2JAR"], androconf.CONF["BIN_DEX2JAR"], androconf.CONF["PATH_JAD"], androconf.CONF["BIN_JAD"], androconf.CONF["TMP_DIRECTORY"] ) )
        elif decompiler == "ded" :
            d.set_decompiler( DecompilerDed( d, androconf.CONF["PATH_DED"], androconf.CONF["BIN_DED"], androconf.CONF["TMP_DIRECTORY"]) )
            #print d.CM.decompiler_ob.classes
        elif decompiler == "dad" :
            d.set_decompiler( DecompilerDAD( d, dx ) )
        else :
            print "Unknown decompiler, use DAD decompiler by default"
            d.set_decompiler( DecompilerDAD( d, dx ) )