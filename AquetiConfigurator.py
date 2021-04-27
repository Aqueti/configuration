#!/usr/bin/python3
#############################################
#
# SDF: Improve efficient (read configs only once)
#
#############################################

import subprocess
from datetime import datetime
import json
import re
import argparse
import sys
import copy

import CommandParser
import AquetiSystemInfo
import FileInterface

VERSION      = "3.0.0.7"
RMEM_MAX     = 26214400
RMEM_DEFAULT = 26214400
LOG_DIR      = "/var/log/aqueti/config"
HOSTS_FILE   = "/etc/hosts"
DPKG_PATH    = "."

status=["uninstalled","behind","current","ahead"]
match=["any","<","==",">",">="]
updatePermissions=["any","security","none"]
importance=["optional","recommended","required"]
installCommands=["sequence","value","error","returnCode"]


class Configurator:

    ##
    # \brief initialization function
    # \param [in] configInfo information about configuration
    # \param [in] logDir log directory
    #
    def __init__(self, configInfo = None, logDir = LOG_DIR):
        self.OS = None
        self.verbose = 0
        self.needsReboot = False
        self.software = {}

        self.configInfo    = None
        self.depends       = None
        self.settings      = None
        self.defaultSource = None
        self.logFile = None

        #Create log file and make sure we have rwx access
        #SDF may want to check permissions on file
        info = CommandParser.validateFile( logDir )
        if not info["exists"]:
            #Create the directory
            cmd = "mkdir -p "+logDir
            result = CommandParser.runCommand( cmd )
            if result["returnCode"]:
                print("ERROR: "+logDir+" does not exist and cannot be created")
                exit 
        elif not info["d"]:
            print("ERROR: "+logDir+" exists but is not a directory")
            exit(1)
        elif not info["w"]:
            print("ERROR: "+logDir+" is not writeable")
            exit(1)

        #Create a log file
        upgradeTime = datetime.now()
        self.logFile = logDir + "/AquetiConfigurator_"+str(upgradeTime.timestamp())+".log"

        #Figure out our OS for future reference
        result = CommandParser.runCommand("cat /etc/lsb-release")
        if result["returnCode"] != 0:
            sys.stderr.write("Unable to access ls-release")
        else:
            lines = result["value"].splitlines(1)
            for line in lines:
                info = line.split("=")
                if info[0] == "DISTRIB_RELEASE":
                    release = info[1].rstrip()

        #get architecture
        result = CommandParser.runCommand("uname -m")
        arch = result["value"]
        self.OS = str(release+" "+arch)

        #If we didn't specify config info, set all sub values to None
        if configInfo != None:
            if not self.OS in configInfo.keys():
                print("OS "+self.OS+" not in the config information")
            else:
                self.configInfo = configInfo[self.OS]

                try:
                    self.depends = configInfo[self.OS]["software"]["depends"]
                except:
                    print("software/depends not provided")
                try:
                    self.defaultSource = configInfo[self.OS]["software"]["defaultSource"]
                except:
                    print("default software source not provided")
                try:
                    self.settings = configInfo[self.OS]["config"]["settings"]
                except:
                    print("config/settings not provided")

        #Create the log file first entry
        logInfo = "Aqueti Configurator Log: "+str(upgradeTime)+"\n"
        print("Log: "+logInfo)
        fp = open( self.logFile, "w")
        fp.write( logInfo )

    ##
    # \brief destructor
    #
    def __del__(self):
        if self.needsReboot:
            print("*********************************************************************")
            print("* WARNING: A system restart is required for changes to take effect  *")
            print("*********************************************************************")

    ##
    # \brief checks NTP settings
    # \param [in] offset maximum allowed time deference in milliseconds from the reference clock 
    # \param [in] restart flag to indicate if the daemon should restart
    # \param [in] delay how long to wait after restart to test daemon
    # \param [in] filename name of the ntp.conf used by the server
    #
    # This function verifies that the server is working correctly
    #
    def checkNTP( self, offset=10, restart=False, delay = 30, filename="/etc/ntp.conf"):
        info ={"pass":True, "valid":[], "invalid":[], "errors":[],"peers":[], "broadcasts":[]}

 
        #Restart the daemon
        if restart:
            if verbose:
                print("Restarting the daemon")
            if not CommandParser.checkSudo():
                info["errors"].append("Unable to restart the ntp.conf file. Not running in SUDO mode")
                print("ValidatNTPDaemon: Must be root to restart the ntp.conf file")
                return info


            ret = CommandParser.runCommand("systemctl restart ntp")
            if ret["returnCode"] != 0:
                print("ValidatNTPDaemon: Error restarting the daemon")
                info["errors"] = "Error restarting the daemon"

            print("\tSleeping for 30 seconds while waiting for NTP to settle")

            CommandParser.printProgress( delay )


        #Check if daemon is running
        #Make sure daemon is running
        if verbose:
            print("verifying NTP daemon is running")

        ret = CommandParser.runCommand("systemctl status ntp |grep running")
        if ret["returnCode"]:
            info["errors"].append("Unable to access ntpd via systemctl")
            info["pass"] = False
            return info

 
        #Check status of daemon
        try:
            fields = ret["value"].split()
            status = fields[1]
            info["status"] = status
        
            #If we are not active, we have a problem
            if status != "active":
                info["errors"].append("ntpd is not running. Unable to validate")
                info["pass"] = False
                return info
        
            #Extract the uptime
            entry = ret["value"].split(";")[1]
            uptime = entry.split()[0]
        
            info["uptime"] = uptime
        except:
            info["errors"].append("Unable to extract ntp daemon status")
            info["pass"] = False
            return info


        ###########################
        # Check ntqp 
        ###########################
        #Run ntpq -p to get a list of connection
        if verbose:
            print("verifying NTP connections")
        ret = CommandParser.runCommand("ntpq -p")
        if ret["returnCode"]:
            info["errors"].append("Failed running ntpq -p")
            info["pass"] = False
            return info

        lines = ret["value"].splitlines()

        #Check each line and see what connections
        init = False
        for line in lines:

            #Drop lines until we get to a line of "=" values
            if line[0] == "=" or not init:
                if line[0] == "=":
                    init = True
                continue

            #Determine line type
            sync = line[0]
            items = line[1:].split()

            #Extract the broadcast first. 
            if "BCST" in items[1]:
                broadcast = {}
                broadcast["network"] = items[0]
                broadcast["entry"] = line
                info["broadcasts"].append(broadcast)
            else:
                source = {}
                source ["remote"] = items[0]
                source["entry"] = line
                if sync == "*":
                    source["status"] = "peer"
                    info["peers"] = items[0]

                    if "LOCL" in items[1]:
                        info["hwclock"] = True

                if "LOCL" in items[1]:
                    source["hwclock"] = True

                info["valid"].append(source)

                #If the first byte is a +, we are an alternate
                if sync == "+":
                    source["status"] = "alternate"

        if len(info["peers"]) > 0:
            info["pass"] = True

        #Make sure timedatectl is not running.
        cmd = "timedatectl status |grep timesyncd.service |cut -d ' ' -f 3"
        ret = CommandParser.runCommand( cmd )

            
        #If failure, assume there is a fundamental error with systemd and fail
        if ret["returnCode"]:
            print("Unable to execute command: "+cmd)
            info["pass"] = False
        elif ret["value"] != "no":
            print("VALIDATION FAILURE: timedatectl is enabled. Disable with: \"sudo timedatectl set-ntp 0\"")
            info["pass"] = False

        return info





    ##
    # \brief modifies sysctl settings
    # \param [in] settings dictionary that specifies a new setting parameters
    # \return True on success, False on failure
    #
    # This function uses hte info in settings variable to override the default
    # values in sysctlSettingsJson. Only fields that change need to be included.
    #
    def changeSysctl(self, filename = "/etc/sysctl.conf", data = None ):
        if not CommandParser.checkSudo():
            print("ERROR: sudo access required for changeSysctl.")
            return False

        if data == None:
#            data = {"info":{}}
            data = {}

        #make sure the settings value is a dictionary
        if not isinstance( data, dict ):
            print("ERROR: checkSystclt requires a JSON object to specify settings")
            return False

        #Read data from system settings values into a key/pair dictionary
        settings = self.settings["sysctl"]
        values = {}

        if "all" in settings.keys():
            keys = settings["all"].keys()

            for key in keys:
                values[key] = settings["all"][key]["value"]

        #Add in new values
        for key in data:
            values[key] = data[key]

        #Read in the specified filename
        sysctl = FileInterface.readConf( filename, delim="=" )
        if not sysctl:
            print("Unable to read data from "+filename)
            return False

        #maintain a list of changed items
        changes=[]
        
        #Loop through sysctl["data"] and set values
        for item in sysctl["data"]:
            #We are only interested in items with info
            if "info" in item.keys():
                #Loop through info item entries. First value == key, second == value
                for e in item["info"]:
                    #Compare against entries in values
                    if e[0] in values.keys():
                        e[1] = values[e[0]]
                        changes.append(e[0])


        #Add an entry for new values
        for key in values.keys():
            if key not in changes:
                entry = {"comments":["# Changes for Aqueti Software"],"info":[]}
                arr = []
                arr.append(key)
                arr.append(values[key])
                entry["info"].append(arr)
                sysctl["data"].append(entry)

        result = FileInterface.writeConf( sysctl, filename, delim="=" )
        if not result["success"]:
            print("ERROR: changeSysctl writeConf was not successful")
            return False

        #restart sysCtl
        cmd = "service systemd-sysctl restart"
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            print("ERROR: changeSysctl unable to restart systemd-sysctl")
            return False
            
        return True

    ##
    # \brief check sysctl settings
    # \param [in] settings dictionary that specifies a new setting parameters
    # \return dictionary with the reuslt
    #
    # This function uses hte info in settings variable to override the default
    # values in sysctlSettingsJson. Only fields that change need to be included.
    def checkSysctl(self):
        sysctlInfo = {"valid":[],"invalid":[]}

        #make sure the settings value is a dictionary
        if self.settings == None:
            print("ERROR: not sysctl configuration settings provided")
            return sysctlInfo

        #Loop through all of the items in settings. These are the top-level objects (e.g. rmem_max)
        settings = self.settings["sysctl"]

        #Loop through settings for everyone
        if "all" in settings.keys():
            keys = settings["all"].keys()


            data = {}
            for key in keys:
                result = {}


                #Override the new info
                for k in settings["all"][key]:
                    data[k] = settings["all"][key][k]

                #Query the system to find out what our settings are
                cmd = "sysctl -a |grep "+key+" |cut -d' ' -f3-"
                result = CommandParser.runCommand( cmd )
                if result["returnCode"]:
                    print("ERROR: Unable to query sysctl with command "+cmd)

                else:
                    if data["type"] == "int":
                        value = int(result["value"])
                        dvalue = int(data["value"])
                    elif data["type"]==  "float":
                        value = float(result["value"])
                        dvalue = float(data["value"])
                    else:
                        value = str(result["value"])
                        dvalue = str(data["value"])

                    #See how we did
                    data["valid"] = False
                    if data["match"] == "==":
                        if dvalue  == value:
                            data["valid"] = True

                    elif data["match"] == ">=":
                        if dvalue  >= value:
                            data["valid"] = True


                    if data["valid"]:
                        data["value"] = value
                        sysctlInfo["valid"].append({key:data})
                        data["expectedValue"] = dvalue
                    else:
                        data["value"] = value
                        data["expectedValue"] = dvalue
                        sysctlInfo["invalid"].append({key:data})

        #Return the result
        return sysctlInfo

    ##
    # \brief check the system name
    # \param [in] systemName new name for the system
    # \param [in] filename name of the configuration file.
    # \return True on success, False on failure
    #
    def checkSystemName(self, filename="/etc/aqueti/daemonConfiguration.json"):
        info = {"valid":[],"invalid":[]}

        #check for sudo access
        if not CommandParser.checkSudo():
            print("ERROR: sudo access required to change firewall.")
            return False


        config = FileInterface.readJson( filename )

        try:
            info["valid"] = {"system":config["directoryOfServices"]["system"]}
            
        except:
            msg = "ERROR: invalid system entry in "+filename
            invalid[{"system":"invalid"}]

        return info
 
            
    ##
    # \brief change the system name
    # \param [in] systemName new name for the system
    # \param [in] filename name of the configuration file.
    # \return True on success, False on failure
    #
    def changeSystemName(self, systemName, filename="/etc/aqueti/daemonConfiguration.json"):
        print("Changing system name to "+systemName)
        #check for sudo access
        if not CommandParser.checkSudo():
            print("ERROR: sudo access required to change firewall.")
            return False


        #Read the configuration file
        config = FileInterface.readJson( filename )

        #Try to change. If failure, there is an issue with the config file
        try:
            print("Config: "+str(config))
            if config["directoryOfServices"]["system"] == systemName:
                print("No name changes required")
                return True
            else:
                config["directoryOfServices"]["system"] = systemName
                print("New config: "+json.dumps(config))
        except:
            print("ERROR: Unable to change system name. Could be due to corrupted file: "+filename)
            return False

        #Write File
        try:
            print("Writing: "+json.dumps(config, indent=4))
            FileInterface.writeJson( config, filename )
          
        except:
            print("ERROR: Unable to write configuration file: "+filename)
            return False

        return True

                

    ##
    # \brief changes the firewall settings
    #
    # For now, this function only disables the firewall
    #
    def disableFirewall(self):
        
        #check for sudo access
        if not CommandParser.checkSudo():
            print("ERROR: sudo access required to change firewall.")
            return False

        #See if the firewall settings are already valid
        status = self.checkFirewall()
        if status["pass"]:
            return True

        #If not, disable firewall
        else:
            cmd = "sudo service ufw stop"
            result = CommandParser.runCommand(cmd)
            if result["returnCode"]:
                print("ERROR: unable to stop ufw daemon")
                return False

        #See if the firewall settings are already valid
        status = self.checkFirewall()
        if status["pass"]:
            return True
        else:
            return False
            
       
    ##
    # \brief check the firewall settings
    # \brief return info structure with a valid flag to indicate success
    #
    # For now, the firewall must be disabled to succeed
    #
    def checkFirewall(self):
        firewallInfo={"pass":True, "valid":[], "invalid":[], "errors":[]}

        cmd = "service ufw status |head -n5 |grep Active"
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            msg = "ERROR: unable to get status of UFW"
            if self.verbose:
                print(msg)
            filewallInfo["errors"].append(msg)
            firewallInfo["pass"] = False
            return firewallInfo
         
        #If we are not inactive, we need to be inactive
        if result["value"].find("inactive") < 0:
            print("inactive : "+result["value"])   
            msg = "ERROR: firwall enabled"
            firewallInfo["pass"] = False
            firewallInfo["errors"].append(msg)
                

        return firewallInfo

            
              
          
    ##
    # \brief modifies sysctl settings
    # \param [in] settings dictionary that specifies a new setting parameters
    # \return True on success, False on failure
    #
    # This function uses hte info in settings variable to override the default
    # values in sysctlSettingsJson. Only fields that change need to be included.
    #
    def changeUserLimits(self, filename = "/etc/security/limits.conf", data = None ):
        field = "DefaultLimitNOFILE"

        #If we're not root, fail
        if not CommandParser.checkSudo():
            print("ERROR: sudo access required for changeUserLimits")
            return False
       
        #If we have data, use it
        if data == None:
            data = {"info":{}}

        #make sure the settings value is a dictionary
        if not isinstance( data, dict ):
            print("ERROR: changeUserLimits requires a JSON object to specify settings")
            return False

        #Read data from system settings values into a key/pair dictionary
        settings = self.settings["limits"]
        values = {}

        #Loop through keys/pairs to find maximuim values for hard/soft files
        for key in settings.keys():
            for k in ["hard","soft"]:
                if not field in values.keys():
                    values[field] = settings[key]["Max open files"][k]

                if values[field]["value"] < settings[key]["Max open files"][k]["value"]:
                    values[field] =  settings[key]["Max open files"][k]
        
        #Read in conf file
        fileInfo = FileInterface.readConf( filename )
        if not fileInfo:
            print("Unable to read data from "+filename)
            return False

        print

        #Loop through fileInfo["data"] and check for settings in info fields. If we 
        #find what we are looking for, set the value
        name = "nofile"
        nofileset = False

        #Look for first field of root or asterix
        value = str(values[field]["value"])
        for key1 in ["root","*"]:
            for key2 in ["soft","hard"]:
                for key3 in ["nofile"]:
                    #Loop through all entries
                    found = False
                    for item in fileInfo["data"]:
                        if "info" in item.keys():
                            for entry in item["info"]:
                                if entry[0] == key1 and entry[1] == key2 and entry[2] == key3:
                                    if entry[3] == value:
                                       print("No change necessary for "+str(entry))
                                    else:
                                       entry[3] = value
                                    found = True
                                    continue
                            if found: 
                                continue

                    #I still haven't found what I've been looking for
                    if not found:
                        newItem = {"info":[]}
                        entry = [key1, key2, key3, value]
                        newItem["info"].append(entry)
                        fileInfo["data"].append(newItem)

        #Write results
        result = FileInterface.writeConf( fileInfo, filename)
        if not result["success"]:
            print("ERROR: changeUserLimits writeConf was not successful for "+filename)
            return False

        self.needsReboot = True

        print("Success!")
        return True
        

    ##
    # \brief modifies sysctl settings
    # \param [in] settings dictionary that specifies a new setting parameters
    # \return True on success, False on failure
    #
    # This function uses hte info in settings variable to override the default
    # values in sysctlSettingsJson. Only fields that change need to be included.
    #
    def changeSystemLimits(self, path = "/etc/systemd", data = None ):
        field = "DefaultLimitNOFILE"
        if not CommandParser.checkSudo():
            print("ERROR: sudo access required for changeSystemLimits.")
            return False

        if data == None:
            data = {"info":{}}

        #make sure the settings value is a dictionary
        if not isinstance( data, dict ):
            print("ERROR: changeSystemLimits requires a JSON object to specify settings")
            return False

        #Read data from system settings values into a key/pair dictionary
        settings = self.settings["limits"]
        values = {}

        #Loop through keys/pairs to find maximuim values for hard/soft files
        for key in settings.keys():
            for k in ["hard","soft"]:
                if not field in values.keys():
                    values[field] = settings[key]["Max open files"][k]

                if values[field]["value"] < settings[key]["Max open files"][k]["value"]:
                    values[field] =  settings[key]["Max open files"][k]

        #Any settings have to be applied to two files
        for name in ["system.conf","user.conf"]:
            filename = path + "/"+name
            fileInfo = FileInterface.readConf( filename, delim="=" )
            if not fileInfo:
                print("Unable to read data from "+filename)
                return False


            #Loop through fileInfo["data"] and check for settings in info fields. If we 
            #find what we are looking for, set the value
            for item in fileInfo["data"]:
                #Make sure we have an info entry.
                if "info" in item.keys():
                   if field in item["info"]:
                       item["info"][field] = values[field]
                       values[field]["set"] = True

            if not "set" in values[field].keys():
                 entry = {}
                 entry["info"] = []
                 entry["info"].append([field, str(values[field]["value"])])
                 fileInfo["data"].append(entry)

            print("Filename: "+filename)
            result = FileInterface.writeConf( fileInfo, filename, delim="=" )
            if not result["success"]:
                print("ERROR: changeSystemLimits writeConf was not successful for "+filename)
                return False

        """
        #restart sysCtl
        cmd = "service systemd-sysctl restart"
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            print("ERROR: changeSysctl unable to restart systemd-sysctl")
            return False
        """ 
        print("Success!")
        return True



    ##
    # \brief check sysctl settings
    # \param [in] settings dictionary that specifies a new setting parameters
    # \return dictionary with the reuslt
    #
    # This function compares the limits in setting against actual limits 
    # queries from running processes. This does not verify the system
    # settings
    #
    def checkLimits(self):
        pid = None
        limitsInfo = {"valid":{},"invalid":{}, "warnings":[]}

        #make sure the settings value is a dictionary
        if self.settings == None:
            print("ERROR: no limits configuration settings provided")
            return limitsInfo

        #Extract the limits we're looking for
        settings = self.settings["limits"]

        data = {}

        #Check each process to find the owner
        for process in settings:
            entry = {}
            #Find out who owns the pro1cess
            cmd = "pgrep "+process
            ret = CommandParser.runCommand(cmd)
            if ret["returnCode"]:
                msg = "WARNING: checkLimits unable to find "+process+". Cannot verify limits for this process"
                limitsInfo["warnings"].append(msg)
                continue

            #Get the current limits for the specified process
            pid = ret["value"]
            processInfo = None
            if pid != None:
                filename = "/proc/"+pid+"/limits"
                fp = open( filename, "r")
                processInfo = fp.read()
                fp.close()
            else:
                limitsInfo["invalid"][process] = entry
                continue

            #Determine process owner
            fp = open("/proc/"+pid+"/status","r")
            procStatus = fp.read()
            fp.close()

            #Extract userid
            for line in procStatus.splitlines(1):
                arr = line.split()
                if arr[0] == "Uid:":
                    uid = arr[1]
                    break

            #Map to username
            fp = open("/etc/passwd","r")
            passInfo = fp.read()
            fp.close()

            for line in passInfo.splitlines(1):
                arr = line.split(":")
                if arr[2] == uid:
                    user = arr[0]
                    break

            entry["owner"] = user

            #Loop through the key settings for each process and extract info
            #from the file
            for key in settings[process].keys():
                #loop through each line of the file
                for line in processInfo.splitlines(1):
                    #If we find the key, we set the values. THe file has
                    #columns: Limit/Soft Limit/Hard Limit/Units. We need
                    if key in line:
                        values = line[26:]
                        soft, hard, units  = values.split()
                        soft = int(soft)
                        hard = int(hard)
                        
                        if "soft" in settings[process][key].keys():
                            entry["soft"] = {}
                            entry["soft"]["value"] = soft
                            entry["soft"]["match"] = settings[process][key]["soft"]["match"] 
                            value = int(settings[process][key]["soft"]["value"])
                            entry["soft"]["target"] = value

                            if settings[process][key]["soft"]["match"] == "==":
                                if value == soft:
                                    entry["soft"]["valid"] = True
                                    limitsInfo["valid"][process] = entry
                                else:
                                    entry["soft"]["valid"] = False
                                    limitsInfo["invalid"][process] = entry

                            elif settings[process][key]["soft"]["match"] == ">=":
                                if soft >= value:
                                    entry["soft"]["valid"] = True
                                    limitsInfo["valid"][process] = entry
                                else:
                                    entry["soft"]["valid"] = False
                                    limitsInfo["invalid"][process] = entry

                            elif settings[process][key]["soft"]["match"] == "<=":
                                if soft <= value:
                                    entry["soft"]["valid"] = True
                                    limitsInfo["valid"][process] = entry
                                else:
                                    entry["soft"]["valid"] = False
                                    limitsInfo["invalid"][process] = entry


                        if "hard" in settings[process][key].keys():
                            entry["hard"] = {}
                            entry["hard"]["value"] = hard
                            value = int(settings[process][key]["hard"]["value"])
                            entry["hard"]["match"] = settings[process][key]["hard"]["match"] 
                            entry["hard"]["target"] = value

                            if settings[process][key]["hard"]["match"] == "==":
                                if value == hard:
                                    entry["hard"]["valid"] = True
                                    limitsInfo["valid"][process] = entry
                                else:
                                    entry["hard"]["valid"] = False
                                    limitsInfo["invalid"][process] = entry

                            if settings[process][key]["hard"]["match"] == ">=":
                                if hard >= value:
                                    entry["hard"]["valid"] = True
                                    limitsInfo["valid"][process] = entry
                                else:
                                    entry["hard"]["valid"] = False
                                    limitsInfo["invalid"][process] = entry

                            if settings[process][key]["hard"]["match"] == "<=":
                                if hard <= value:
                                    entry["hard"]["valid"] = True
                                    limitsInfo["valid"][process] = entry
                                else:
                                    entry["hard"]["valid"] = False
                                    limitsInfo["invalid"][process] = entry


        #Return the result
        return limitsInfo


    ##
    # \brief Function to validate system configuration
    #
    def checkConfig(self):
        self.config= {"valid":{},"invalid":{}}
        self.config["version"] = VERSION

        if "version" in depends.keys():
            self.config["dependencyVersion"] = depends["version"]
        else:
            self.config["dependencyVersion"] = None

 
        #loop through all keys in the dependencies
        for key in self.depends:
            ref = self.depends[key]
            status = {}

            result = CommandParser.runCommand(ref["queryCommand"])

            #If we failed to run, softare is not installed
            if result["returnCode"] != 0:
                status["status"] = "uninstalled" 
                status["valid"] = False

            elif result["value"] == "":
                status["status"] = "uninstalled" 
                status["valid"] = False
            
            else:
                value = result["value"]
                status["value"] = value

                #If the current version exceeds required version
                if value > ref["value"]:
                    value["status"] = "ahead"
                    if ref["match"] == ">=" or ref["match"] == ">":
                        value["valid"] = True
                    else:
                        value["valid"] = False
     
                #If we are equal
                elif version == self.depends[key]["version"]:
                    value["status"] = "current"

                    if ref["match"] == ">" or ref["match"] == "<":
                        value["valid"] = False
                    else:
                        value["valid"] = True

                #If we are behind
                elif version < self.depends[key]["version"]:
                    value["status"] = "behind"

                    if ref["match"] == "<":
                        value["valid"] = True
                    else:
                        value["valid"] = False
                        
                #if any version is valid...
                elif ref["match"] == "any":
                    value["valid"] = True
                else:
                    value["valid"] = False

            if value["valid"]: 
                self.config["valid"][key] = value
            else:
                self.config["invalid"][key] = value



        return self.config

    ##
    # \brief checks software dependencies
    #
    def checkDependencies(self):
        if not self.depends:
            return False
        self.software = {"valid":{},"invalid":{}}
        self.software["version"] = VERSION

        if "version" in depends.keys():
            self.software["dependencyVersion"] = depends["version"]
        else:
            self.software["dependencyVersion"] = None

 
        #loop through all keys in the dependencies
        for key in self.depends:
            ref = self.depends[key]
            value = {}

            result = CommandParser.runCommand(ref["versionCommand"])

            #If we failed to run, softare is not installed
            if result["returnCode"] != 0:
                value["status"] = "uninstalled" 
                value["valid"] = False

            elif result["value"] == "":
                value["status"] = "uninstalled" 
                value["valid"] = False
            
            else:
                version = result["value"]
                value["version"] = version


                #If the current version exceeds required version
                if version > ref["version"]:
                    value["status"] = "ahead"
                    if ref["match"] == ">=" or ref["match"] == ">":
                        value["valid"] = True
                    else:
                        value["valid"] = False
     
                #If we are equal
                elif version == self.depends[key]["version"]:
                    value["status"] = "current"

                    if ref["match"] == ">" or ref["match"] == "<":
                        value["valid"] = False
                    else:
                        value["valid"] = True

                #If we are behind
                elif version < self.depends[key]["version"]:
                    value["status"] = "behind"

                    if ref["match"] == "<":
                        value["valid"] = True
                    else:
                        value["valid"] = False
                        
                #if any version is valid...
                elif ref["match"] == "any":
                    value["valid"] = True
                else:
                    value["valid"] = False

            if value["valid"]: 
                self.software["valid"][key] = value
            else:
                self.software["invalid"][key] = value

        return self.software

    ##
    # \brief updates the system and checks dependencies
    # 
    # 
    def updateSystem(self, dpkgPath = DPKG_PATH):
        if not CommandParser.checkSudo():
            sys.stderr.write("Unable to update the sytem without sudo access\n")
            return False

        print("Updating the repository references")
        result = CommandParser.runCommand("sudo apt -y update")
        if result["returnCode"] != 0:
            sys.stderr.write("Unable to do an apt update. Aborting system update")
            return False

        print("Upgrading the system")
        result = CommandParser.runCommand("sudo apt -y  upgrade")
        if result["returnCode"] != 0:
            sys.stderr.write("Unable to do an apt upgrade. Aborting system upgrade")

        #Check each dependencies and fix invalid entries
        print("Upgrading all software")
        for key in self.depends.keys():

            #If we're installed and valid, skip
            if key in self.software.keys():
                if self.software[key]["valid"]:
                    continue

            #upgrade component
            self.upgrade(key, updateSystem="no", dpkgPath = dpkgPath )

        return True

    ##
    # \brief update the specified software package   
    # \param [in] version what installation version to use
    # \param [in] 
    #
    def upgrade(self, name, source=None, updateSystem="yes", dpkgPath = DPKG_PATH):
        if not CommandParser.checkSudo():
            sys.stderr.write("Unable to upgrade the sytem without sudo access\n")
            return False


        success = True

        #verify that the name is a known software package
        if name != "all" and name not in self.depends.keys():
            sys.stderr.write("WARNING: Unknown software package: "+name+". Unable to upgrade\n")
            return False

        #If we dont have sudo access, return False
        if not CommandParser.checkSudo(): 
            sys.stderr.write("ERROR: Unable to upgrade "+name+"without root access. Aborting\n")
            return False

        if self.verbose:
            print("upgrading: "+str(name))

        #If name == all, update all components through recursion
        if name == "all":
            print("Upgrading all")
            for key in self.depends.keys():
                self.upgrade( key, source  = source, dpkgPath = dpkgPath )
             
            print("Upgraded all")
            return

        #check if an upgrade is necessary
        self.checkDependencies()
        ref = self.depends[name]

        if name in self.software["valid"]:
            print(name+" is valid")
            current = self.software["valid"][name]
        elif name in self.software["invalid"]:
            print(name+" is invalid")
            current = self.software["invalid"][name]
        else:
            print("Name: "+str(name)+" not in the software list")


        #If we're are up to speed, exit
        if current["valid"] != False:
            print(name+" version: "+ current["version"]+" is valid. No update needed")
            return False


        #############################################
        #Start the installation process
        #############################################
        #If we don't have a specific source use the default
        if source == None:
            #If a source is not provided, try to use the software reecommended source.
            #If not, use the global default
            if "defaultSource" in self.depends[name].keys():
                source = self.depends[name]["defaultSource"]
            else:
                source = self.defaultSource


        upgradeTime = str(datetime.now())

        print("Updating: "+name+" at "+str(upgradeTime))

        #Exract the command sequence
        sequence = ref["install"][source]["sequence"]

        #If we are dpkg, we need to include the path in the command. To do this we will 
        #loop through each command and if we find the specified file, we will replace it in
        #the command with the path plus file
        if source == "dpkg":
            print("installing: "+name)

            #If there is a file key value pair, we replace that string with path+file
            for i in range(0,len(sequence)):
                item = sequence[i]

            if "file" in item.keys():
                fullPath = dpkgPath+"/"+item["file"]
                item["command"] = item["command"].replace(item["file"], fullPath)
                sequence[i] = item


        result = CommandParser.runCommandSequence(sequence)
        if result["returnCode"] != 0:
            print("Unable to upgrade "+name+": "+str(result["error"]))
            upgradeMsg = upgradeTime+"\t- ERROR: Unable to upgrade "+name
            success = False

        else:
            #Update our dependences to see if they are correct
            self.checkDependencies()

            if name in self.software["valid"].keys():
                update = self.software["valid"][name]
            elif name in self.software["invalid"].keys():
                update = self.software["invalid"][name]
            else:
                print("ERROR:"+name+" is not a known dependency!")

            if name == "network-manager-config-connectivity-ubuntu":
                print("SDF:"+json.dumps(self.software, indent=4))
                exit(1)

            if update["valid"]:
                if current["status"] == "uninstalled":
                    print( "Installed "+name+" "+update["version"])
                    upgradeMsg = upgradeTime+"\t- INSTALLED: "+name+" "+update["version"]
                else:
                    print( "Upgraded "+name+" from "+current["version"]+" to "+update["version"])
                    upgradeMsg = upgradeTime+"\t- Upgraded: "+name+" from "+current["version"]+" "+update["version"]
                #check if we need to upgrade
                if "installReboot" in ref.keys():
                    if ref["installReboot"]:
                        self.needsReboot = True
            else:
                print("Unable to update "+str(name))
                upgradeMsg = upgradeTime+"\t- ERROR: Unable to upgrade: "+name
                print("STATUS:"+str(json.dumps(update)))
                success = False

        #Log results
        fp = open( self.logFile, "a")
        fp.write( upgradeMsg+"\n")
        fp.close()


        return success

    ##
    # \brief changes the nvidia settings
    # 
    def changeNVidia( self ):
        nvInfo = {"pass":False, "valid":[],"invalid":[]}

        #check sudo
        if not CommandParser.checkSudo():
            print("Sudo access needed for changeHostsFile")
            return nvInfo 

        #Make sure we have an nVidia card

        #See if a change is needed
        result = self.checkNVidia()
        if result["pass"]:
            print("No change needed")
            nvInfo["pass"] = True
            return nvInfo

        #auto install ubuntu drivers
        cmd = "sudo ubuntu-drivers autoinstall"
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            print("Failed to execute command "+cmd)
            return nvInfo

        #Check return value


        #Check if change worked
        result = self.checkNVidia()
        if result["pass"]:
            print("No change needed")
            nvInfo["pass"] = True

        else:
            print("Unable to change NVIDIA")
            return nvInfo



        
     



    ##
    # \brief changes the hosts file to include <hostname>.local
    # 
    def changeHostsFile( self ):
        hostInfo = {"pass":False, "valid":[],"invalid":[]}
        hostFile = HOSTS_FILE

        if not CommandParser.checkSudo():
            print("Sudo access needed for changeHostsFile")
            return hostInfo 

        #get the hostname
        cmd = "hostname"
        result = CommandParser.runCommand(cmd )
        if result["returnCode"]:
            print("Failed to execute command "+cmd)
            return hostInfo

        hostname = result["value"]

        #Check the hosts file to see if it meets requirements
        status = self.checkHostsFile()
        if status["pass"]:
            print("No changes to Hostfile needed")
            return status

        for item in status["invalid"]:
            if "local" in item.keys():
                target = item["local"]["target"]

        #Read the hosts file
        fileInfo = FileInterface.readConf( hostFile)
#        print(json.dumps(fileInfo, indent=4))

        #Read each item. If hostname.local is there, mark as found. If not, insert
        found = False
        localCount = 0
        index = 0
        for item in fileInfo["data"]:
            if "info" in item:
                localCount = localCount + 1
                for entry in item["info"]:
                    #Find lines with the local IP
                    if entry[0] == "127.0.1.1":
                        if entry[1] == target:
                            found = True
                        elif entry[1] == hostname:
                            index = localCount

        if not found:
            entry = {"comments":["# Aqueti: Local reference for docker"], "info":[["127.0.1.1", target]]}
#SDF            fileInfo["data"].insert(index, entry)
            fileInfo["data"].insert(0, entry)

        result = FileInterface.writeConf( fileInfo, hostFile, delim=" " )

        status = self.checkHostsFile()
        return status

            
    ##
    # \brief Verifies the settings in the hosts file
    # \return object with results of process
    #
    def checkHostsFile(self):
        hostInfo = {"pass":False, "valid":[],"invalid":[]}

        #get the hostname
        cmd = "hostname"
        result = CommandParser.runCommand(cmd )
        if result["returnCode"]:
            print("Failed to execute command "+cmd)
            return hostInfo

        #We are looking for this hostname .local
        hostname = result["value"]
        target = hostname+".local"

        hostFile = HOSTS_FILE

        #check of hostfile exists
        ret = CommandParser.validateFile( hostFile )
        if not ret["exists"]:
            print("Host file "+hostFile+" does not exist")
            hostInfo["invalid"].append({"local":{"hostFile":hostfile, "error":"does not exist"}})
            return hostInfo


        #Read the hosts file
        fileInfo = FileInterface.readConf( hostFile)

        #Read each item. If hostname.local is there, mark as found. If not, insert
        found = False
        localCount = 0
        index = 0
        for item in fileInfo["data"]:
            if "info" in item:
                localCount = localCount + 1
                for entry in item["info"]:
                    #Find lines with the local IP
                    if entry[0] == "127.0.1.1":
                        if entry[1] == target:
                            found = True
                        elif entry[1] == hostname:
                            index = localCount


        if found:
            hostInfo["pass"] = True
            hostInfo["valid"].append({"local":{"target":target, "pass":True}})
        else:
            hostInfo["invalid"].append({"local":{"target":target, "error":"not set"}})
            hostInfo["pass"] = False

        return hostInfo
     
    ##
    # \brief Verifies that nvidia drivers are proper setup 
    # \return object with results of process
    #
    def checkNVidia(self):
        nvInfo = {"pass":False, "valid":[],"invalid":[]}

        #get the hostname
        cmd = "glxinfo | grep OpenGL | grep vendor"
        result = CommandParser.runCommand(cmd )
        if result["returnCode"]:
            print("Failed to execute command "+cmd)
            return nvInfo


        #Make sure the value contains NVIDIA
        if "NVIDIA" in result["value"].split():
            nvInfo["pass"] = True
         
        return nvInfo


    ##           
    # \brief Verifies the settings in the hosts file
    # \return object with results of process
    #
    def checkDaemonConfig(self, filename="/etc/aqueti/daemonConfiguration.json"):
        daemonInfo = {"pass":False, "valid":[],"invalid":[]}

        info = FileInterface.readJson( filename )
        try:
            if info == False:
                print("ERROR: Unable to read daemonConfiguration file: "+str(filename))
                daemonInfo["pass"] = False
                return daemonInfo

        except:
            print("ERROR: AquetiDaemon may not be installed")

            return daemonInfo
      

        #Check storage directory
        if not "submodule" in info.keys():
            print("ERROR: invalid configuration file. No submodule list")
            daemonInfo["pass"] = False
            return daemonInfo

        #Loop through submodules to find Coeus (storage) module
        storage = False
        for item in info["submodule"]:
            if item["type"] == "Coeus":
               validStorage = True
               if "storageDirs" in item.keys():
                  for path in item["storageDirs"]:
                      entry={}
                      entry["errors"] = []
                      entry["path"] = path
                      pinfo = CommandParser.validateFile(path)

                      valid = True
                      if not pinfo["exists"]:
                          entry["errors"].append("directory does not exit")
                          valid = False
                      else:
                          if not pinfo["d"]:
                              entry["errors"].append("not a directory")
                              valid = False
                          if not pinfo["r"]:
                              entry["errors"].append("not a readable")
                              valid = False
                          if not pinfo["w"]:
                              entry["errors"].append("not writeable")
                              valid = False
                          if not pinfo["x"]:
                              entry["errors"].append("not executable")
                              valid = False

                      if valid:
                          daemonInfo["valid"].append(entry)
                      else:
                          daemonInfo["invalid"].append(entry)
                          validStorage = False
                          
               else:
                  validStorage = False

        if validStorage:
            daemonInfo["pass"] = True
        else:
            daemonInfo["pass"] = False

        return daemonInfo

##
# \brief run unit tests to ensure the script is working
# \param [in] verbose verbosity level (0,1)
# 
# This should not be run on production systems
#
def test(verbose = 0):
    #Get information about the time and the machine
    ts = str(datetime.now().timestamp())

    cmd = "cat /etc/machine-id"
    res = CommandParser.runCommand(cmd)
    machineId = res["value"]
   
    testResult = {}
    testResult["timestamp"] = ts
    testResult["machine-id"] = machineId
    testResult["version"]   = VERSION
    testResult["pass"]     = True

    testResult["data"] = {}
    testResult["firewall"] = {"pass":True, "errors":[], "warnings":[]}
    testResult["systemName"] = {"pass":True, "errors":[], "warnings":[]}


    #############################################
    # Check firewall
    #############################################
    #Enable firewall
    cmd = "sudo service ufw restart"
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        msg = "Unable to execute command: "+cmd
        testResult["firewall"]["errors"].append(msg)

    else:
        #Check should fail with firewall initalling incorrect
        cmd = "./AquetiConfigurator.py depends.json -checkFirewall" 
        result = CommandParser.runCommand(cmd)

        if "firewall is valid" in result["value"].splitlines()[-1]:
            msg = "Firewall shows valid when it should by enabled"
            testResult["firewall"]["errors"].append(msg)
            testResult["firewall"]["pass"] = True


        ####
        # change firewall to fix it
        ####
        #Check should fail with firewall initalling incorrect
        cmd = "./AquetiConfigurator.py depends.json -disableFirewall" 
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            msg = "Unable to change firewall with command: "+cmd
            testResult["firewall"]["errors"].append(msg)
            testResult["firewall"]["pass"] = False
            testResult["pass"] = False
           
        else:
            # Check the firewall again
            #Check should fail with firewall initalling incorrect
            cmd = "./AquetiConfigurator.py depends.json -checkFirewall" 
            result = CommandParser.runCommand(cmd)

            if "firewall is valid" not in result["value"].splitlines()[-1]:
                msg = "Firewall shows invalid when it should by enabled after change"
                testResult["firewall"]["errors"].append(msg)
                testResult["firewall"]["pass"] = False
                testResult["pass"] = False

    #############################################
    # Check set system
    #############################################
    #Record initial system name
    cmd = "sudo ./AquetiConfigurator.py depends.json -checkSystem |tail -n 1"
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        print("RESULT: "+json.dumps(result, indent=4))
        msg = "Unable to execute command: "+cmd
        testResult["systemName"]["errors"].append(msg)
        testResult["systemName"]["pass"] = False
        testResult["pass"] = False

    else:
        try:
            systemInfo = json.loads(result["value"])
        except:
            msg = "Unable to convert return to dictionary for command "+cmd
            testResult["systemName"]["errors"].append(msg)
            testResult["systemName"]["pass"] = False
            testResult["pass"] = False
    


    if testResult["systemName"]["pass"]:
        try:
            name = systemInfo["valid"]["system"]
        except:
            msg = "Invalid system name in config file"
            testResult["systemName"]["errors"].append(msg)
            testResult["systemName"]["pass"] = False
            testResult["pass"] = False

    if testResult["systemName"]["pass"]:
        #Change to a new name
        name2 = name + "_test"
        cmd = "sudo ./AquetiConfigurator.py depends.json -changeSystem "+name2
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            print("RETURN: "+json.dumps(result, indent=4))
            msg = "Unable to execute command:: "+cmd
            testResult["systemName"]["errors"].append(msg)
            testResult["systemName"]["pass"] = False
            testResult["pass"] = False

    #Check new name
    if testResult["systemName"]["pass"]:
        cmd = "sudo ./AquetiConfigurator.py depends.json -checkSystem |tail -n 1"
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            msg = "Unable to execute command - "+cmd
            testResult["systemName"]["errors"].append(msg)
            testResult["systemName"]["pass"] = False
            testResult["pass"] = False

        else:
            try:
                systemInfo = json.loads(result["value"])
            except:
                msg = "Unable to convert return to dictionary for command "+cmd
                testResult["systemName"]["errors"].append(msg)
                testResult["systemName"]["pass"] = False
                testResult["pass"] = False

        if testResult["systemName"]["pass"]:
            try:
                if systemInfo["valid"]["system"] != name2:
                   msg = "Unable to change system name to "+name2
                   testResult["systemName"]["errors"].append(msg)
                   testResult["systemName"]["pass"] = False
                   testResult["pass"] = False
            except:
                msg = "Error with changed file"
                testResult["systemName"]["errors"].append(msg)
                testResult["systemName"]["pass"] = False
                testResult["pass"] = False

        else:
            print("Failed to change name")

        #Change to previous name
        cmd = "./AquetiConfigurator.py depends.json -changeSystem "+name
        result = CommandParser.runCommand(cmd)

        return testResult

        if result["returnCode"]:
            msg = "Unable to execute command "+cmd
            testResult["systemName"]["errors"].append(msg)
            testResult["systemName"]["pass"] = False
            testResult["pass"] = False


    return testResult

##
# \brief Main function
if __name__ == "__main__":

    epilog = """\
Examples: 
   sudo ./AquetiConfigurator.py depends.json -configure
   sudo ./AquetiConfigurator.py depends.json -checkSoftware 
   sudo ./AquetiConfigurator.py depends.json -update 
   sudo ./AquetiConfigurator.py depends.json -changeSysctl
   sudo ./AquetiConfigurator.py depends.json -changeSysctl '{"net.core.rmem_default":200000}'
"""

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=str("AQUETI System Configurator"+str(VERSION)), epilog = epilog)
    parser.add_argument("depends", action="store", help="file with software dependency information")

    parser.add_argument("-check", action="store_const", dest="check", const=True, help="Full system check")
    parser.add_argument("-checkSoftware", action="store_const", dest="checkSoftware", const=True, help="check existing software compatibility")
    parser.add_argument("-upgrade", action="store", nargs=1, dest="upgrade", help="upgrades the software component specified")
    parser.add_argument("-update", action="store_const", dest="update", const="True", help="upgrades the system software")
    parser.add_argument("-configure", action="store_const", dest="configure", const="True", help="Upgrades all supported functionality")
    parser.add_argument("-checkNTP", action="store_const", dest="checkNTP", const=True, help="verifies sysctl settings")
    parser.add_argument("-checkSysctl", action="store_const", dest="checkSysctl", const=True, help="verifies sysctl settings")
    parser.add_argument("-changeSysctl", action="store", dest="changeSysctl", nargs='?', const=True, help="verifies sysctl settings")
    parser.add_argument("-checkSystem", action="store_const", dest="checkSystem", const=True, help="verifies sysctl settings")
    parser.add_argument("-changeSystem", action="store", dest="changeSystem", help="verifies sysctl settings")
    parser.add_argument("-checkLimits", action="store_const", dest="checkLimits", const=True, help="verifies sysctl settings")
    parser.add_argument("-changeLimits", action="store", dest="changeLimits", nargs='?', const=True, help="verifies sysctl settings")
    parser.add_argument("-checkHostsFile", action="store_const", dest="checkHosts", const=True, help="checks the /etc/hosts file")
    parser.add_argument("-changeHostsFile", action="store_const", dest="changeHosts", const=True, help="modifies the /etc/hosts file")
    parser.add_argument("-checkDaemonConfig", action="store_const", dest="checkDaemonConfig", const=True, help="checks the /etc/hosts file")
    parser.add_argument("-disableFirewall", action="store_const", dest="disableFirewall", const=True, help="changes the firewall status")
    parser.add_argument("-checkFirewall", action="store_const", dest="checkFirewall", const=True, help="checks the firewall status")
    parser.add_argument("-checkNVidia", action="store_const", dest="checkNVidia", const=True, help="checks the firewall status")
    parser.add_argument("-changeNVidia", action="store_const", dest="changeNVidia", const=True, help="changes the firewall status")
    parser.add_argument("-dpkgPath", action="store", dest="dpkgPath", help="path to dpkg files to install")


    parser.add_argument("-v", action="store_const", dest="verbose", const=True, help="Verbose output")
    parser.add_argument("-test", action="store_const", dest="test", const=True, help="Run Unit test")
    args = parser.parse_args()


    verbose = False
    if args.verbose:
        verbose = True

    dpkgPath = DPKG_PATH

    checkInfo = {}
  
    if args.test:
        result = test()
        print("result: "+json.dumps(result, indent=4))
        exit(1)
      


    #If we have a dependcy file, load it.
    if args.depends:
        filename = args.depends

        try:
            with open(filename, 'r') as f:
                depends = json.load(f)
        except:
            depends = None
    else:
        depends = None
  
    if args.dpkgPath:
        dpkgPath = args.dpkgPath

    #Create the configurator class
    configurator = Configurator(depends)

    #if configure then do everything
    if args.configure:
        args.update          = True
        args.changeSysctl    = True
        args.changeLimits    = True
        args.changeHosts     = True
        args.disableFirewall = True
        args.changeNVidia    = True

    #If update is specified, then update the system
    if args.update:
        configurator.updateSystem(dpkgPath)
        print()

    if args.upgrade:
        target = args.upgrade[0]
        if len(args.upgrade) > 1:
            version = args.upgrade[1]
        else:
            version = None

        result = configurator.upgrade(target, version, dpkgPath)
        print()

    if args.changeHosts:
        info = configurator.changeHostsFile()

    if args.changeNVidia:
        info = configurator.changeNVidia()
 
    if args.changeSysctl:
        #If we're a boolean, no values provided
        if isinstance( args.changeSysctl, bool):
            result = configurator.changeSysctl()

        else:
            #Try to convert to JSON
            try:
                data = json.loads( args.changeSysctl )
            except:
                print("ERROR: Unable to create object from "+args.changeSysctl )
                exit()

            print("DATA:\n"+json.dumps(data, indent=4 ))
            result = configurator.changeSysctl(data = data )

        if result:
            print("Successfully changed sysctl")
            info = configurator.checkSysctl()
        else:
            print("Unable to change sysctl")

    if args.changeLimits:
        #If we're a boolean, no values provided
        if isinstance( args.changeLimits, bool):
            result = configurator.changeSystemLimits ()
        else:
            result = configurator.changeSystemLimits ()

        if result:
            print("Successfully changed system limits")
            info = configurator.checkLimits()
        else:
            print("Unable to change system limits")

        #Change User limits
        if isinstance( args.changeLimits, bool):
            result = configurator.changeUserLimits ()
        else:
            result = configurator.changeUserLimits ()

        if result:
            print("Successfully changed system limits")
            info = configurator.checkLimits()
        else:
            print("Unable to change system limits")


        



    if args.check:
        args.checkSoftware     = True
        args.checkHosts        = True
        args.checkNTP          = True
        args.checkSysctl       = True
        args.checkLimits       = True
        args.checkDaemonConfig = True
        args.checkFirewall     = True
        args.checkNVidia       = True


    if args.checkSoftware:
        info = configurator.checkDependencies()

        print
        checkInfo["software"] = {}
        checkInfo["software"]["pass"] = True

        if isinstance( info, dict):
            for k in info.keys():
                checkInfo["software"][k] = info[k]

            if len(info["invalid"].keys()) > 0:
                print("WARNING: Software check did not pass!")
                checkInfo["software"]["pass"] = False
        else:
            checkInfo["software"]["pass"] = False

    if args.checkNVidia:
        info = configurator.checkNVidia()
        checkInfo["nvidia"] = {}
        checkInfo["nvidia"]["pass"] = False

        if isinstance(info, dict):
            for k in info.keys():
                checkInfo["nvidia"][k] = info[k]
            if len(info["invalid"]) > 0:
                print("WARNING: nvidia file check did not pass!")
                checkInfo["nvidia"]["pass"] = False
            elif len(info["valid"]) > 0:
                checkInfo["nvidia"]["pass"] = True
                
        else:
            checkInfo["nvidia"]["pass"] = False
   
     

    if args.checkHosts:
        info = configurator.checkHostsFile()
        checkInfo["hostsFile"] = {}
        checkInfo["hostsFile"]["pass"] = False

        if isinstance(info, dict):
            for k in info.keys():
                checkInfo["hostsFile"][k] = info[k]
            if len(info["invalid"]) > 0:
                print("WARNING: hosts file check did not pass!")
                checkInfo["hostsFile"]["pass"] = False
            elif len(info["valid"]) > 0:
                checkInfo["hostsFile"]["pass"] = True
                
        else:
            checkInfo["hostsFile"]["pass"] = False
   
    if args.checkNTP:
        info = configurator.checkNTP()
        checkInfo["ntp"] = {} 
        checkInfo["ntp"]["pass"] = False
 
        if isinstance(info, dict):
            for k in info.keys():
                checkInfo["ntp"][k] = info[k]
            if len(info["invalid"]) > 0:
                print("WARNING: ntp file check did not pass!")
                checkInfo["ntp"]["pass"] = False
            elif len(info["valid"]) > 0:
                checkInfo["ntp"]["pass"] = True
        else:
            checkInfo["ntp"]["pass"] = False
       

    if args.checkSysctl:
        info = configurator.checkSysctl()
        checkInfo["sysctl"] = {} 
        checkInfo["sysctl"]["pass"] = False
 
        if isinstance(info, dict):
            for k in info.keys():
                checkInfo["sysctl"][k] = info[k]
            if len(info["invalid"]) > 0:
                print("WARNING: sysctl file check did not pass!")
                checkInfo["sysctl"]["pass"] = False
            elif len(info["valid"]) > 0:
                checkInfo["sysctl"]["pass"] = True
        else:
            checkInfo["sysctl"]["pass"] = False

    if args.checkLimits:
        info = configurator.checkLimits()

        checkInfo["limits"] = {} 
        checkInfo["limits"]["pass"] = False
 
        if isinstance(info, dict):
            for k in info.keys():
                checkInfo["limits"][k] = info[k]
            if len(info["invalid"]) > 0:
                checkInfo["limits"]["pass"] = False
            elif len(info["valid"]) > 0:
                checkInfo["limits"]["pass"] = True
        else:
            print("L2")
            checkInfo["limits"]["pass"] = False


    if verbose:
        print("CheckInfo:"+json.dumps( checkInfo, indent=4))
    else:
        for key in checkInfo.keys():
            warnings = False
            #Print any warnings
            if "warnings" in checkInfo[key].keys():
                for item in checkInfo[key]["warnings"]:
                    print("\t"+key+":"+item)
                    warnings = True


            if checkInfo[key]["pass"]:
                if warnings:
                    print(key+" check passed with warnings")
                else:
                    print(key+" check passed")
            else:
                print(key+" check failed!")

    if args.checkDaemonConfig:
        info = configurator.checkDaemonConfig()

        if verbose:
            print("daemonConfig: "+json.dumps(info,indent=4))

        else:
            if len(info["invalid"]) == 0:
                print("daemonConfig is valid")
            else:
                print("daemonConfig is not valid")
                print(json.dumps(info["invalid"]))



    if args.disableFirewall:
        info = configurator.disableFirewall()
        if verbose:
           print("firewall: "+json.dumps(info,indent=4))

        if info:
            print("Firewall change success")
        else:
            print("ERROR: unable to change firewall")


    if args.checkFirewall:
        info = configurator.checkFirewall()
        if verbose:
           print("firewall: "+json.dumps(info,indent=4))

        else:
            if info["pass"] == True:
                print("firewall is valid")
            else:
                print("firewall is not valid")

    if args.changeSystem:
        print("Changing system to "+args.changeSystem)
        result = configurator.changeSystemName(args.changeSystem)

        print("Result: "+str(result))

    if args.checkSystem:
        result = configurator.checkSystemName()
        print("Result:\n"+json.dumps(result))
              

#    print(json.dumps( checkInfo, indent=4))
