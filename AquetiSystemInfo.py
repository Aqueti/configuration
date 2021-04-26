#!/usr/bin/python3
import subprocess
from datetime import datetime
import json
import re
import argparse
import CommandParser
import sys
import copy

VERSION = "-1.0.0"


##
# \brief class that extracts hachine hardware information
class SystemInfo:
    def __init__(self):
        self.config = {}
        self.OS = None

        #Directories of Interest
        self.systemDirs = ["/", "/var", "/tmp", "/home"]
        self.dependencies={}
        self.dependencies["vim"]={"version":{"match":"gt","version":"2.0","level":"warning"}}

        #Get timestamp when this was created
        now = datetime.now()
        timestamp = datetime.timestamp(now)

        #Figure out our OS for future reference
        result = CommandParser.runCommand("cat /etc/lsb-release")
        if result["returnCode"] != 0:
            sys.stderr.write("Unable to access ls-release")
        
        else:
            lines = result["value"].splitlines(1)
            for line in lines:
                info = line.split("=")
                if info[0] == "DISTRIB_RELEASE":
                    self.OS = info[1].rstrip()


    ##
    # \brief return the OS version
    def getOS(self):
        return self.OS

    ##
    # \brief Updates all 
    #
    def updateAll(self):
       self.info = {}
       self.info["version"]     = VERSION
       self.info["machineInfo"] = self.updateMachineInfo()
       self.info["systemInfo"]  = self.updateSystemInfo()
       self.info["packageInfo"] = self.updatePackageInfo()
       return self.info

    ##
    # \brief update machine hardare information
    #
    # This script extracts hardware specific information from the machine
    #
    def updateMachineInfo(self):
        machineInfo = {}
        #get machine info
        result = CommandParser.runCommand("cat /etc/machine-id")
        if result["returnCode"] != 0:
            sys.stderr.write("Failed to read machine-id")
            return False
            
        machineInfo["machine-id"] = result["value"]
        machineInfo["partitions"] = {}
        machineInfo["memory"] = {}
        machineInfo["CPU"] = {}
        machineInfo["PCI"] = {}
            
        #get partition table
        result = CommandParser.runCommand("df -h")
        if result["returnCode"] != 0:
            sys.stderr.write("Unable to read partitiion table")
        else:
            lines = result["value"].splitlines(1)

            for line in lines:
                #Check for each systemDir item
                for item in self.systemDirs:
                    if str(item+"\n") in line:
                        values = re.findall(r"\S+", line)
                        machineInfo["partitions"][item] = {}
                        machineInfo["partitions"][item]["harddrive"] = values[0]
                        machineInfo["partitions"][item]["size"] = values[1]
                        machineInfo["partitions"][item]["used"] = values[2]
                        machineInfo["partitions"][item]["avail"] = values[3]
                        machineInfo["partitions"][item]["percentUse"] = values[4]
                        machineInfo["partitions"][item]["mountPoint"] = values[5]

        #Get memory info
        result = CommandParser.runCommand("free -h")
        if result["returnCode"] != 0:
            sys.stderr.write("Unable to read available memory")

        lines = result["value"].splitlines(1)
        for line in lines:
            #skip the first line
            if line[0] == " ":
                continue

            info = re.findall(r"\S+", line)
            if info[0] == "Mem:":
                machineInfo["memory"]["RAM"] = info[1]
            elif info[0] == "Swap:":
                machineInfo["memory"]["Swap"] = info[1]


        #Get CPU Info
        result = CommandParser.runCommand("cat /proc/cpuinfo")
        lines = result["value"].splitlines(1)

        cpuInfo = {}
        cores = None
        model = None
        for line in lines:
            if "processor" in line: 
                cores = line[12:].rstrip()
            if "model name" in line: 
                model = line[12:].rstrip()

        cpuInfo["cores"] = int(cores)+1
        cpuInfo["model"] = model

        machineInfo["CPU"] = cpuInfo
    
        #Get NIC and GPU information
        result = CommandParser.runCommand("lspci")
        lines = result["value"].splitlines(1)

        GPUData = []
        NICData = []
        for item in lines:
            #Get slot info
            itemData = {}
            itemInfo = item.split(" ")
            itemData["slot"] = itemInfo[0]

            pciType = item[8:].split(":")[0]
            itemData["description"] = item[8:].split(":")[1]


            #Find our VGA controller, try to extract manufacturer
            if pciType == "VGA compatible controller":
                itemInfo = item.split(" ")
                if item.find("NVIDIA"):
                    itemData["brand"] = "NVIDIA"
                    
                    #find card type
                    start = item.find("[")+1
                    end   = item.find("]")
                    itemData["type"]=item[start:end]

                GPUData.append(itemData)

            #Find NIC information
            elif pciType == "Network controller" or pciType == "Ethernet controller":
                if item.find("Intel") > -1:
                    itemData["brand"] = "Intel"
                elif item.find("Realtek") > -1:
                    itemData["brand"] = "Realtek"

                #get a list of network devices by looking at /sys/class/net/
                result = CommandParser.runCommand("ls /sys/class/net/")
                if result["returnCode"] != 0:
                    sys.stderr.write("Unable to extract NIC information")
                else:
                    #Get a list of NIC directories
                    result = CommandParser.runCommand(str("ls /sys/class/net/"))
                    if result["returnCode"] != 0:
                        sys.stderr.write("Unable to access /sys/class/net/\n")
                    else:
                        nics = result["value"].split()
                        for nic in nics:
                            if nic == "lo":
                                continue

                            # Get Slot
                            #See if the device directory is a dynamic link, extract slot
                            result = CommandParser.runCommand(str("ls -al /sys/class/net/"+nic+"/device"))
                            if result["returnCode"] != 0:
                                sys.stderr.write("Unable to access /sys/class/net/"+nic+"/device")
                            else:
                                pciLink = result["value"]
                                if pciLink.find(itemData["slot"]) > -1:
                                    result = CommandParser.runCommand("cat /sys/class/net/"+nic+"/address")
                                    if result["returnCode"] != 0:
                                        sys.stderr.write("Unable to extract network address\n")
                                    else:
                                        MAC = result["value"]
        
                                    #Found it, now fill in the detais
                                    itemData["MAC"] = MAC
                                    itemData["NIC"] = nic
                         
                                    NICData.append(itemData)


        #set PCI information
        machineInfo["PCI"]["GPU"] = GPUData
        machineInfo["PCI"]["NIC"] = NICData

        return machineInfo

    ## 
    # \brief function get gets the system information
    #
    def updateSystemInfo(self):
        systemInfo ={}
        result = CommandParser.runCommand("uname -a")
        if result["returnCode"] != 0:
            sys.stderr.write("Unable to extract kernel information")
        else:
            #Extract the kernel info from the output
            info = result["value"].split(" ")
            kernelInfo = {}
            kernelInfo["sysname"]  = info[0]
            kernelInfo["nodename"] = info[1]
            kernelInfo["release"]  = info[2]
            kernelInfo["version"]  = info[3]
            kernelInfo["machine"]  = info[4]

            systemInfo["kernel"] = kernelInfo

        #Extract distribution info
        distInfo={}
        result = CommandParser.runCommand("cat /etc/lsb-release")
        if result["returnCode"] != 0:
            sys.stderr.write("Unable to access lsb-release")
        else:
            info = result["value"]
            for line in info.splitlines(1):
                data = line.split("=")
                if data[0] == "DISTRIB_ID":
                    distInfo["id"] = data[1].rstrip()
                elif data[0] == "DISTRIB_RELEASE":
                    distInfo["release"] = data[1].rstrip()
                elif data[0] == "DISTRIB_CODENAME":
                    distInfo["code"] = data[1].rstrip()
                elif data[0] == "DISTRIB_DESCRIPTION":
                    distInfo["description"] = data[1].rstrip().strip('\"')
            systemInfo["dist"] = distInfo

        return systemInfo

    ##
    # \brief updates the network configuration information
    def updateNetworkInfo(self):
        return

    ## 
    # \brief function that updates GPU information
    #
    def updateGPUInfo(self):
        return

    ##
    # \brief this function is used to get information about installed packages
    #
    def updatePackageInfo(self):
        packageInfo = {}

        #get package list
        result = CommandParser.runCommand("dpkg --list")
        if result["returnCode"] != 0:
            sys.stderr.write("Unable to access package list")
        else:

            packages = result["value"]
            #parse each line
            lines = packages.splitlines(1)

            #Loop through all lines and add to the database
            data = {}
            for line in lines:
                #Wait until we get our first value
                if line[0:2] != "ii":
                   continue


                #This is space delimited on LUbuntu. Need to validate on other systems
                statusInfo  = str(line[0:4])
                name    = str(line[4:42]).rstrip().lstrip()
                version = str(line[42:85]).rstrip().lstrip()
                arch    = str(line[86:99]).rstrip().lstrip()

                data[name] = {}

                #split status 
                if statusInfo[2] != " ":
                    data[name]["status"] = "ERROR"
                elif statusInfo[1] == "i":
                    data[name]["status"] = "Installed"
                elif statusInfo[1] == "n":
                    data[name]["status"] = "Not Installed"
                else:
                    data[name]["status"] = "Unknown"
                    
                #Fill in additional info
                data[name]["version"] = version
                data[name]["arch"]    = arch

            packageInfo  = data

        return packageInfo


if __name__ == "__main__":
    full = True
    hw = False
    system = False



    parser = argparse.ArgumentParser(description=str("AQUETI Validation Script "+str(VERSION)))
    parser.add_argument("-hw", action="store_const", dest="hw", const="True", help="Query Hardware Information")
    parser.add_argument("-system", action="store_const", dest="system", const="True", help="Query System Information")
    parser.add_argument("-all", action="store_const", dest="all", const="True", help="Query System Information")
    parser.add_argument("-packages", action="store_const", dest="packages", const="True", help="Query System Information")
    parser.add_argument("-outFile", action="store", dest="outFile", help="Specify output file")
    parser.add_argument("-test", action="store_const", dest="test", const="True", help="Query System Information")
    args = parser.parse_args()

    system = SystemInfo()

    #Initialize the system
    result = {}

    if args.test:
        CommandParser.test()
        exit(1)

    #This is the result data
    if args.all:
        result = system.updateAll()
        full = False

    else:
        if args.hw:
            full = False
            info = system.updateMachineInfo()
            result["machineInfo"] = info
        if args.system:
            full = False
            info = system.updateSystemInfo()
            result["systemInfo"] = info
        if args.packages:
            full = False
            info = system.updatePackageInfo()
            result["packages"] = info
        if args.all:
            print("updating all")
            full = True

    #Print the output
    if args.outFile:
        with open(args.outFile, 'w')  as outfile:
            json.dump(result, outfile, sort_keys= True, indent=4)
        
    else:
        print(json.dumps(result, sort_keys= True, indent=4))

