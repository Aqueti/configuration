#!/usr/bin/python3
###########################################################
# NetworkManager.py
#
# This file contains the tools to manage and configure the
# network settings for a device. 
###########################################################
import json
import CommandParser
import argparse
import copy
from datetime import datetime
import hashlib
import socket
import struct
import time
import yaml

#from deepdiff import DeepDiff

VERSION="0.0.1"
DEFAULT_CONFIGURATION="""
{
    "nameservers":{
        "search": ["mydomain", "otherdomain"],
        "addresses":["8.8.8.8",1,1,1,1]
    }
}
"""
NETPLAN_DIR  = "/etc/netplan/"
NETPLAN_FILE = "01-netcfg.yaml"
BAK_DIR = "/var/log/aqueti/etc/netplan/"

##
# \brief read in the netplan informtion
# \param [in] source file to load the data from 
# \return an object with an array of comments and a yaml data object
#
# This function returns the comments and data for a yaml file. 
# {
#     "comments"[...],
#     #data":{...}
# }
# Where the comments are an array of comment lines beginning with # and
# data refers to the yaml data in the file
def readYaml( source ):
    yamlData = {"comments":[]}
    #pull off comments
    with open( source, 'r') as fptr:
        fileInfo = fptr.read()

    lines = fileInfo.splitlines(1)
    index = 0
    yd = ""
    for line in lines:
        if line[0] == "#":
            yamlData["comments"].append(line.strip())
            index = index + 1

        else:
            yd = yd + line

    yData = yaml.load(yd)

    yamlData["data"] = yData
    return yamlData


##
# \brief writes the data in a yaml object to a file
#
# This function will write the lines in the "comments" array in the yData
# object as a header to the yaml file. The information in the "data"
# object will then be added in yaml form.
def writeYaml( dest, yData ):

    #make sure yData is an object
    if not isinstance( yData, object):
        print("ERROR: writeYaml can only write objects")

    if not "data" in yData.keys():
        print("ERROR: writeYaml assumes an object with a yaml sub-object")
        return False

    data = ""
    
    #Add all comments provided
    if "comments" in yData.keys():
        for line in yData["comments"]:
            data = data+line+"\n"

    #Add the yaml data to the buffer
    data = data + yaml.dump(yData["data"], default_flow_style=False)

    with open(dest, 'w') as fptr:
        fptr.write(data)
    fptr.close()

    #Verify data was properly written
    d2 = readYaml( dest )
    if d2 != yData:
        print("Saved data does not match")
        print("yData:\n"+json.dumps(yData,indent=4))
        print("d2:\n"+json.dumps(d2,indent=4))
        return False

    return True

##
# \breif reads the existing netplan file into memory
def readNetplan(filename = NETPLAN_DIR+NETPLAN_FILE):
    yData = readYaml(filename)
    return yData

##
# \brief Function to write netplan data
def updateNetplan(data, verifyIP=None, filename = NETPLAN_DIR+NETPLAN_FILE ):

    #Make sure we're sudo
    if not CommandParser.checkSudo():
        print("Must be a sudo user to write a netplan file")
        return False

    origData = readNetplan()
    origSuccess = validateNetplan()

    #Write the data
    #SDF consider a function to validate data
    print("...updating file")
    ydata = {}
    ydata["data"] = data
    success = writeYaml( filename, data)
    if not success:
        print("Unable to write netplan information to "+filename)
        return False

    #Apply netplan apply
    print("...applying changes")
    cmd = "netplan apply"
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        print("Unable to apply netplan")
        print("Result:\n"+json.dumps(result, indent=4))
        success = False

    #Restart interfaces
    print("...restarting interfaces")
    for item in getInterfaces():
        if item != "lo":
            #Disable
            changeState(item, {"state":"DOWN"})

    for item in getInterfaces():
        if item != "lo":
            changeState(item, {"state":"UP"})


    #If all good, check validate the 
    if success:
        time.sleep(2)
        print("...validating change")
        success = validateNetplan()

    #Make sure we can ping the verifyIP. If not, failure
    if success and verifyIP != None:
        print("...pinging "+verifyIP+ " to verify configuration")
        success = CommandParser.ping(verifyIP)
        if not success:
            print("FAILURE: Unable to ping "+verifyIP+" after changes")


    #All should be good, If not, and we've been asked to check, restore
    #previous data
    restoreSuccess = True
    if not success:
        print("...restoring the original settings")
        restoreSuccess = writeYaml( filename, origData )

        #reapply the netplan
        if restoreSuccess:
            cmd = "netplan apply"
            result = CommandParser.runCommand(cmd)
            if result["returnCode"]:
                print("Unable to apply netplan")
                print("Result:\n"+json.dumps(result, indent=4))
                restoreSuccess = False

        #Validate the restored netplan
        if restoreSuccess:
            print("...validating restored data")
            time.sleep(1)
            restoreSuccess = validateNetplan()

        if not restoreSuccess and origSuccess:
            print("ERROR: System validation failed. Network is in an unknown state")
            return False

        elif not restoreSuccess:
            print("WARNING: restored original file which is not valid")
        else:
            print("...system returned to the original state")

    return success

##
# \brief converts subnet to netmask entry
# \param [in] IPv4 netmask avlue
# \return Cidr representation or False on failure
#
def convertNetmaskToCidr(netmask):
    #Make sure it's a valid netmask
    if not isinstance(netmask, str):
        print("A netmask must be string of the form xxx.xxx.xxx.xxx")
        return False
    arr = netmask.split(".")
    if len(arr) < 4:
        print("A netmask must be of the form xxx.xxx.xxx.xxx")
        return False

    for item in arr:
        try:
            int(item)
        except:
            print("All netmask entries must be integers")
            return False

    if int(arr[0]) < 0 or int(arr[0]) > 255:
        print("First netmask entry must be between 0 and 254")
        return False
            
    if int(arr[1]) < 0 or int(arr[1]) > 255:
        print("Last netmask entry must be between 0 and 255")
        return False

    if int(arr[2]) < 0 or int(arr[2]) > 255:
        print("Last netmask entry must be between 0 and 255")
        return False

    if int(arr[3]) < 0 or int(arr[3]) > 255:
        print("Last netmask entry must be between 0 and 255")
        return False


    #All is good. Do the conversion
    return (sum([bin(int(bits)).count("1") for bits in netmask.split(".") ]))

##
# \brief converts a Cidr representation to netmask
# \param [in] cidr integer representation of a netmask
# \return string of the form "xxx.xxx.xxx.xxx" or False on failure
#
def convertCidrToNetmask( cidr ):
    if not isinstance(cidr, int):
        print("ERROR: convertCidrToNetmask: cidr must be an integer between 0 and 32")
        return False

    if cidr < 0 or cidr > 32:
        print("ERROR: convertCidrToNetmask: cidr ("+str(cidr)+") must be between 0 and 32")
        return False

    #Calculate netmask
    maskbits = 32 - int(cidr)

    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << maskbits)))

    return netmask

##
# \brief describes network interfaces settings
# \param [in] iface specifies which interface to query. If set to None, all interfaces will be returned
# \return object of interfaces and their settings on success, False on failure
#
# If no interaces is provided, this function will return an
def getState( iface = None ):

    #interfaceInfo = {"interfaces":{}}
    interfaces = getInterfaces()

    #Get a list of interfaces
    result = CommandParser.runCommand("ip maddress show")
    if result["returnCode"] != 0:
        print("unable to  run command 'ip address show'. Exiting")
        return False

    #If we are looking for a specific interface, make sure it exists
    if iface != None:
        if not iface in interfaces:
            print("Interface "+iface+" not found. Unable to get information")
            return False

    interfaceInfo = {} 


    #Query information about each interface
    for interface in interfaces:

        #Check if this is an interface we are looking for. If not, continue
        #to the next interface
        if iface != None and interface != iface:
            continue


        entry = {}
        entry["addresses"] = []
        entry["dhcp4"] = False

        result = CommandParser.runCommand("ip address show "+interface+" |grep inet |grep -v inet6")
        if result["returnCode"] == 0:
            #Split the return value into lines
            lines = result["value"].splitlines(1)

            #The first line for each NIC has a value in the first byte
            for line in lines:
                arr = line.split()

                entry["addresses"].append(arr[1])

                #Extract scope and broadcast information
                index = 2
                scope     = None
                broadcast = None
                while index < len(arr):
                    if arr[index] == "brd":
                        entry["broadcast"] = arr[index+1]
                        index = index + 2
                    elif arr[index] == "scope":
                        entry["scope"] = arr[index+1]
                        index = index + 2
                    elif arr[index] == "dynamic":
                        entry["dhcp4"]=True
                        dynamic = True
                        index = index + 1
                    else:
                        index = index+1
                    
        cmd = "ip link show "+interface
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            print("Unable to query link for "+interface)
        else:
            lines = result["value"].splitlines(1)
            
            #Loop through the entries of the first line and extract inf
            linkArray = lines[0].split()
            entry["state"] = linkArray[2]

            values = ["mtu", "qdisc", "state", "mode", "group", "qlen"]

            for value in values:
                try:
                    index = linkArray.index(value)
                    if index >= 0:
                        if value == "mtu" or value == "qlen":
                            entry[value] = int(linkArray[index+1])
                        else:
                            entry[value] = linkArray[index+1]
                except:
                    print(value+" not available")

        #Command to get the gateway. 
        if interface != "lo":
            cmd = "ip route |grep "+interface
            result = CommandParser.runCommand(cmd)
            if result["returnCode"]:
#                print("Unable to get route information for interface "+interface)
                pass
            else:
                lines = result["value"].splitlines(1)
                for line in lines:
                    arr = line.split()
                    if "default" in line:
                        entry["gateway4"] = arr[2]
                        break
                    else:
                        entry["gateway4"] = arr[-1]

        #get the nameservers, if they are set. They are not required
        cmd = "systemd-resolve --status |grep DNS |grep  Servers"
        result = CommandParser.runCommand(cmd)

        #SDF This may be needed later.
        #For each line, assign to the approprite interface.
        for line in result["value"].splitlines(1):
            nameserver = line.split(": ")[1]

        #Add interface
        interfaceInfo[interface] = entry

    result = {}
    result["comments"] = ["# Queried system state"]
    result["data"] = interfaceInfo
    return result

##
# \brief get the interfaces in the system
# \return array of interfaces
def getInterfaces():
    interfaces = []

    #Get a list of interfaces
    result = CommandParser.runCommand("ip maddress show")
    if result["returnCode"] != 0:
        print("unable to  run command 'ip address show'. Exiting")
        return False

    lines = result["value"].splitlines(1)
    for line in lines:
        if line[0] > "0" and line[0] <= "9":
            arr =  line.split()
            interfaces.append(arr[1])


    return interfaces

##
# \brief function to verify the specified target is accessible by the system
# \param [in] target hostname or ip address of a target system to test against
#
def validateRemote( target, delay=10):

    result = CommandParser.ping(target)

    if not result:
        print("Unable to ping target: "+target+" after "+str(delay)+" seconds")
        print("Reverting interface "+target+" to previous state")

    return result


##
# \brief function to update and validate network settings
# \return True on success, false on failure
#
# This function modifies a network interface as specified and then
# veifies that the target system is accessible via a ping. If the 
# target system cannot be reached, the system will revert to the
# orginal configuration.
#
# The system will try to ping the target one a second for the given 
# delay. If not successful, the system will revert to the previous
# state.
#
def updateAndVerify( iface, address, netmask, target, mtu=None,delay=10 ):
    #record the current state
    info = getState()

    if not isinstance(delay, int):
        print("Delay values must be integers")
        return False

    if iface not in info["data"].keys():
        print("ERROR: Invalid interface name provided")
        return False

    #Record the old state
    oldState = info["data"][iface]

    #First, try to set the new IP address and netmask
    result = setInterfaceIP(iface, address, netmask, mtu=mtu)
    if not result:
        print("Failed to set the IP address")
        return False

    valid = validateTarget( target, delay )



##
# \brief changes the provided state settings
# \param [in] iface network interface name to change
# \param [in] values object that contains the fields to change
# \param [in] verifyIP ip address of a remote system to verify network configuration works
# \return object that describes the interface state
#
# Example state object
#        "enp4s0": {
#            "addresses": ["10.0.0.1/24"] ,
#            "dhcp4": false,
#            "scope": "global",
#            "state": "UP",
#            "mtu": 1500,
#            "qdisc": "fq_codel",
#            "mode": "DEFAULT",
#            "group": "default",
#            "qlen": 1000
#        },
#
def changeState( iface, values, verifyIP = None ):
    result = True 

    #Verify that we are in the proper state
    if not CommandParser.checkSudo():
        print("Must be sudo to change state")
        return False

    netplanFile = NETPLAN_DIR+NETPLAN_FILE
    NETPLAN_PARAMS=["addresses", "mtu", "gateway4","nameservers"]
    STATE_PARAMS=["state"]
    newState = {}

    #Make sure it's a valid interface
    if not iface in getInterfaces():
        print("ChangeState: Unknown interface "+iface)
        return False

    #If have more than state, we have to make changes. If not,
    #Skip to the state section
    if len( set(values.keys()) & set(NETPLAN_PARAMS)) > 0:
        print("...updating netplan parameters for "+iface)
        #Make sure the interface is up
        info = getState()
        if info["data"][iface]["state"].lower() == "down":
            cmd = "ip link set "+iface+" up"
            res = CommandParser.runCommand( cmd )
            if res["returnCode"]:
                print("ERROR: Unable to set link state to "+values[key].lower())
                return False
    
            #Wait for the command to settle
            time.sleep(1)
    
        #Extract current information
        info = getState()
        state = info["data"][iface]
        netplan = readNetplan()
    
        #Update fields with new data
        #SDF need to check for value keys that are not in state (error state)
        change = False
        for key in state.keys():
           if key in NETPLAN_PARAMS:
               if key in values.keys():
                   newState[key] = values[key]
                   if state[key] != values[key]:
                       change = True
               else:
                   newState[key] = state[key]

        for key in set(values.keys()) & set(NETPLAN_PARAMS):
            try:
                if state[key] != values[key]:
                    newState[key] = values[key]
                    change = True
            except:
                newState[key] = values[key]
                change = True
        
        if change:
            #Backup netplan file
            print("...Backing up file")
            backupFile = backupNetplan()
            if not backupFile:
                print("ERROR. Unable to backup netplan file. Unable to change state")
                return False
    
            #Write netplan file
            ydata = {}
            ydata["comments"] = []
            ydata["data"] = {}
            ydata["data"]["network"] = {}
            ydata["data"]["network"]["ethernets"] = {}
            print(iface+" - newSate:"+str(newState))
            ydata["data"]["network"]["ethernets"][iface] = newState
    
            print("...updating netplan")
            result = updateNetplan( ydata, verifyIP )
    
            if not result:
                print("ERROR Unable to change state")
            else:
                print("...successfully changed state")

    #Apply state info
    stateSuccess = True
    for key in values.keys():
        if key in STATE_PARAMS:
            if key == "state":
                if values[key].lower() == "up" or values[key].lower() == "down":
                    cmd = "ip link set "+iface+" "+values[key].lower()
                    res = CommandParser.runCommand( cmd )
                    if res["returnCode"]:
                        print("Unable to set link state to "+values[key].lower())
                        stateSuccess = False
                    else:
                        #Wait to reach required state
                        time.sleep(2)
                else:
                    print("ERROR: Unknown state value: "+values[key])
                    stateSuccess = False
    return stateSuccess and result

##
# \brief function to backup the netplan configuration file
# \param [in] dest destination directory for where to place a file
# \result this result returns False on failure or the backup filename on success
#
def backupNetplan(dest=BAK_DIR):
    #Check if BAK_DIR exists. If not create it
    result = CommandParser.validateFile(BAK_DIR)
    if not result["d"]:
        cmd = "mkdir -p "+BAK_DIR
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            print("FAILURE: Backup directory "+BAK_DIR+" does not exist and cannot be created")
            return False

    #Back up the old file to the BAK_DIR 
    ts = datetime.now().timestamp()
    netplanFile = NETPLAN_DIR+NETPLAN_FILE
    bakFile = dest+NETPLAN_FILE+".bak_"+str(ts)
    cmd = "cp "+netplanFile+" "+bakFile
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        print("ERROR: Unable to create backup file\n"+json.dumps(result,indent=4))
        return False

    return bakFile

##
# \brief restores the specified backup problem
# \param [in] source name of the file to backup
# \param [in] check verifies that the network is working after change
# \param [in] backup file to back the current netplan to prior to restoration. False=no backup
# \return True on success, False on failure
#
def restoreNetplan( source, check=True):
    netplanFile = NETPLAN_DIR+NETPLAN_FILE
    interfaceInfo = getState()

    #check if we're sudo
    if not CommandParser.checkSudo():
        print("Must have sude access to restore a netplan file")
        return False

    #Make sure source exists
    result = CommandParser.validateFile(source)
    if not result["exists"]:
        print("The source file "+source+" does not exist")
        return False
    if not result["r"]:
        print("The source file "+source+" is not readable")
        return False

    #Read in the original netplan
    orig = readNetplan()
    origSuccess = validateNetplan()

    success = True
    cmd = "cp "+source+" "+netplanFile
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        print("FAILURE: Unable to copy "+source+" to "+netplanFile)
        success = False

    #If we are successful, apply the netplan information
    if success:
        cmd = "netplan apply"
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            print("FAILURE: Unable to apply netplan")
            print("Result:\n"+json.dumps(result, indent=4))
            success = False

    #If all good, check validate the netplan matches expected results
    if success:
        time.sleep(1)
        success = validateNetplan()

    #All should be good, If not, and we've been asked to check, restore
    #previous data
    restoreSuccess = True
    if not success and check:
        print("Restoring original settings")
        restoreSuccess = writeYaml( netplanFile, orig )

        #reapply the netplan
        if restoreSuccess:
            cmd = "netplan apply"
            result = CommandParser.runCommand(cmd)
            if result["returnCode"]:
                print("Unable to apply netplan")
                CommandParser.runCommand("cat /etc/netplan/01-netcfg.yaml")
                print("Result:\n"+json.dumps(result, indent=4))
                restoreSuccess = False

        #Validate the restored netplan
        if restoreSuccess:
            restoreSuccess = validateNetplan()

        if not restoreSuccess and origSuccess:
            print("ERROR: System validation failed. Network is in an unknown state")
            return False
        elif not restoreSuccess:
            print("Restored original file which was not valid")
        else:
            print("System returned to the original state")
    return True

##
# \brief changes an interface address to the provided ip
# \param [in] iface interface to modify
# \param [in] ip address of the form "xxx.xxx.xxx.xxx" or "dhcp"
# \param [in] netmask mask of the form xxx.xxx.xxx.xxx or "/x" for the interface
# \param [in] mtu     optional mtu size parameter. 
# \param [in] recurse set to True if the function is being called recursively
#
# If the IP is set to "dhcp" the interface will be configured via DHCP. Otherwise,
# a valid IP address must be provided. The 
def setInterfaceIP( iface, ip, netmask, configuration=None, recurse=False ):
    netplanFile = NETPLAN_DIR+NETPLAN_FILE
    #Check for sudo
    if not CommandParser.checkSudo():
        print("ERROR: sudo access required to change interface settings")
        return False

    #get interface information 
    data = readYaml( netplanFile )

    #verify that the iface is in the file. 
    try:
        if not iface in data["data"]["network"]["ethernets"].keys():
            print("WARNING! "+iface+" is not defined in "+netplanFile+". Adding entry")
            data["data"]["network"]["ethernets"][iface]= {}
#            return False

    except:
        print("ERROR: Unable to access ethernets in "+netplanFile)
        return False
 
    #SDF
    # If the interface is set to dhcp
    if ip ==  "dhcp":
        data["data"]["network"]["ethernets"][iface]["dhcp4"] = "yes"


    else:
        #############################################
        # Set new IP
        #############################################
        #verify that it is a valid ip
        values = ip.split(".")
        if len(values) != 4:
            print("Invalid IP address provided")
            return False

        
        try:
            if int(values[0]) < 1 or int(values[0]) > 254:
                print("ERROR: first IP entry must be in a range from 1 to 254")
                return False

            entry = 1
            for v in values[1:2]:
                if int(v) < 0 or int(v) > 254:
                    print("ERROR: IP entry must be in a range from 0 to 254")
                    return False

                entry = entry+1

            if int(values[3]) < 1 or int(values[3]) > 254:
                print("ERROR: last IP entry must be in a range from 1 to 254")
                return False
        except:
            print("IP address "+ip+" is invalid")
            return False

        #Validate the netmask
        if not isinstance(netmask, str):
            print("Netmask must be of the form \"xxx.xxx.xxx.xxx\" or a cidr entry \\24")
            return False

        #If netmask is a cidr value, verify that it is correct
        if netmask[0] == "/":
            try:
                cidr = int(netmask[1:])
            except:
                print("CIDR entry for netmask must an integer after a leading \\")
                return False

        else:
            cidr = convertNetmaskToCidr(netmask)
            if cidr == False:
                print("Unable to generate CIDR from netmask "+netmask)
                return False

        #Make sure they are not the same
        entry = ip+"/"+str(cidr)
        if entry in data["data"]["network"]["ethernets"][iface]["addresses"]:
            print("Entry "+entry+" already exists. No changes necessary")
            return True


        #Check if BAK_DIR exists. If not create it
        result = CommandParser.validateFile(BAK_DIR)
        if not result["d"]:
            cmd = "mkdir -p "+BAK_DIR
            result = CommandParser.runCommand(cmd)
            if result["returnCode"]:
                print("FAILURE: Backup directory "+BAK_DIR+" does not exist and cannot be created")
                return False
        
        data["data"]["network"]["ethernets"][iface]["addresses"] = [entry]

    #Back up the old file to the BAK_DIR 
    ts = datetime.now().timestamp()
    bakFile = BAK_DIR+NETPLAN_FILE+"_"+str(ts)
    cmd = "cp "+netplanFile+" "+bakFile
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        print("ERROR: Unable to create backup file\n"+json.dumps(result,indent=4))
        return False

    #calculate hash based on yaml data, not comments
    newHash = hashlib.md5(str(data).encode())

    #Update comments
    data["comments"] = []
    data["comments"].append("##############################################")
    data["comments"].append("# Created by Aqueti NetworkManager")
    data["comments"].append("# Version: "+VERSION)
    data["comments"].append("# Date: "+str(datetime.now()))
    data["comments"].append("# Hash: "+newHash.hexdigest())
    data["comments"].append("##############################################")
    
    #Write file
    result =  writeYaml( netplanFile, data )
    if not result:
        print("ERROR!: Unable to write new "+netplanFile+". Exiting")
        return False

    #Apply
    cmd = "sudo netplan apply"
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        print("Failed to apply netplan with command: "+cmd)
        return False

    return success

"""
##
# \brief validates the the netplan information is consistent with the system
# \param [in] iface optional name of the interface to validate. None = default
# \return object with a key/value pair for each interface and if it is valid
# 
# This function indicates if the provided interafce is valid. If no interface
# is provided (iface == None), it will check all interfaces. Since this is 
# validating the netplan file, it will only be successful for interfaces 
# specified in that file. 
#
# The comparison only guarantees that the paramters specified in the netplan
# file are consistent with system settings. Extra parameters are ignored. The
# netplan file will not be valid if specified parameters cannot be verified.
#
def validateNetplan( iface = None  ):

    #CHeck if iface in interfaces
    ifaces = getInterfaces()

    if iface != None:
        if not iface in ifaces:
            print("ERROR: Undefined interface. Unable to validate "+iface)
            return False

        else:
            ifaces = [iface]

    np = readNetplan()
    state = getState()

    #Loop through the iface entries
    result = {}
    for iface in ifaces:
        #Read in the two files
"""

##
# \brief function to verify the specified target is accessible by the system
# \param [in] target hostname or ip address of a target system to test against
#
def validateRemote( target, delay=10):

    result = CommandParser.ping(target)

    if not result:
        print("Unable to ping target: "+target+" after "+str(delay)+" seconds")
        print("Reverting interface "+target+" to previous state")

    return result


##
# \brief function to update and validate network settings
# \return True on success, false on failure
#
# This function modifies a network interface as specified and then
# veifies that the target system is accessible via a ping. If the 
# target system cannot be reached, the system will revert to the
# orginal configuration.
#
# The system will try to ping the target one a second for the given 
# delay. If not successful, the system will revert to the previous
# state.
#
def updateAndVerify( iface, address, netmask, target, mtu=None,delay=10 ):
    #record the current state
    info = getState()

    if not isinstance(delay, int):
        print("Delay values must be integers")
        return False

    if iface not in info["interfaces"].keys():
        print("ERROR: Invalid interface name provided")
        return False

    #Record the old state
    oldState = info["interfaces"][iface]

    #First, try to set the new IP address and netmask
    result = setInterfaceIP(iface, address, netmask, mtu=mtu)
    if not result:
        print("Failed to set the IP address")
        return False

    valid = validateTarget( target, delay )



##
# \brief changes the provided state settings
# \param [in] iface network interface name to change
# \param [in] values object that contains the fields to change
# \param [in] verifyIP ip address of a remote system to verify network configuration works
# \return object that describes the interface state
#
# Example state object
#        "enp4s0": {
#            "addresses": ["10.0.0.1/24"] ,
#            "dhcp4": false,
#            "scope": "global",
#            "state": "UP",
#            "mtu": 1500,
#            "qdisc": "fq_codel",
#            "mode": "DEFAULT",
#            "group": "default",
#            "qlen": 1000
#        },
#
def changeState( iface, values, verifyIP = None ):
    result = True 

    #Verify that we are in the proper state
    if not CommandParser.checkSudo():
        print("Must be sudo to change state")
        return False

    netplanFile = NETPLAN_DIR+NETPLAN_FILE
    NETPLAN_PARAMS=["addresses", "mtu", "gateway4","nameservers"]
    STATE_PARAMS=["state"]
    newState = {}

    #Make sure it's a valid interface
    if not iface in getInterfaces():
        print("ChangeState: Unknown interface "+iface)
        return False

    #If have more than state, we have to make changes. If not,
    #Skip to the state section
    if len( set(values.keys()) & set(NETPLAN_PARAMS)) > 0:
        print("...updating netplan parameters for "+iface)
        #Make sure the interface is up
        info = getState()
        if info["data"][iface]["state"].lower() == "down":
            cmd = "ip link set "+iface+" up"
            res = CommandParser.runCommand( cmd )
            if res["returnCode"]:
                print("ERROR: Unable to set link state to "+values[key].lower())
                return False
    
            #Wait for the command to settle
            time.sleep(1)
    
        #Extract current information
        info = getState()
        state = info["data"][iface]
        netplan = readNetplan()
    
        #Update fields with new data
        #SDF need to check for value keys that are not in state (error state)
        change = False
        for key in state.keys():
           if key in NETPLAN_PARAMS:
               if key in values.keys():
                   newState[key] = values[key]
                   if state[key] != values[key]:
                       change = True
               else:
                   newState[key] = state[key]

        for key in set(values.keys()) & set(NETPLAN_PARAMS):
            try:
                if state[key] != values[key]:
                    newState[key] = values[key]
                    change = True
            except:
                newState[key] = values[key]
                change = True
        
        if change:
            #Backup netplan file
            print("...Backing up file")
            backupFile = backupNetplan()
            if not backupFile:
                print("ERROR. Unable to backup netplan file. Unable to change state")
                return False
    
            #Write netplan file
            ydata = {}
            ydata["comments"] = []
            ydata["data"] = {}
            ydata["data"]["network"] = {}
            ydata["data"]["network"]["ethernets"] = {}
            print(iface+" - newSate:"+str(newState))
            ydata["data"]["network"]["ethernets"][iface] = newState
    
            print("...updating netplan")
            result = updateNetplan( ydata, verifyIP )
    
            if not result:
                print("ERROR Unable to change state")
            else:
                print("...successfully changed state")

    #Apply state info
    stateSuccess = True
    for key in values.keys():
        if key in STATE_PARAMS:
            if key == "state":
                if values[key].lower() == "up" or values[key].lower() == "down":
                    cmd = "ip link set "+iface+" "+values[key].lower()
                    res = CommandParser.runCommand( cmd )
                    if res["returnCode"]:
                        print("Unable to set link state to "+values[key].lower())
                        stateSuccess = False
                    else:
                        #Wait to reach required state
                        time.sleep(2)
                else:
                    print("ERROR: Unknown state value: "+values[key])
                    stateSuccess = False
    return stateSuccess and result

##
# \brief function to backup the netplan configuration file
# \param [in] dest destination directory for where to place a file
# \result this result returns False on failure or the backup filename on success
#
def backupNetplan(dest=BAK_DIR):
    #Check if BAK_DIR exists. If not create it
    result = CommandParser.validateFile(BAK_DIR)
    if not result["d"]:
        cmd = "mkdir -p "+BAK_DIR
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            print("FAILURE: Backup directory "+BAK_DIR+" does not exist and cannot be created")
            return False

    #Back up the old file to the BAK_DIR 
    ts = datetime.now().timestamp()
    netplanFile = NETPLAN_DIR+NETPLAN_FILE
    bakFile = dest+NETPLAN_FILE+".bak_"+str(ts)
    cmd = "cp "+netplanFile+" "+bakFile
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        print("ERROR: Unable to create backup file\n"+json.dumps(result,indent=4))
        return False

    return bakFile

##
# \brief restores the specified backup problem
# \param [in] source name of the file to backup
# \param [in] check verifies that the network is working after change
# \param [in] backup file to back the current netplan to prior to restoration. False=no backup
# \return True on success, False on failure
#
def restoreNetplan( source, check=True):
    netplanFile = NETPLAN_DIR+NETPLAN_FILE

    #check if we're sudo
    if not CommandParser.checkSudo():
        print("Must have sude access to restore a netplan file")
        return False

    #Make sure source exists
    result = CommandParser.validateFile(source)
    if not result["exists"]:
        print("The source file "+source+" does not exist")
        return False
    if not result["r"]:
        print("The source file "+source+" is not readable")
        return False

    #Read in the original netplan
    orig = readNetplan()
    origSuccess = validateNetplan()

    cmd = "cp "+source+" "+netplanFile
    result = CommandParser.runCommand(cmd)
    success = True
    if result["returnCode"]:
        print("FAILURE: Unable to copy "+source+" to "+netplanFile)
        success = False

    #If we are successful, apply the netplan information
    if success:
        cmd = "netplan apply"
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            print("FAILURE: Unable to apply netplan")
            print("Result:\n"+json.dumps(result, indent=4))
            success = False

    #If all good, check validate the netplan matches expected results
    if success:
        time.sleep(1)
        success = validateNetplan()

    #All should be good, If not, and we've been asked to check, restore
    #previous data
    restoreSuccess = True
    if not success and check:
        print("Restoring original settings")
        restoreSuccess = writeYaml( netplanFile, orig )

        #reapply the netplan
        if restoreSuccess:
            cmd = "netplan apply"
            result = CommandParser.runCommand(cmd)
            if result["returnCode"]:
                print("Unable to apply netplan")
                CommandParser.runCommand("cat /etc/netplan/01-netcfg.yaml")
                print("Result:\n"+json.dumps(result, indent=4))
                restoreSuccess = False

        #Validate the restored netplan
        if restoreSuccess:
            restoreSuccess = validateNetplan()

        if not restoreSuccess and origSuccess:
            print("ERROR: System validation failed. Network is in an unknown state")
            return False

        elif not restoreSuccess:
            print("Restored original file which was not valid")
        else:
            print("System returned to the original state")

    return success

##
# \brief validates the the netplan information is consistent with the system
# \param [in] iface optional name of the interface to validate. None = default
# \return object with a key/value pair for each interface and if it is valid
# 
# This function indicates if the provided interafce is valid. If no interface
# is provided (iface == None), it will check all interfaces. Since this is 
# validating the netplan file, it will only be successful for interfaces 
# specified in that file. 
#
# The comparison only guarantees that the paramters specified in the netplan
# file are consistent with system settings. Extra parameters are ignored. The
# netplan file will not be valid if specified parameters cannot be verified.
#
def validateNetplan( iface = None  ):

    #CHeck if iface in interfaces
    ifaces = getInterfaces()

    if iface != None:
        if not iface in ifaces:
            print("ERROR: Undefined interface. Unable to validate "+iface)
            return False

        else:
            ifaces = [iface]

    np = readNetplan()
    state = getState()

    #Loop through the iface entries
    result = {}
    for iface in ifaces:
        #Turn interface on
        if state["data"][iface]["state"] == "down":
            res = changeState(iface, {"state":"up"})
            if not res:
                print("Unable to change state to up.")
                success = False
            else: 
                np = readNetplan()
    
        try: 
            if iface in np["data"]["network"]["ethernets"].keys():
                npIface = np["data"]["network"]["ethernets"][iface]

                info = getState()
                infoIface = info["data"][iface]

                #COmpare the data
                compare  = CommandParser.compareObjects( npIface, infoIface )

                #If there is a mismatch, we have a problem 
                success = True
                if len(compare["mismatch"]) > 0:
                    print("ERROR: There is a mismatch between the netplan file and system settings")
                    print("CMP:\n"+json.dumps(compare,indent=4))
                    success = False

                if len(compare["extra"]) > 0:
                    print("ERROR: There are extra netplan settings"+str(compare["extra"]))
                    success = False
            else:
                success = False
        except:
            print("Non-standard netplan format!")
            success = False

        result[iface] = success
    return result
    


    
##
# \brief prints the current interface information
def printInfo():
    info = getState()
    print(json.dumps(info, indent=4))

##
# \brief series of unit tests
def test():

    #Get information
    ts = str(datetime.now().timestamp())

    cmd = "cat /etc/machine-id"
    res = CommandParser.runCommand(cmd)
    machineId = res["value"]


    testResult = {}
    testResult["timestamp"]  = ts
    testResult["machine-id"] = machineId
    testResult["version"]    = VERSION
    testResult["pass"]       = True
    testResult["data"]       = {}
    testResult["data"]["writeYaml"]     = "unknown"
    testResult["data"]["readYaml"]      = "unknown"
    testResult["data"]["netmaskToCidr"] = "unknown"
    testResult["data"]["cidrToNetmask"] = "unknown"
    testResult["data"]["getInterfaces"]      = "unknown"
    testResult["data"]["getState"]      = "unknown"

    #Make a test directory
    testDir = "/tmp/NetworkManagerTest/"
    CommandParser.runCommand( "mkdir "+testDir)

    #Check Yaml functionality
    yData = {"comments":["# People tracker","# test application"], "data":{}}
    yData["data"]["person"] = {"name":"John Doe", "address":{"street":"1 easy lane","city":"anytown"}}


    success = True
    #write file
    outfile = testDir+"test1.yaml"
    result = writeYaml(outfile, yData)
    if not result:
        print("ERROR: Failed to write file "+outfile)
        testResult["data"]["writeYaml"] = "fail"
        success = True

    if success:
        #Read it back in
        fileData = readYaml(outfile)
        if fileData == False:
            print("ERROR: readYaml failed for file: "+outfile)
            testResult["data"]["readYaml"] = "fail"
            success = False

    if success:
        if fileData != yData:
            print("Data mismatch!")
            print("Input data:  "+str(person))
            print("Output data: "+str(person2))
        else:
            testResult["data"]["writeYaml"] = "pass"
            testResult["data"]["readYaml"]  = "pass"


    #Check convertNetmaskToCidr
    mask = "255.255.255.255"
    cidr = convertNetmaskToCidr(mask)
    newmask = convertCidrToNetmask(cidr)
    if newmask != mask:
        print("ERROR: mask "+mask+" => cidr "+str(cidr)+" => newmask "+newmask)
        testResult["data"]["netmaskToCidr"] = "fail"
        success = False

    #Check convertNetmaskToCidr
    mask = "0.0.0.0"
    cidr = convertNetmaskToCidr(mask)
    newmask = convertCidrToNetmask(cidr)
    if newmask != mask:
        print("ERROR: mask "+mask+" => cidr "+str(cidr)+" => newmask "+newmask)
        testResult["data"]["netmaskToCidr"] = "fail"
        success = False
    else:
        #Check convertNetmaskToCidr
        mask = "0.0.0.0"
        cidr = convertNetmaskToCidr(mask)
        newmask = convertCidrToNetmask(cidr)
        if newmask != mask:
            print("ERROR: mask "+mask+" => cidr "+str(cidr)+" => newmask "+newmask)
            testResult["data"]["netmaskToCidr"] = "fail"
            success = False

        else:
            testResult["data"]["netmaskToCidr"] = "pass"

    #Check error conditions
    errSuccess = True
    print("--- Begin Errors")
    result = convertNetmaskToCidr("256.255.255.0")
    if result: 
        errSuccess = False
        testResult["data"]["netmaskToCidr"] = "fail"
    result = convertNetmaskToCidr("A.255.255.0")
    if result: 
        errSuccess = False
        testResult["data"]["netmaskToCidr"] = "fail"
    result = convertNetmaskToCidr([10,1,1,1])
    if result: 
        errSuccess = False
        testResult["data"]["netmaskToCidr"] = "fail"
    result = convertCidrToNetmask(35)
    if result: 
        errSuccess = False
        testResult["data"]["cidrToNetmask"] = "fail"
    result = convertCidrToNetmask(-1)
    if result: 
        errSuccess = False
        testResult["data"]["cidrToNetmask"] = "fail"
    result = convertCidrToNetmask("1")
    if result: 
        errSuccess = False
        testResult["data"]["cidrToNetmask"] = "fail"
    print("--- End Errors")

    success = success & errSuccess

    #Get interfaces
    ifaces = getInterfaces()
    if ifaces == False:
        print("ERROR: Unable to get interfaces")
        testResult["data"]["getInterfaces"] = "fail"
        success = False
    elif not "lo" in ifaces:
        print("ERROR: Interface list does not include \'lo\'")
        testResult["data"]["getInterfaces"] = "fail"
        success = False
    else:
        testResult["data"]["getInterfaces"] = "pass"
          
    #Get interface state information
    stateSuccess = True
    interfaceData = getState()
    if interfaceData == False:
        print("ERROR: Unable to get state")
        testResult["data"]["getState"]  = "fail"
        stateSuccess = False
    else:
        for key in interfaceData["data"].keys():
            if not key in ifaces:
                print("getState returned a key not in the interface list")
                testResult["data"]["getState"]  = "fail"
                stateSuccess = False
        for key in ifaces:
            if not key in interfaceData["data"].keys():
                print("getInterfaces returned a key not getState")
                testResult["data"]["getState"]  = "fail"
                stateSuccess = False

    if stateSuccess:
                testResult["data"]["getState"]  = "pass"


    success = success & stateSuccess

    sudoer = CommandParser.checkSudo()
    if not sudoer:
        print("WARNING: NetworkManager unit tests requires sudo access for full functionalty")
        testResult["pass"] = False
        return testResult

    #Check error conditions
    print("--- Begin Errors")
    result = convertNetmaskToCidr("256.255.255.0")
    result = convertNetmaskToCidr("A.255.255.0")
    result = convertNetmaskToCidr([10,1,1,1])
    result = convertCidrToNetmask(35)
    result = convertCidrToNetmask(-1)
    result = convertCidrToNetmask("1")
    print("--- End Errors")

    #Get information about interfaces
    interfaceData = getState()

    #Find an UP interface, turn it off, verify that is is DOWN
    #Then renable
    iface = None
    ifaceSuccess = True
    for key in interfaceData["data"].keys():
        if interfaceData["data"][key]["state"] == "UP":
            iface = key
            break

    if iface == None:
        print("ERROR: Unable to find an active interface")
        ifaceSuccess = False

    #Turn off interface
    result = changeState( iface, {"state":"DOWN"})
    if not result:
        print("ERROR: Failed to set interface state to down!")
        testResult["data"]["setDown"] = "fail"
        ifaceSuccess = False

    else:
        interfaceData = getState(iface)
        if not interfaceData["data"][iface]["state"] == "DOWN":
            print("ERROR: Unable to set interface "+iface+" to DOWN")
            testResult["setDown"] = "fail"
            ifaceSuccess = False

    
    #Turn the interface back on
    result = changeState( iface, {"state":"UP"})
    if not result:
        print("ERROR: Failed to set interface state to up!")
        testResult["data"]["setUp"] = "fail"
        ifaceSuccess = False

    else:
        interfaceData = getState()
        if interfaceData["data"][iface]["state"] == "UP":
            print("ERROR: Unable to set interface "+iface+" to UP")
            testResult["setUp"] = "fail"
            ifaceSuccess = False

    if ifaceSuccess:
        testResult["setUp"]   = "pass"
        testResult["setDown"] = "pass"

    success = success & ifaceSuccess
        
    #############################################
    #Remove test directory
    #############################################
    result = CommandParser.runCommand( "rm -rf "+testDir)
    if result["returnCode"]:
        print("Unable to remove test directory")
        testResult["pass"] = False
        return testResult

    testResult["pass"] = success
    return testResult


##
# \brief main function
#
if __name__ == "__main__":

    epilog = """\
Additional Parameter Information:

This application generally queries and applies change to a specific interface.


Example Usage:
    ./NetworkManager.py -iface eth0 -printState
"""

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description="Aqueti NTP Configurator: "+str(VERSION), epilog = epilog)
    parser.add_argument("-printInterfaces", action="store_const", dest="printInterfaces", const=True, help="returns a list of interfaces in the system")
    parser.add_argument("-iface", action="store", dest="iface", help="specifies the interface to reference")

    #Queries
    parser.add_argument("-getState", action="store_const", dest="getState", const=True, help="Gets the current state of the specified interface. If no interface is provided, gets all interfaces")
    parser.add_argument("-readNetplan", action="store_const", dest="readNetplan", const=True, help="displays information about the iterface")

    #Modifications
    parser.add_argument("-changeState", action="store", dest="changeState", metavar="json", help="Changes the set of the provide interface based on the input")
    parser.add_argument("-backupNetplan", action="store", dest="backupNetplan", metavar="filename", const=True, nargs="?", help="backups up the netplan file")
    parser.add_argument("-restoreNetplan", action="store", dest="restoreFile", metavar="restoreFile", help="backups up the netplan file")

    #Checks
    parser.add_argument("-validateNetplan", action="store_const", dest="validateNetplan", const=True, help="validate that the netplan file matches system settings")
    parser.add_argument("-verify", action="store", dest="verify", metavar="ip", help="ip address to verify configuration works")

    #Output
    parser.add_argument("-printJson", action="store_const", dest="printJson", const=True, help="Write the output to a JSON file") 
    parser.add_argument("-printYaml", action="store_const", dest="printYaml", const=True, help="Write the output in the yaml format") 
    parser.add_argument("-writeJson", action="store", dest="writeJson", metavar=("filename"), help="Write the output to a JSON file") 
    parser.add_argument("-writeYaml", action="store", dest="writeYaml", metavar=("filename"),  help="Write the output in the yaml format") 

    #Extras
    parser.add_argument("-version", action="store_const", dest="version", const=True, help="prints vrsion information for this script")
    parser.add_argument("-v", action="store_const", dest="v", const=True, help="Validate ntp settings")
    parser.add_argument("-test", action="store_const", dest="test", const=True, help="Runs unit tests for software as a sequence of commands")

#    parser.add_argument("-printState", action="store_const", dest="printState", const=True, help="Changes the set of the provide interface based on the input")
#    parser.add_argument("-setInterfaceState", nargs=2, action="store", dest="setInterfaceState", metavar=('interface','state'), help="Sets the interface state to either \"UP\" or \"DOWN\"")
#    parser.add_argument("-setInterfaceIP", nargs=3, action="store", dest="setInterfaceIP", metavar=('interface','ip','netmask'), help="Sets the interface to the specified IP address with the provided netmask and sets the state to UP")
#    parser.add_argument("-printInfo", action="store_const", dest="printInfo", const=True, help="displays information about the iterface")
#    parser.add_argument("-validateRemote", action="store", dest="validateRemote", help="hostname or address of a remote system")
    args = parser.parse_args()
    
    verbose = 0
    iface = None

    if args.getState and args.readNetplan:
        print("-getState and -readNetplan options are incompatible")
        exit()

    if args.v:
        verbose = 1

    
    #############################################
    # Script related functions
    #############################################
    #Check version
    if args.version:
        print("NetworkManager version: "+VERSION)
        exit()

    #Run unit tests
    if args.test:
        result = test()
        if result["pass"]:
            print("SUCCESS: NetworkManager passed all unit tests")
        else:
            print("FAILURE: Network manager did not pass all tests")

        if args.writeJson:
            with open(args.writeJson, 'w') as fptr:
                fptr.write(json.dumps(result, indent=4))
            fptr.close()

        else:
            print(json.dumps(result, indent=4))

        exit()

    #############################################
    # Validate arguments
    #############################################
    #Get a list of interfaces
    ifaces = getInterfaces()

    # Get a list of interfaces
    if args.printInterfaces:
        print("Interfaces: "+str(ifaces))
        exit()

    #Check interface
    if args.iface:
        if not args.iface in ifaces:
            print("ERROR: Interface "+args.iface+" not found. Available interfaces: "+str(ifaces))
            exit()

        iface = args.iface

    #############################################
    # Data validations and transformations
    #############################################
    if args.backupNetplan:
        result = False
        if isinstance(args.backupNetplan,str):
            result = backupNetplan( args.backupNetplan)
        else:
            result = backupNetplan()

        if result:
            print("Successfully backed up the netplan file "+result)
        else:
            print("ERROR: Unable to backup the netplan file")

    #Copy the specified file to the netplan directory and apply
    if args.restoreFile:
        restoreNetplan( args.restoreFile )

    #Change the state for an interface
    if args.changeState:
        if iface == None:
            print("ERROR: Must specify and interface to change with the -iface option")
            exit(1)
        try:
            state = json.loads(args.changeState)
        except:
            print("Error in state object")
            exit(1)

        result = changeState( iface, state, args.verify )
        state = getState(iface)
 
    #Compare netplan file against system settings
    if args.validateNetplan:
        result = validateNetplan( iface )
        print("Validation Results:\n"+json.dumps(result,indent=4))

    #############################################
    # Read in information
    #############################################
    #Read state information from the system
    if args.getState:
        state = getState(iface)

    #Print netplan info
    if args.readNetplan:
        state = readNetplan()

    #############################################
    # Handle output
    #############################################
    if args.printJson:
        print(json.dumps(state, indent=4))

    if args.printYaml:
        output = ""
        
        try:
            for comment in state["comments"]:
                output = output + comment + "\n"
        except:
            pass

        output = output +yaml.dump( state["data"], default_flow_style=False )
        print(output)

    if args.writeJson:
        with open(args.writeJson, 'w') as fptr:
            fptr.write(json.dumps(state, indent=4))
        fptr.close()

    if args.writeYaml:
        writeYaml( args.writeYaml, state)




    """
    #Check netplan and ip are installed. If not, print error and exit
    result = validateNetplan("enp4s0")
    print(result)
    exit(1)


    if args.changeState:
        result = changeState( args[0], args[1])

    #set the interface state to up or down
    if args.setInterfaceState:
        result = setInterfaceState( args.setInterfaceState[0], args.setInterfaceState[1])

    if args.printNetplan:
        ydata = readYaml("/etc/netplan/01-netcfg.yaml")
        print(json.dumps(ydata, indent=4))
        exit(1)

    #get interface information
    if args.printInfo:
        info = getInterfaceInfo()
        print(json.dumps(info, indent=4))
        exit(1)

    if args.setInterfaceIP:
        result = setInterfaceIP( args.setInterfaceIP[0],args.setInterfaceIP[1], args.setInterfaceIP[2] )
        if not result:
            print("Failed to set IP address. Double check settings")

        if verbose:
            info = getInterfaceInfo()
            print(json.dumps(info["interfaces"][args.setInterfaceIP[0]], indent=4))

    if args.validateRemote:
        result = validateRemote(args.validateRemote)
        if result:
            print("Able to access remote host "+args.validateRemote)
        else:
            print("FAILURE. Unable to access remote host "+args.validateRemote)
    """
