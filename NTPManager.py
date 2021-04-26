#!/usr/bin/python3
###########################################################
# NTPManager 
#
# This file contains the tools to manage and configure the
# NTP settings for a device. It has the following advantages
# over manually editing the ntp.conf file:
#    - auto validation of file parameters and compatibilities
#    - consistent, known good file configurations
#    - validation tools to ensure the daemon is runnign properly
#    - tracks changes to files to track modificatins
#    - timestamps to record when the change ocurrded
#    - JSON compatible NTP representations for recording
###########################################################
import json
import CommandParser
import argparse
import copy
from datetime import datetime
import time
import hashlib

VERSION="0.0.1"
BAK_DIR = "/var/log/aqueti/etc/"

defaultNTPData = """
{
    "timestamp": "2020-08-21 14:28:27.750719",
    "version": "0.0.1",
    "data":{
        "driftfile": {
            "comments": [
               "# Tracks clock drift over time"
            ],
            "info": [[
                        "driftfile",
                        "/var/lib/ntp/ntp.drift"
                    ]
                ],
                "type": "driftfile"
        },
        "leapfile": {
            "comments": [
                "# Leap seconds definition provided by tzdata"
            ],
            "info": [
                [
                    "leapfile",
                    "/usr/share/zoneinfo/leap-seconds.list"
                ]
            ],
            "type": "leapfile"
        }
        ,
        "statistics":
        {
            "comments": [
                "# tracks statistics over time"
            ],
            "info": [
                [
                    "statistics",
                    "loopstats",
                    "peerstats",
                    "clockstats"
                ],
                [
                    "filegen",
                    "loopstats",
                    "file",
                    "loopstats",
                    "type",
                    "day",
                    "enable"
                ],
                [
                    "filegen",
                    "peerstats",
                    "file",
                    "peerstats",
                    "type",
                    "day",
                    "enable"
                ],
                [
                    "filegen",
                    "clockstats",
                    "file",
                    "clockstats",
                    "type",
                    "day",
                    "enable"
                ]
            ],
            "type": "statistics"
        },
        "pool":
        {
            "comments": [
                "# Specify one or more NTP servers.",
                "# Use servers from the NTP Pool Project. Approved by Ubuntu Technical Board",
                "# on 2011-02-08 (LP: #104525). See http://www.pool.ntp.org/join.html for",
                "# more information."
            ],
            "info": [
                [
                    "pool",
                    "0.ubuntu.pool.ntp.org",
                    "iburst"
                ],
                [
                    "pool",
                    "1.ubuntu.pool.ntp.org",
                    "iburst"
                ],
                [
                    "pool",
                    "2.ubuntu.pool.ntp.org",
                    "iburst"
                ],
                [
                    "pool",
                    "3.ubuntu.pool.ntp.org",
                    "iburst"
                ]
            ],
            "type": "pool"
        },
        "server":
        {
            "comments": [
                "# external servers"
            ],
            "info": [
                [
                    "server",
                    "time2.google.com",
                    "iburst"
                ]
            ],
            "type": "server"
        },
        "hwclock":
        {
            "comments": [
                "# reference local hardware clock"
            ],
            "info": [
                [
                    "server",
                    "127.127.1.0", 
                    "iburst",
                    "prefer"
                ]
            ],
            "type": "server"
        },
        "restrict":
        {
            "comments": [
                "# Access control configuration; see /usr/share/doc/ntp-doc/html/accopt.html for",
                "# details.  The web page <http://support.ntp.org/bin/view/Support/AccessRestrictions>",
                "# might also be helpful.",
                "#",
                "# Note that restrict applies to both servers and clients, so a configuration",
                "# that might be intended to block requests from certain clients could also end",
                "# up blocking replies from your own upstream servers.",
                "",
                "# By default, exchange time with everybody, but don't allow configuration."
            ],
            "info": [
                [
                    "restrict",
                    "-4",
                    "default",
                    "kod",
                    "notrap",
                    "nomodify",
                    "nopeer",
                    "noquery",
                    "limited"
                ],
                [
                    "restrict",
                    "-6",
                    "default",
                    "kod",
                    "notrap",
                    "nomodify",
                    "nopeer",
                    "noquery",
                    "limited"
                ],
                [
                    "restrict",
                    "127.0.0.1"
                ],
                [
                    "restrict",
                    "::1"
                ],
                [
                    "restrict",
                    "source",
                    "notrap",
                    "nomodify",
                    "noquery"
                ]
            ],
            "type": "restrict"
        },
        "broadcastdelay":
        {
            "info": [
                [
                    "broadcastdelay",
                    ".008"
                ]
            ],
            "type": "broadcastdelay"
        },
        "broadcast":
        {
            "comments":[
                "# Specified what network to broadcast ntp data over"
            ],
            "info":
            [
                [
                    "broadcast",
                    "10.0.255.255",
                    "minpoll",
                    "4",
                    "maxpoll",
                    "4"
                ]
            ],
            "type": "broadcast"
        }
    }
}
"""


##
# \brief reads in the specifed ntp.conf file
def readNTP( filename = "/etc/ntp.conf"):
    ntpData = {}
    now = datetime.now()
    ntpData["timestamp"] = str(now)
    ntpData["version"] = str(VERSION)
    header = []

    ntpInfo = []

    ntpFile = open(filename,"r")
    data = ntpFile.read()
    ntpFile.close()

    count = 0
    #Convert file into JSON representation
    #For each non-comment line, the first word becomes the key. Subsequent words
    #are written to an array
    entry = {}
    comments = []
    entries  = []
    lines    = []
    key = None

    #Each line sequence is a new entry
    headerCount = 0

    for line in data.splitlines(1):
#        line = line.rstrip()

        #Find the comments and append them to the comments array. This assumes
        #that comments and subsequent info values do not have separation. If 
        #there is separation, the spacing will generate a comments-only entry

        #If the line is a comment or blank, we check if there is a key. If so, we need 
        #to write the previous comment information before adding the currently line to
        #the next comment array
        #If we have a blank line, assign a comment key
        if len(line)  <= 1:
            key = "comments"

        elif line[0] == "#":
            comments.append(str(line))

        #Line has info. Generate the entry
        elif len(line) > 1:
            info = line.split()
    
            #Each line is represented as an object. There may be multiple
            #lines with the same type so we track the lines as an array of 
            #object
            key = info[0]
            entries.append(info)


        #If we have a key or we're the last line, add data
        if key != None:
            #If we have comments and a key, then add comments to the entry
            if len(comments) > 0:
                entry["comments"] = comments
                entry["type"] = "comments"

            if len(entries) > 0:
                entry["info"] = entries
                entry["type"] = entries[0][0]

                #broadcast delay should always precede a broadcat entry
                if entry["type"] == "broadcastdelay":
                    entry["type"] = "broadcast"

            #Only add data if we have a value in the entry
            if "comments" in entry.keys() or "info" in entry.keys():
                ntpInfo.append(entry)

            comments = []
            entry = {}
            entries = []
            key = None

    ntpData["ntpInfo"] = ntpInfo

    return ntpData

##
# \brief function to restore the previous ntp.conf file
# \param backup alternative backup filename. If None, it uses the default extention.
def restoreNTPFile( target, backupFile=None):
    if backupFile == None:
        backupFile = target+self.backupExtension

    print("Backup: "+backupFile+", target: "+target)
    
    ret = CommandParser.runCommand("cp "+backupFile+" "+target)
    if ret["returnCode"] != 0:
            print("Unable to restore backup file "+backupFile+". Aborting NTP file creation")
            return False

    #If /etc/ntp.conf restart
    if target == "/etc/ntp.conf":
        ret = self.validateNTPDaemon(restart=True)

        if not result["valid"]:
            print("ERROR: NTP restored, but unable to valdidate daemon. Please check NTP configuration")
            return False
        else:
            print("Daemon restarted")


    print("Restoration complete")
    return True

##
# \brief reads a JSON file with NTP data
def readNTPJson( filename ):
    #Check if file exists
    result = CommandParser.validateFile(filename)
    if not result["exists"]:
        print("ERROR: Umable to read Json file. "+filename+" does not exist")
        return False

    jsonFile = open(filename ,"r")
    info = json.load(jsonFile)
    jsonFile.close()

    return info

##
# \brief check the hash of an ntp file
#
def checkHash(  target):

    #read the file file into a buffer
    ntpFile = open(target,"r")
    data = ntpFile.read()
    ntpFile.close()

    #remove hash line
    lines = data.splitlines(1)

    hashData = ""
    hashLine = ""
    for line in lines:
        index = line.find("Hash")
        if index < 0:
            hashData = hashData+line
        else:
            hashLine = line
        
    items = hashLine.split(" ")
#    oldHash = items[2].rstrip()
    oldHash = items[2]

    newHashInfo = hashlib.md5(hashData.encode())
    newHash = newHashInfo.hexdigest()

    if str(newHash) != str(oldHash):
        print("File has been modified")
        return False

    return True

##
# \brief function to write the json value into a new ntp.conf file
# \param [in] ntpObject object with the ntp data
# \param [in] backup backup file location. 
# \return True on success False on failure
#
# This function backups the existing ntp.conf file and writes a new
# one based on the values in ntpJson. This process will overwrite 
# any existing backup files.
# 
# If the version parameter is set, the outpu file will include additional version
# information including the version of this software, the date the file was 
# generated and a hash number for the file (excluding the hash line)
#
def writeNTPFile( ntpData, target, backup=None, version=True, validate=True, restart=False):
    backupFile = BAK_DIR+"ntp.conf_"+str(datetime.now().timestamp())

    #buffer to hold the output
    ntpBuffer    = ""
    oldHashLine  = ""
    headerBuffer = ""

    ntpInfo = ntpData["ntpInfo"]

    if backup == None:
        backup = backupFile

    #Loop through all key in the object, generate the necessary comments
    #and lines. Each key is an object that contains an array of comments
    #and a line that starts with key followed by an array of info
    index = 0
    headerBuffer = ""
    for entry in ntpInfo:
        #For comment entries, there is no info
        if entry["type"] == "comments":
            for line in entry["comments"]:
                line = line.rstrip()

                if "Hash:" in line:
                    oldHashLine = line

                headerBuffer = headerBuffer + line+"\n"

#                headerBuffer = headerBuffer + line.rstrip()+"\n"
        #Normal entry
        else:
            if "comments" in entry.keys():
                for line in entry["comments"]:
                    ntpBuffer = ntpBuffer + line.rstrip()+ "\n"
#                    ntpBuffer = ntpBuffer + line+ "\n"

            if "info" in entry.keys():
                for item in entry["info"]:
                    line = ""
                    for value in item:
                        line = line + value + " "

                    ntpBuffer = ntpBuffer + line.rstrip()
                
                #Strip the lat space
                ntpBuffer = ntpBuffer +"\n"
#                ntpBuffer.rstrip()
            ntpBuffer = ntpBuffer+"\n"
        index = index+1

    #Generate the header
    #SDF checkf for existing header. If hash changes, create a new one
    #Each header will be four lines. If the header already exists, the file has not been
    #been modified.
#    ntpBuffer = ntpBuffer.rstrip()

    hashMatch = False
    print("HashBuff:\n"+ntpBuffer)
    print("OLD Line:\n", oldHashLine)
    if version:
        #generate hash from the buffer 
        newHash = hashlib.md5(str(ntpBuffer).encode())
        newHash = str(newHash.hexdigest())

        #Compare new hash against old hash. If there are no changes, keep creation data
        if len(oldHashLine) > 0:
            oldHash = oldHashLine.split(' ')[2].rstrip()
            if newHash != oldHash:
                print("Hash mismatch: "+str(newHash)+" != "+oldHash)
            else:
                print("HASH MATCH")
                hashMatch = True
        
        if not hashMatch:
            #Create a new hash
            headerBuffer  = ""
            headerBuffer  = headerBuffer+"####################################################\n"
            headerBuffer  = headerBuffer+"# Created by Aqueti NTP Manager version "+VERSION+"\n"
            headerBuffer  = headerBuffer+"# Date: "+ntpData["timestamp"]+"\n"
            headerBuffer  = headerBuffer+"# Hash: "+newHash+"\n"
            headerBuffer  = headerBuffer+"####################################################\n"

        ntpBuffer = headerBuffer + "\n"+ ntpBuffer

    """
    #Check if target exists. If so, back it up
    ret = CommandParser.validateFile(target)
    backupFile = None
    if ret["exists"]: 
        backupFile = target+backup
        ret = CommandParser.runCommand("cp "+target+" "+backupFile)
        if ret["returnCode"] != 0:
            print("Unable to generate backup file "+backupFile+". Aborting NTP file creation")
            return False
    """

    #write the new file to disk
    fp = open(target, "w")
#    fp.write(ntpBuffer+"\n")
    fp.write(ntpBuffer.rstrip()+"\n")
    fp.close()

    #If target is /etc/ntp.conf and restart, validate the daemon
    if target == "/etc/ntp.conf" and restart:
        print("Restarting and Validating Daemon")
        result = self.validateNTPDaemon(restart=True)

        #If the result is not valid, restart previous and restart again
        if not result["valid"]:
            restore = self.restoreNTPFile(target)

            if not restore:
                 print("ERROR: Invalid ntp.conf file written, unable to restore valid version")

            return restore
            

    return True


##
# \brief validates the current running ntp daemon
# \param [in] restart flag to indicate if the daemon should restart
def validateNTPDaemon(  restart=False, delay = 30, verbose = 1 ):
    minNTPVersion = "4.0"

    result = { "valid":False, "status":"ok", "hwclock":False, "errors":[], "warnings":[], "sources":[],"broadcasts":[],"peers":[]}

    #Restart the daemon
    if restart:
        if verbose:
            print("Restarting the daemon")
        if not CommandParser.checkSudo():
            result["errors"].append("Unable to restart the ntp.conf file. Not running in SUDO mode")
            print("ValidatNTPDaemon: Must be root to restart the ntp.conf file")
            return result


        ret = CommandParser.runCommand("systemctl restart ntp")
        if ret["returnCode"] != 0:
            print("ValidatNTPDaemon: Error restarting the daemon")
            result["errors"] = "Error restarting the daemon"

        print("\tSleeping for 30 seconds while waiting for NTP to settle")

        CommandParser.printProgress( delay )
 
    #Check ntp version and make sure it's installed
    if verbose:
        print("verifying NTP version")
    ret = CommandParser.runCommand("ntpd -? |grep -i Ver |head -n 1 |rev |cut -d' ' -f 1 |rev")
    if ret["returnCode"]:
        result["errors"].append("Unable to access ntpd. Likely, ntpd is not installed")
        result["valid"] = False
        return result

    if ret["value" ] < minNTPVersion:
        result["warnings"].append("ntpd version of "+result["value"]+" is less than recommended version "+minNTPVersion)
        result["version"] = ret["value"]
        result["status"] = "sub-optimal"

    #check ntpq version
    ret = CommandParser.runCommand("ntpq --version |cut -d' ' -f2")
    if ret["returnCode"]:
        result["errors"].append("Unable to access ntpq. Cannot continue testing")
        result["valid"] = False
        return result

    #Make sure daemon is running
    if verbose:
        print("verifying NTP daemon is running")
    ret = CommandParser.runCommand("systemctl status ntp |grep running")
    if ret["returnCode"]:
        result["errors"].append("Unable to access ntpd via systemctl")
        result["valid"] = False
        return result

    #Check status
    fields = ret["value"].split()
    status = fields[1]
    result["status"] = status

    #If we are not active, we have a problem
    if status != "active":
        result["errors"].append("ntpd is not running. Unable to validate")
        result["valid"] = False
        return result

    #Extract the uptime
    entry = ret["value"].split(";")[1]
    uptime = entry.split()[0]

    result["uptime"] = uptime

    #Run ntpq -p to get a list of connection
    if verbose:
        print("verifying NTP connections")
    ret = CommandParser.runCommand("ntpq -p")
    if not ret["returnCode"]:
        result["errors"].append("Failed running ntpq -p")
        result["valid"] = False

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
            result["broadcasts"].append(broadcast)
        else:
            source = {}
            source ["remote"] = items[0]
            source["entry"] = line
            if sync == "*":
                source["status"] = "peer"
                result["peers"] = items[0]

                if "LOCL" in items[1]:
                    result["hwclock"] = True
          
            if "LOCL" in items[1]:
                source["hwclock"] = True

            result["sources"].append(source)

            #If the first byte is a +, we are an alternate
            if sync == "+":
                source["status"] = "alternate"

    if len(result["peers"]) > 0:
        result["valid"] = True

    #Make sure timedatectl is not running.
    cmd = "timedatectl status |grep timesyncd.service |cut -d ' ' -f 3"
    ret = CommandParser.runCommand( cmd )

    #If failure, assume there is a fundamental error with systemd and fail
    if ret["returnCode"]:
        print("Unable to execute command: "+cmd)
        result["valid"] = False
    elif ret["value"] != "no":
        print("VALIDATION FAILURE: timedatectl is enabled. Disable with: \"sudo timedatectl set-ntp 0\"")
        result["valid"] = False

    return result

##
# \brief validates an ntp.conf configuration
# \param [in] ntpData JSON representation of an NTP file
def validateNTPData(  ntpData, verbose = 1 ):
    sudoer = False

    #Define our return value
    returnValue = {}
    returnValue["valid"] = True
    returnValue["status"] = "ok"
    returnValue["warnings"] = []
    returnValue["errors"] = []
    returnValue["broadcast"] = False
    returnValue["details"] = {}

    #Default settings to compare against
    ifaceRestrictions = ["default","kod","notrap","nomodify","nopeer","noquery","limited"]
    sourceRestrictions = ["notrap", "nomodify", "noquery"]
    broadcastMaxPollRange = [4,17]
    broadcastMinPollRange = [4,17]

    testResult = {}
    testResult["driftfile"]  = {"valid":"False"}
    testResult["leapfile"]   = {"valid":"False"}
    testResult["statsdir"]   = {"valid":"False"}
    testResult["statistics"] = {"valid":"False"}
    testResult["pool"]       = {"valid":"False"}
    testResult["server"]     = {"valid":"False"}
    testResult["restrict"]   = {"valid":"False"}
    testResult["broadcast"]  = {"valid":"False"}

    directives = list(testResult.keys())
    directives.append("filegen")

    driftfileEntries  = []
    leapfileEntries   = []
    statdirEntries    = []
    statisticsEntries = []
    poolEntries       = []
    serverEntries     = []
    restrictEntries   = []
    broadcastEntries  = []
    broadcastdelayEntries  = []

    serverOK = 0
    serverTotal = 0

    previousInfo = ""            #Track previous entry

    #CHeck if we're root
    if CommandParser.checkSudo():
        sudoer = True
    else:
        print("MUst be root to validate all aspects of the ntp.conf file")

    if verbose:
        print("Validating ntp data")

    #Loop through ntp entries
    for entry in ntpData["ntpInfo"]:
        if "info" in entry.keys():
            for item in entry["info"]:
                key = item[0]

                # Validate driftfile and leadpfile entries.
                #  - verify files exists with rw access for root
                #  - if the file doesn't exist, try to create it and assign permissions
                #  - NOTE: This will not modify an existing file
                if key == "driftfile" or key == "leapfile":
                    fileEntry = {}
                    fileEntry["valid"] = True
                    fileEntry["status"] = "ok"
                    fileEntry["errors"] = []
                    fileEntry["warnings"] = []
                    

                    result = CommandParser.validateFile(item[1])
                    #If the file does not exist, try to create it
                    if not result["exists"]:
                        CommandParser.runCommand("touch "+item[1])
                        CommandParser.runCommand("chmod 644 "+item[1])
                        result = CommandParser.validateFile(item[1])
                        if not result["exists"]:
                            fileEntry["error"].append(" does not exist and cannot be created")
                            fileEntry["Status"] = "broken"
                            fileEntry["valid"] = False
                        else:
                            result = CommandParser.validateFile(item[1])

                    #Make sure it is writeable
                    if sudoer:
                        if not result["w"]:
                            fileEntry["error"].append(item[1]+" is not writeable")
                            fileEntry["Status"] = "broken"
                            fileEntry["valid"] = False

                    #Make sure it is readable
                    if not result["r"]:
                        fileEntry["error"].append(item[1]+" is not readable")
                        fileEntry["Status"] = "broken"
                        fileEntry["valid"] = False
                    if key == "driftfile":
                        driftfileEntries.append(fileEntry)
                    elif key == "leapfile":
                        leapfileEntries.append(fileEntry)

                # Validate directories exist and are directories
                elif key == "statsdir":
                    dirEntry = {}
                    dirEntry["valid"] = True
                    dirEntry["errors"] = []
                    dirEntry["warnings"] = []

                    result = CommandParser.validateFile(item[1])
                    if not result["d"]:
                        CommandParser.runCommand("mkdir -p "+item[1])
                        if result["returnCode"] != 0:
                            dirEntry["errors"].append(item[1]+" is not a directory and cannot be created")
                            dirEntry["valid"] = False
                        else:
                            result = CommandParser.valdiateFile(item[1])
                            if not result["d"]:
                                dirEntry["errors"].append(item[1]+" is not a directory and cannot be created")
                                dirEntry["valid"] = False

                    statdirEntries.append(dirEntry)            

                #Validate statistics entries. This statistics line includes a list of 
                #statistics to collect. A filegen line needs to exist for each statistic
                #type.
                #
                #Assume filegen entries are only for statistics
                #
                elif key == "statistics":
                    statEntry = {}
                    statEntry["valid"] = True
                    statEntry["errors"] = []
                    statEntry["warnings"] = []
                    statEntry["fieldEntries"] = []

                    goodNames = []
                    invalidNames = []            
                    extraNames = []

                    #Make sure that we have entries after statistics
                    if item == 1:
                        statEntry["errors"].append( key+" does not have subsequent fields" )
                        statEntry["valid"] = False
                    else:
                        #Get a list of values to track
                        entries = item[1:]

                        #Loop through all entries and pull out filegen data that matches keys
                        for e in ntpData["ntpInfo"]:
                            #If we have info, see if the first entry is for filegen. If so, a
                            #filegen entry should exist for each statistics field

                            fieldEntry = copy.deepcopy(statEntry)
                            fieldEntry["unknownDirective"] = []
                            if "info" in e.keys():
                                if e["info"][0] == "filegen":
                                    name = e["info"][1]
                                    if name in entries:
                                        if e["info"][2] != "file":
                                            fieldEntry["error"].append(key+" "+str(e["info"])+" - 3rd field unknown")
                                            fieldEntry["valid"] = False
                                        if e["info"][3] != e["info"][1]:
                                            fieldEntry["error"].append(key+" "+str(e["info"])+" - 4th field does not match 2nd field")
                                            fieldEntry["valid"] = False
                                        if e["info"][4] != "type":
                                            fieldEntry["error"].append(key+" "+str(e["info"])+" - 5th field unknown")
                                            fieldEntry["valid"] = False
                                        if e["info"][5] != "day":
                                            fieldEntry["error"].append(key+" "+str(e["info"])+" - 6th field unknown")
                                            fieldEntry["valid"] = False
                                        if e["info"][6] != "enable":
                                            fieldEntry["error"].append(key+" "+str(e["info"])+" - 7th field unknown")
                                            fieldEntry["valid"] = False

                                    else:
                                        fieldEntry["unknownDirective"].append(name)

                            statEntry["fieldEntries"].append(fieldEntry)

                    #Add it to the stat entries list
                    statisticsEntries.append(statEntry)

                #Validate pool and server entries. 
                # - Make sure the address is pingable
                # - make sure subsequent options are valid
                elif key == "pool":
                    poolEntry = {}
                    poolEntry["warnings"] = []
                    poolEntry["errors"]  = []
                    poolEntry["valid"]   = True
                    poolEntry["status"]  = "ok"

                    #validate we have at least 2 items.
                    if len(item) <= 1:
                        poolEntry["errors"].append("not enough items")
                        poolEntry["status"]  = "broken"

                    #Make sure the host is pingable
                    host = item[1]
                    poolEntry["hostname"] = item[1]
                    if verbose:
                        print("\tpinging pool server: "+poolEntry["hostname"])

                    result = CommandParser.ping(poolEntry["hostname"])
                    if not result:
                        poolEntry["errors"].append("unable to ping")
                        poolEntry["valid"] = False
                        poolEntry["status"]  = "broken"

                        if verbose:
                            print("ERROR: Unable to ping pool entry "+poolEntry["hostname"])

                    if not "iburst" in item:
                        poolEntry["warnings"].append("no iburst directive")
                        if poolEntry["status"] == "ok":
                            poolEntry["status"] = "sub-optimal"

                    #Add the entry to the poolEntries list
                    poolEntries.append(poolEntry)

                #Validate server and server entries. 
                # - Make sure the address is pingable
                # - make sure subsequent options are valid
                elif key == "server":
                    serverEntry = {}
                    serverEntry["warnings"] = []
                    serverEntry["errors"] = []
                    serverEntry["status"] = "ok"
                    serverEntry["localClock"] = False
                    serverEntry["valid"] = True

                    #validate we have at least 2 items.
                    if len(item) <= 1:
                        serverEntry["errors"].append("not enough items")
                        serverEntry["status"] = "broken"

                    host = item[1]
                    serverEntry["hostname"] = host

                    iplist = host.split(".")
                    if iplist[0] == "127":
                        serverEntry["localClock"] = True
                        if not "prefer" in item:
                            serverEntry["warnings"].append("Using a local clock without prefer directive")
                            if serverEntry["status"] == "ok":
                                serverEntry["status"] = "sub-optimal"

                    #Make sure the host is pingable
                    if verbose:
                        print("\tpinging server: "+serverEntry["hostname"])

                    result = CommandParser.ping(serverEntry["hostname"])
                    if not result:
                        serverEntry["errors"].append("unable to ping")
                        serverEntry["status"] = "broken"
                        serverEntry["valid"]= False

                        if verbose:
                            print("ERROR: Unable to ping server entry "+serverEntry["hostname"])

                    if not "iburst" in item:
                        serverEntry["warnings"].append("no iburst directive")
                        if serverEntry["status"] == "ok":
                            serverEntry["status"] = "sub-optimal"

                    #Check maxpoll
                    #Verify maxpoll is in a reasonable range
                    #Check for maxpoll, get next field as value
                    usingMaxPoll = True
                    try:
                        index = item.index("maxpoll")
                    except:
                        serverEntry["warnings"].append("maxpoll entry not used")
                        if serverEntry["status"] == "ok":
                            serverEntry["status"] = "sub-optimal"
                        usingMaxPoll = False

                    if usingMaxPoll:
                        try:
                            maxpoll = int(item[index])
                        except:
                            if serverEntry["status"] == "ok":
                                serverEntry["status"] = "sub-optimal"
                            maxpoll = -1

                        #Max poll should always be 6 or higher 
                        if maxpoll < 1:
                            serverEntry["error"].append("maxpoll directive is found, but entry not provided")
                            serverEntry["valid"] = False
                            serverEntry["status"] = "broken"
                        elif maxpoll < 6:
                            serverEntry["warnings"].append("maxpoll entry of "+maxpoll+" is very aggressive")
                            if serverEntry["status"] == "ok":
                                serverEntry["status"] = "sub-optimal"

                    #Add the server entry to the serverEntries list
                    serverEntries.append(serverEntry)

                elif key == "restrict":
                    restrictEntry = {}
                    restrictEntry["warnings"] = []
                    restrictEntry["errors"]   = []
                    restrictEntry["value"]    = []
                    restrictEntry["status"]   = "ok"
                    restrictEntry["valid"]    = True

                    restrictEntry["value"].append(item)

                    #Make sure there is additional information
                    if len(item) <= 1:
                       restrictEntry["error"].append("No subsequent fields provided")
                       restrictEntry["status"] = "broken"
                       restrictEntry["valid"] = False

                    #Validate based on the second entry
                    name = item[1]
                    restrictEntry["interface"] = name
                    restrictEntry["restrictions"] = copy.deepcopy(item[2:])

                    #Handle localhost and ::1
                    if name == "127.0.0.1" or name == "::1":
                        if len(item) > 2:
                            restrictEntry["warnings"].append("Unexpected restrictions placed on "+name)
                            if restrictEntry["status"] == "ok":
                                restrictEntry["status"] = "sub-optimal"

                    if name == "-4" or name == "-6":
                        if set(item[2:]) != set(ifaceRestrictions):
                            restrictEntry["warnings"].append("Non-standard restrictions")
                            if restrictEntry["status"] == "ok":
                                restrictEntry["status"] = "sub-optimal"

                    if name == "source":
                        if set(item[2:]) != set (sourceRestrictions):
                            restrictEntry["warnings"].append("Non-standard restrictions")
                            if restrictEntry["status"] == "ok":
                                restrictEntry["status"] = "sub-optimal"
                        
                    restrictEntries.append(restrictEntry)

                #The fudge directive needs to follow a server directive
                elif key == "fudge":
                    fudgeEntry = {}
                    fudgeEntry["warnings"]  = []
                    fudgeEntry["errors"]    = []
                    fudgeEntry["subnets"]   = []
                    fudgeEntry["status"]    = "ok"
                    fudgeEntry["localClock"] = False
                    fudgeEntry["valid"]     = True

                    host = item[1]
                    fudgeEntry["hostname"] = host
                    iplist = host.split(".")

                    if iplist[0] == "127":
                        fudgeEntry["localClock"] = True

                    #Ensure previous line was for a server
                    if previousInfo[0] != "server":
                        fudgeEntry["warnings"].append("previous entry is not for a server")
                        if fudgeEntry["status"] == "ok":
                            fudgeEntry["status"] == "sub-optimal"

                    #Check to ensure its hostname matches last hostname
                    if host != previousInfo[1]:
                        fudgeEntry["warnings"].append("host "+host+" does not match previous line host")
                        if fudgeEntry["status"] == "ok":
                            fudgeEntry["status"] == "sub-optimal"

                    #Make sure stratum has a reasonable number
                    if "stratum" in item:
                        index = item.index("stratum")

                        #Make sure we have a stratum entry
                        if len(item) < index+1:
                            fudgeEntry["warnings"].append("stratum does not include a value")
                            if fudgeEntry["status"] == "ok":
                                fudgeEntry["status"] == "sub-optimal"
                        else:
                            try:
                                level = int(item[index+1])
                            except:
                                fudgeEntry["errors"].append("stratum has non-integer value")
                                fudgeEntry["status"] == "broken"
                                fudgeEntry["valid"] == False
                                level = -1

                            if level > 15:
                                fudgeEntry["errors"].append("value exceeds maximum of 15")
                                fudgeEntry["status"] == "broken"
                                fudgeEntry["valid"] == False

                            if fudgeEntry["localClock"] and level != 10:
                                fudgeEntry["warnings"].append("recommended stratum level of 10 for a hardware clock")
                                if fudgeEntry["status"] == "ok":
                                    fudgeEntry["status"] == "sub-optimal"


                elif key == "broadcast":
                    broadcastEntry = {}
                    broadcastEntry["warnings"] = []
                    broadcastEntry["errors"]   = []
                    broadcastEntry["network"]  = None
                    broadcastEntry["status"]   = "ok"
                    broadcastEntry["valid"]    = True
                   
                    #Make sure we have enough items
                    if len(item) < 2:
                        broadcastEntry["errors"].append("broadcast entry does not have additional fields")
                    else:
                        #Verify the bcastNet maps to an existing IP address
                        bcastNet = item[1].split(".")

                        if len(bcastNet) != 4:
                            broadcastEntry["errors"].append("Not enough fields in the bcastNet entry "+item[0])
                            broadcastEntry["status"] = "broken"
                            broadcastEntry["valid"] = False

                        #Make sure entries are ints and between 0 and 255
                        valid = True
                        for value in bcastNet:
                            try:
                                if int(value) > 255 or int(value) < 0:
                                    valid = False
                            except:
                                valid = False

                        if not valid:
                            broadcastEntry["errors"].append("Subnet entries are not integers between 0 and 255")
                            broadcastEntry["status"] = "broken"
                            broadcastEntry["valid"] = False
         
                        #At least our bcastNet is numbers. Check components
                        else:
                            if int(bcastNet[0]) == 0 or int(bcastNet[0]) == 255:
                                broadcastEntry["errors"].append("Initials bcastNet entry outside of the range from 1 to 254")
                                broadcastEntry["status"] = "broken"
                                broadcastEntry["valid"] = False

                            if int(bcastNet[-1]) == 0:
                                broadcastEntry["errors"].append("Final bcastNet entry is 0")
                                broadcastEntry["status"] = "broken"
                                broadcastEntry["valid"] = False

                            #Making this an error due to the rarity of alternative configurations
                            if int(bcastNet[-1]) != 255 :
                                broadcastEntry["errors"].append("Final bcastNet entry is not 255. This is a non-typical configuration")
                                broadcastEntry["status"] = "broken"
                                broadcastEntry["valid"] = False

                            if broadcastEntry["valid"]:
                                broadcastEntry["network"] = item[1]

                    #Handle minpoll and max poll if they are provided
                    if len(item) > 2:
                       minPoll = None
                       maxPoll = None
                       for entry in item[2:]:
                           if entry == "minpoll" or entry == "maxpoll":
                               index=item.index(entry)
                               value = None
                               try:
                                   value = int(item[index+1])
                               except:
                                   broadcastEntry["warnings"].append(entry+" entry is invalid")
                                   if broadcastEntry["status"] == "ok":
                                           broadcastEntry["status"] = "sub-optimal"

                               if value != None:
                                   if entry == "minpoll":
                                       minPoll = value
                                   elif entry == "maxpoll":
                                       maxPoll = value
                           else:
                               broadcastEntry["warnings"].append("broadcast entry "+entry+" is unknown")
                               if broadcastEntry["status"] == "ok":
                                   broadcastEntry["status"] = "sub-optimal"

                       #Compare minpoll and max poll
                       if maxPoll != None:
                           if maxPoll not in range( broadcastMaxPollRange[0], broadcastMaxPollRange[1]):
                               broadcastEntry["warnings"].append("maxpoll entry "+str(maxPoll)+" is less than the recommended range of "+str(broadcastMaxPollRange))
                               if broadcastEntry["status"] == "ok":
                                           broadcastEntry["status"] = "sub-optimal"

                       if minPoll != None:
                           if minPoll not in range( broadcastMinPollRange[0], broadcastMinPollRange[1]):
                               broadcastEntry["warnings"].append("minpoll entry "+str(minPoll)+" is less than the recommended range of "+str(broadcastMaxPollRange))
                               if broadcastEntry["status"] == "ok":
                                           broadcastEntry["status"] = "sub-optimal"

                       if minPoll != None and maxPoll != None:
                           if maxPoll < minPoll:
                               broadcastEntry["warnings"].append("maxpoll entry "+str(maxPoll)+" is less than minpoll entry "+str(minPoll))
                               if broadcastEntry["status"] == "ok":
                                           broadcastEntry["status"] = "sub-optimal"

                    broadcastEntries.append(broadcastEntry)

                elif key == "broadcastdelay":
                    broadcastdelayEntry = {}
                    broadcastdelayEntry["warnings"] = []
                    broadcastdelayEntry["errors"]   = []
                    broadcastdelayEntry["status"]   = "ok"
                    broadcastdelayEntry["valid"]    = True


                    if len(item) < 2:
                        broadcastdelayEntry["errors"].append("No additional directives provided")
                        broadcastdelayEntry["status"]   = "broken"
                        broadcastdelayEntry["valid"]    = False
                   
                    else:
                        #Make sure second item is a flow
                        value = None
                        try:
                            value = float(item[1])
                        except:
                            pass

                        if value == None:
                            broadcastdelayEntry["errors"].append("second entry "+item[1]+" is not a floating point number")
                            broadcastdelayEntry["status"]   = "broken"
                            broadcastdelayEntry["valid"]    = False

                        elif value < 0:
                            broadcastdelayEntry["errors"].append("negative delay values are invalid")
                            broadcastdelayEntry["status"]   = "broken"
                            broadcastdelayEntry["valid"]    = False

                        elif value > 1.0:
                            broadcastdelayEntry["warnings"].append("value of "+str(value)+" outside of expected range")
                            if broadcastdelayEntry["status"] == "ok":
                                broadcastdelayEntry["status"]   = "sub-optimal"

                    if len(item) > 2:
                        broadcastdelayEntry["warnings"].append("Broadcast delay has more than two entries")
                        if broadcastdelayEntry["status"] == "ok":
                            broadcastdelayEntry["status"]   = "sub-optimal"

                    broadcastdelayEntries.append(broadcastdelayEntry)

                elif key not in directives:
                    print("WARNING: Unknown directive :"+key+" --- ignoring")

            previousInfo = item

    #########################################
    # Define success here
    #########################################
   
    #The drift file is optional, but sould generate a warning if it's not provided
    #or if it is not configured correctly. If there are multiple driftfiles, we 
    #will look at the first.
    #
    driftfileResult={"valid":True,"errors":[],"warnings":[],"status":"ok"}

    if len(driftfileEntries) == 0:
        driftfileResult["warnings"].append("No drift file entries provided. Accuracy may suffer")
        driftfileResult["status"] = "sub-optimal"

    else:
        if len(driftfileEntries) > 1:
            driftfileResult["warnings"].append("Multiple drift files specified")
            driftfileResult["status"] = "sub-optimal"

        else:
            driftValid = True
            optimal = False
            subOptimal = False
            broken = False

            for item in driftfileEntries:
                if not item["valid"]:
                    driftfileResult["valid"] = False
                    driftfileResult["status"] = "broken"
                    driftValid = False

                if item["status"] == "broken":
                    driftfileResult["status"] = item["status"]
                elif driftfileResult["status"] == "ok" or item["status"] == "sub-optimal":
                    driftfileResult["status"] = item["status"]
                    

            driftfileResult["valid"] = driftValid

    #The leapfile is optional, but sould generate a warning if it's not provided
    #or if it is not configured correctly. If there are multiple Leapfiles, we 
    #will look at the first
    #
    leapfileResult={"valid":True,"errors":[],"warnings":[],"status":"ok"}
    if len(leapfileEntries) == 0:
        leapfileResult["warnings"].append("No leap fileentries provided.")
        if leapfileResult["status"] == "ok":
            leapfileResult["status"] = "sub-optimal"
    else:
        if len(leapfileEntries) > 1:
            leapfileResult["warnings"].append("Multiple leapfiles specified")
            if leapfileResult["status"] == "ok":
                leapfileResult["status"] = "sub-optimal"

        leapValid = True
        for item in leapfileEntries:
            if not leapfileEntries[0]["valid"]:
                leapfileResult["warnings"].append("Invalid leapfile configuration")
                leapfileResult["status"] = "broken"
                leapValid = False

    # Make sure we have a valid pool file. Ideally we should have either 1 or 4+
    poolResult = {"valid":True,"errors":[],"warnings":[], "status":"ok", "servers":[]}
    validPools = 0
    for item in poolEntries:
        if item["valid"] == True:
            validPools = validPools + 1

        poolResult["servers"].append(item)

    #Make sure we have from 1-4 pools
    if validPools > 1 and validPools < 4:
        poolResult["warnings"].append(str(validPools)+" detected. It is recommended to have either one server or 4+")
        if poolResult["status"] == "ok":
            poolResult["status"] = "sub-optimal"

    #If we don't have any valid pools
    if validPools == 0:
        poolResult["valid"] = False
        poolResult["warnings"].append("no valid pools")
        poolResult["status"] = "broken"
        
    # Make sure we have a valid server file. Ideally we should have either 1 or 4+
    serverResult={"valid":True,"errors":[],"warnings":[], "status":"unknown","servers":[]}
    validServers = 0
    localServers = 0
    status = "ok"
    for item in serverEntries:
        if item["localClock"]:
            localServers = localServers + 1
        if item["valid"] == True:
            validServers = validServers + 1
        else:
            status = "sub-optimal"

        serverResult["servers"].append(item)

    serverResult["status"] = status

    if validServers == 0:
        serverResult["valid"] = False
        serverResult["status"] = "broken"

    if localServers > 0:
        serverResult["hwclock"] = True

    if localServers > 1:
        serverResult["warnings"].append("Multiple local servers are defined")
        if serverResult["status"] == "ok":
            serverResult["status"] = "sub-optimal"



    #Handle restrict items

    restrictResult = {"valid":True,"errors":[],"warnings":[], "status":"ok"}
    #Make sure restrictions are compatible with the server/pool
    #There is a known bug where the nopeer directive without an additional
    #restrict soruce can prevent the pool directive from working
    if poolResult["valid"]:
        nopeer = False
        source = False
        for item in restrictEntries:
            if item["interface"] == "source":
                source = True

            if "nopeer" in item["restrictions"]:
                nopeer = True

        if nopeer and not source:
            #SDF Need to see if this is an error rather than a warning
            poolResult["warnings"].append("'restrict nopeer' directive used without 'restrict soruce' directive. This may prevent pools from working")
 

    #Check broadcast settings
    #If we have at least one vald subnet, enabled = True
    #Make a complete list of available networks
    broadcastResult = {"valid":True,"enabled":False,"errors":[],"warnings":[], "status":"ok", "networks":[]}
    for entry in broadcastEntries:
        if entry["network"] != None:
            broadcastResult["networks"].append(entry["network"])
            if entry["valid"]:
                broadcastResult["enabled"] = True
            else:
                #If any settings are invalid, then all broadcast is invalid
                broadcastResult["valid"] = False
                broadcastResult["errors"].append("Invalid broadcast settings for "+str(entry["network"]))
                broadcastResult["status"] = "broken"

        #If we have valid and invalid networks, geneate an error
        if broadcastResult["enabled"] == True and broadcastResult["valid"] == False:
            broadcastResult["warnings"].append("Not all broadcast entries are valid")
            if broadcastResult["status"] == "ok":
                broadcastResult["status"] = "sub-optimal"
        
        #If broadcast delay is set, generate a warning
        if len(broadcastdelayEntries) > 0:
            broadcastResult["warnings"].append("broadcastdelay entries may degrade performance")
            if broadcastResult["status"] == "ok":
                broadcastResult["status"] = "sub-optimal"

        valid = True
        status = "ok"
        for bcdEntry in broadcastdelayEntries:
            if not bcdEntry["valid"]:
                valid = False

            broadcastResult["errors"] = broadcastResult["errors"] + bcdEntry["errors"]
            broadcastResult["warnings"] = broadcastResult["warnings"] + bcdEntry["warnings"]

            if status == "ok" and bcdEntry["status"] == "sub-optimal":
                status = "sub-optimal"

            if bcdEntry["status"] == "broken":
                status = "broken"

        broadcastResult["valid"]  = valid
        broadcastResult["status"] = status
            


    returnValue["details"]["driftfile"] = driftfileResult
    returnValue["details"]["leapfile"] = leapfileResult
    returnValue["details"]["pool"] = poolResult
    returnValue["details"]["server"] = serverResult
    returnValue["details"]["restrict"] = restrictResult
    returnValue["details"]["broadcast"] = broadcastResult


    #We are not valid if we do not have any valid pool or server entries
    if not (serverResult["valid"] | poolResult["valid"]):
        returnValue["errors"].append("no valid server or pool entries")
        returnValue["valid"] = False
 
    #If we are using both servers and pool entries, need to generate a warnings
    if serverResult["valid"] and poolResult["valid"]:
        returnValue["warnings"].append("using both pool and server entries")
        returnValue["status"] = "sub-optimal"

    if broadcastResult["valid"]:
        returnValue["broadcast"] == True

    returnValue["errors"] = returnValue["errors"] + driftfileResult["errors"]
    returnValue["errors"] = returnValue["errors"] + leapfileResult["errors"]
    returnValue["errors"] = returnValue["errors"] + poolResult["errors"]
    returnValue["errors"] = returnValue["errors"] + serverResult["errors"]
    returnValue["errors"] = returnValue["errors"] + restrictResult["errors"]
    returnValue["errors"] = returnValue["errors"] + broadcastResult["errors"]
    
    return returnValue


##
# \brief generates an ntp.conf file based on the contents of an existig file
# \param [in] genFields JSON descriptor of settings to install
# \param [in] ntpData a reference JSON data structure to use
#
def generateNTPJson( genFields, verbose = 0 ):
    pool = []
    servers = []
    broadcastdelay = 0
    timestamp  = True
    driftfile  = True
    leapfile   = True
    statistics = True
    broadcast = []

    validkeys = ["servers","pool","broadcastdelay", "broadcast","timestamp"]

    for key in genFields.keys():
        if key == "servers":
            servers = genFields["servers"]

        elif key == "pool":
            pool = genFields["pool"]

        elif key == "broadcastdelay":
            broadcastdelay = genFields["broadcastdelay"]

        elif key == "broadcast":
            broadcast = genFields["broadcast"]

        elif key == "timestamp":
            timestamp = genFields["timestamp"]
        else:
            print("generateNTPJson Unknown key: "+str(key))
            print("valid keys for generate: "+str(validkeys))
            return False

    if len(pool) == 0 and len(servers) == 0:
        print("No servers or pool servers provided. Unable to complete")
        return False

    if broadcastdelay != False and len(broadcast) == 0:
        print("Broadcast delay without broadcast support meaningless")
        return False

    refData = json.loads(defaultNTPData)

    ntpData = {"version":VERSION, "ntpInfo":[]}

    if timestamp:
        now = datetime.now()
        ntpData["timestamp"] = str(now)

    if driftfile:
        ntpData["ntpInfo"].append(refData["data"]["driftfile"])
        
    if leapfile:
        ntpData["ntpInfo"].append(refData["data"]["leapfile"])

    if statistics:
        ntpData["ntpInfo"].append(refData["data"]["statistics"])

    #Add pool entries
    if len(pool) > 0:
        init = False
        for server in pool:
            serverEntry = copy.deepcopy(refData["data"]["pool"])

            #Only add default comments on the first entry
            if init:
                serverEntry["comments"]=[]

        #Add the server to the list
        ntpData["ntpInfo"].append(serverEntry)

    #Add server entries
    if len(servers) > 0:
        init = False
        for server in servers:
            if server == "hwclock":
                serverEntry = copy.deepcopy(refData["data"]["hwclock"])

            else:
                serverEntry = refData["data"]["server"]

                #Only add default comments on the first entry
                if init:
                    serverEntry["comments"]=[]

                #Add new server address
                serverEntry["info"][0][1] = server

            #Add the server to the list
            ntpData["ntpInfo"].append(serverEntry)

            init = True

    #Add broadcast info
    if len(broadcast) > 0:
        broadcastdelayEntry = refData["data"]["broadcastdelay"]

        #If we have a specified broadcast delay, use it
        if broadcastdelay > 0.0:
            broadcastdelayEntry["info"][0][2] = str(broadcastdelay)

        if broadcastdelay > 0.0:
            ntpData["ntpInfo"].append(broadcastdelayEntry)

        #Add broadcast entries
        for net in broadcast:
            broadcastEntry = copy.deepcopy(refData["data"]["broadcast"])
            broadcastEntry["info"][0][1] = net
            ntpData["ntpInfo"].append(broadcastEntry)

    return ntpData
 
##
# \brief tracks ntp performance over time
def trackStats( minDelay=15):
    offset = 100

    print("Time                           \tDelay\tOffset\tjitter")

    cmd = "ntpq -p |grep \"*\""
    while abs(offset) > 15.0:
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            array=["x","x","x"]

        else:
            line = result["value"]
            array = line.split()
        now = datetime.now()
        offset = float(array[-2])

        print(str(now)+"\t"+str(array[-3]+"\t"+array[-2]+"\t"+array[-1]))

        time.sleep(1)

        return ntpData

##
# \brief verifies that the specified server is a valid network endpoint
#
def testServer( server):
    if not isinstance(server, str):
        print("Unable to test a server of a non-string type")
        return False

    #ping the server to make sure it's on the network
    result = CommandParser.runCommand(str("ping -c 1 "+server+" |grep received |cut -d ' ' -f1"))
    if result.value != "1":
        return False

    return True

##
# \brief Unit test function for the class
#
# This test works by recursively running a sequence of OS commands. To be successful, the
# unit test needs to be run as root on a system where the ntp configuration can be modified.
def test(verbose = 0):
    #Get information
    ts = str(datetime.now().timestamp())

    cmd = "cat /etc/machine-id"
    res = CommandParser.runCommand(cmd)
    machineId = res["value"]
    


    if verbose:
        print("NTPManager Unit test")

    success = True
    workDir = "/tmp/NTPManagerTest/"

    testResult = {}
    testResult["timestamp"] = ts
    testResult["machine-id"] = machineId
    testResult["version"]   = VERSION
    testResult["pass"]     = True
    testResult["data"]      = {}
    testResult["data"]["generate"] = "unknown"
    testResult["data"]["copy"]     = "unknown"
    testResult["data"]["sudo"]     = {}
    testResult["data"]["sudo"]["generate"]              = "unknown"
    testResult["data"]["sudo"]["validate"]              = "unknown"
    testResult["data"]["sudo"]["gen+validate"]          = "unknown"
    testResult["data"]["sudo"]["extraFields"]           = "unknown"
    testResult["data"]["sudo"]["genInvalidServer"]      = "unknown"
    testResult["data"]["sudo"]["genInvalidServerForce"] = "unknown"

    #Create a test directory if it doesn't exist
    result = CommandParser.validateFile(workDir)
    if not result["exists"]:
        result = CommandParser.runCommand("mkdir "+workDir)
        if result["returnCode"]:
            print("FAILURE: Unable to create "+workDir)
            print("RESULT: "+json.dumps(result, indent=4))
            return False

    #Specify the generation destination file
    genDest  = workDir+"ntp1.conf"
    outDest  = workDir+"ntp2.conf"

    ##########################
    # Test: Generate an ntp.conf file, read it in and then create a second file
    #         Files should match
    ##########################
    if verbose:
        print("- Generate an ntp.conf file")

    cmd = "./NTPManager.py -changeState '{\"servers\":[\"time2.google.com\"],\"broadcast\":[\"10.0.0.255\",\"192.168.2.255\"]}' -outputFile "+genDest
    if verbose > 1:
        print("\t...COMMAND: "+cmd)

    result = CommandParser.runCommand(cmd)
    if result["returnCode"] != 0:
        print("FAILURE: Unable to generate file "+genDest)
        print("Result:\n"+json.dumps(result,indent=4))
        print("Aborting unit tests")
        testResult["pass"] = False
        testResult["data"]["generate"] = "fail"
    else:
        ntpJson = readNTP(genDest)
        ret = validateNTPData( ntpJson )
        if not ret["valid"]:
            print("ERROR: Invalid NTP File generated")
            if verbose > 1:
                print("RESULT:\n"+json.dumps(ret))


            testResult["pass"] = False
            testResult["data"]["generate"] = "fail"

        else:
            success = True
            testResult["data"]["generate"] = "pass"

    if success:
        if verbose:
            print("- loading file and writing a new one. Comparing for consistency")
        #Load ntpFile and write a second ntp File
        cmd = "./NTPManager.py -inputFile "+genDest+" -outputFile "+outDest
        if verbose > 1:
            print("\t...COMMAND: "+cmd)
        result = CommandParser.runCommand(cmd)
        if result["returnCode"] != 0:
            print("FAILURE: to generate outputFile "+outDest+" with return code: "+str(result["returnCode"]))
            print("Result:\n"+json.dumps(result,indent=4))
            testResult["data"]["copy"] = "fail"
        
        else:
            #Files should match
            cmd = "cmp "+genDest+" "+outDest
            result = CommandParser.runCommand(cmd)
            if verbose > 1:
                print("\t...COMMAND: "+cmd)

            if result["returnCode"] != 0:
                print("FAILURE: unable to compare files in command \""+cmd+"\"")
                print("Result:\n"+json.dumps(result,indent=4))
                testResult["data"]["copy"] = "fail"
            elif len(result["value"]) > 0:
                print("FAILURE: "+str(result["value"]))
                testResult["data"]["copy"] = "fail"
            else:
                testResult["data"]["copy"] = "pass"

    ##########################
    # Test: Convert ntp.conf to json, save json, read json, write to ntp.conf
    #         File should match
    ##########################
    if success:
        if verbose:
            print("- converting file to a json file")
        jsonSuccess = True
        jsonDest = workDir+"ntp1.json"
        testOut  = workDir+"ntpJson.conf"

        cmd = "./NTPManager.py -inputFile "+genDest+" -outputJson "+jsonDest
        if verbose > 1:
            print("\t...COMMAND: "+cmd)
        result = CommandParser.runCommand(cmd)
        if result["returnCode"]:
            print("FAILURE: unable to compare files in command \""+cmd+"\"")
            print("Result:\n"+json.dumps(result,indent=4))
            jsonSuccess = False
            testResult["data"]["jsonExportImport"] = "fail"

        if jsonSuccess:
            if verbose:
                print("- converting json file to conf file")

            cmd = "./NTPManager.py -inputJson "+jsonDest+" -outputFile "+testOut
            if verbose > 1:
                print("\t...COMMAND: "+cmd)
            result = CommandParser.runCommand(cmd)
            if result["returnCode"] != 0:
                print("FAILURE: unable to compare files in command \""+cmd+"\"")
                print("Result:\n"+json.dumps(result,indent=4))
                jsonSuccess = False
                testResult["data"]["jsonExportImport"] = "fail"

        if jsonSuccess:
            #Files should match
            if verbose:
                print("- comparing original file with json generated output file")
            cmd = "cmp "+genDest+" "+testOut 
            result = CommandParser.runCommand(cmd)
            if verbose > 1:
                print("\t...COMMAND: "+cmd)
            if result["returnCode"] != 0:
                print("FAILURE: unable to compare files in command \""+cmd+"\"")
                print("Result:\n"+json.dumps(result,indent=4))
                testResult["data"]["jsonExportImport"] = "fail"
                jsonSuccess = False

            elif len(result["value"]) > 0:
                print("FAILURE: "+str(result["value"]))
                testResult["data"]["jsonExportImport"] = "fail"
                jsonSuccess = False

    if not CommandParser.checkSudo():
        print("All basic tasks have passed")
        print("Unable to complete unit tests without sudo access")
        return testResult

    print()
    print("This section will change NTP settings and then restore the original. This can take a few minutes")
    print("DO NOT INTERRUPT!")
    print()

    ##########################
    # Test: Backup the ntp.conf file
    #         Should pass validation and daemonValidation test
    ##########################
    ts = str(datetime.now().timestamp())
    ntpFile = "/etc/ntp.conf"
    bakFile = workDir+"ntp.conf_"+str(ts)

    if verbose > 0:
        print("- BACKUP: creating a copy of "+ntpFile+" at "+bakFile)

    #Backup the file
    cmd = "cp "+ntpFile+" "+bakFile
    if verbose > 1:
        print("\t...COMMAND: "+cmd)
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        print("FAILURE: Unable to back up "+ntpFile)
        print("Result:\n"+json.dumps(result, indent=4))
        return testResult 

    #Compare to ensure correctness
    cmd = "cmp "+ntpFile+" "+bakFile
    if verbose > 1:
        print("\t...COMMAND: "+cmd)
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        print("FAILURE: Unable to compare "+ntpFile+" with its backup: "+bakFile )
        print("Result:\n"+json.dumps(result, indent=4))
        return testResult

    if len(result["value"]) > 0:
        print("FAILURE: backup file "+backFile+" does not match original "+ntpFile)
        print("Result:\n"+json.dumps(result, indent=4))
        return testResult

    #Going forward, we are testing changes to the actual configuration. The success
    #variable will track if we are successful. At the end, we need to restore the
    #orginal ntp.conf file
    success = True

    ##########################
    # Test: Generate an ntp.conf with a valid server
    #         Should pass validation and daemonValidation test
    ##########################
    if verbose:
        print("- Creating a file with a valid server --- this will take several seconds")

    verb = ""
    if verbose:
        verb = "-v"

    cmd = "./NTPManager.py "+verb+" -changeState '{\"servers\":[\"time2.google.com\"],\"broadcast\":[\"10.0.0.255\"]}' -outputFile "+ntpFile
    if verbose > 1:
        print("\t...COMMAND: "+cmd)
        print("\t---- this can take several seconds")

    result = CommandParser.runCommand( cmd )
    if result["returnCode"]:
        print("FAILURE: Unable to generate "+ntpFile+" file")
        testResult["data"]["sudo"]["generate"] = "fail"
        success = False
    else:
        testResult["data"]["sudo"]["generate"] = "pass"


    ##########################
    # Test: Validate ntp.conf with a valid server
    #         Should pass validation and daemonValidation test
    ##########################
    if verbose:
        print("- Validating a file with a valid server --- this will take several seconds")

    verb = ""
    if verbose:
        verb = "-v"

    cmd = "./NTPManager.py "+verb+" -validate"
    if verbose > 1:
        print("\t...COMMAND: "+cmd)
        print("\t---- this can take several seconds")
    result = CommandParser.runCommand( cmd )
    if result["returnCode"]:
        print("FAILURE: Unable to generate "+ntpFile+" file")
        testResult["data"]["sudo"]["validate"] = "fail"
        success = False
    else:
        testResult["data"]["sudo"]["validate"] = "pass"

    #############################################
    # Test: Generate and validate ntp.conf
    #############################################
    if verbose:
        print("- Create and validate an file with a valid server --- this will take several seconds")

    verb = ""
    if verbose:
        verb = "-v"

    cmd = "./NTPManager.py "+verb+" -validate -changeState'{\"servers\":[\"time2.google.com\"],\"broadcast\":[\"10.0.0.255\"]}' -outputFile "+ntpFile
    if verbose > 1:
        print("\t...COMMAND: "+cmd)
        print("\t---- this can take several seconds")
    result = CommandParser.runCommand( cmd )
    if result["returnCode"]:
        print("FAILURE: Unable to generate "+ntpFile+" file")
        testResult["data"]["sudo"]["gen+validate"] = "fail"
        success = False
    else:
        testResult["data"]["sudo"]["gen+validate"] = "pass"

    ##########################
    # Test: Add nonsense line to ntp.conf
    #         Should pass validation test with warning
    ##########################
    testString = "testString"
    if verbose:
        print("- Testing added info")

    fp = open(ntpFile, "a")
    fp.write(testString)
    fp.close()


    cmd = "./NTPManager.py "+verb+" -validate"
    if verbose > 1:
        print("\t...COMMAND: "+cmd)
    result = CommandParser.runCommand( cmd )
    if result["returnCode"]:
        print("FAILURE: Error on validation")
        print("RESULT: "+json.dumps(result, indent=4))
        testResult["data"]["sudo"]["extraFields"] = "fail"
        success = False

    #Result["value"] should have 
    valueSubStr = "WARNING: Unknown directive :"+testString+" --- ignoring"
    if not valueSubStr in result["value"]:
        print("ERROR: Warning message not created for "+testString)
        testResult["data"]["sudo"]["extraFields"] = "fail"
        success = False
    else:
        testResult["data"]["sudo"]["extraFields"] = "pass"

    ##########################
    # Test: Generate an ntp.conf with an invalid server
    #         Should return to previous version
    ##########################
    if verbose:
        print("- Creating an file with an invalid server --- this will take several seconds")
    invalidServer = "254.0.0.1"
    cmd = "./NTPManager.py "+verb+" -validate -changeState '{\"servers\":[\""+invalidServer+"\"],\"broadcast\":[\"10.0.0.255\"]}' -outputFile "+ntpFile
    if verbose > 1:
        print("\t...COMMAND: "+cmd)
        print("---- this can take several seconds")
    result = CommandParser.runCommand( cmd )
    if not result["returnCode"]:
        print("FAILURE: Unexpected success with invalid server: "+invalidServer)
        testResult["data"]["sudo"]["genInvalidServer"] = "fail"
        success = False
    else:
        testResult["data"]["sudo"]["genInvalidServer"] = "pass"

    ##########################
    # Test 4: Generate an ntp.conf with an invalid server and force apply
    #         Should not pass validation test afterwards
    ##########################
    if verbose:
        print("- Creating an file with an invalid server using -force --- this will take several seconds")
    invalidServer = "254.0.0.1"
    cmd = "./NTPManager.py "+verb+" -validate -changeState'{\"servers\":[\""+invalidServer+"\"],\"broadcast\":[\"10.0.0.255\"]}' -outputFile "+ntpFile+" -force"
    if verbose > 1:
        print("\t...COMMAND: "+cmd)
        print("---- this can take several seconds")
    result = CommandParser.runCommand( cmd )
    if result["returnCode"]:
        print("FAILURE: unable to set invalid server with -force: "+invalidServer)
        testResult["data"]["sudo"]["genInvalidServerForce"] = "fail"
        success = False

    #System should faile validation
    cmd = "./NTPManager -validateDaemon -v"
    result = CommandParser.runCommand(cmd)
    if not result["returnCode"]:
        print("Able to validate daemon when expected to be false!")
        testResult["data"]["sudo"]["genInvalidServerForce"] = "fail"
        success = False
    else:
        testResult["data"]["sudo"]["genInvalidServerForce"] = "pass"

    ##########################
    # Restore original ntp.conf file
    ##########################
    #Restore the file
    if verbose > 0:
        print("- RESTORE: Copying "+bakFile+" to "+ntpFile)
    cmd = "cp "+bakFile+" "+ntpFile
    if verbose > 1:
        print("\t...COMMAND: "+cmd)
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        print("FAILURE: Unable to back up "+ntpFile)
        print("Result:\n"+json.dumps(result, indent=4))
        testResult["pass"] = False
        return testResult

    #Compare to ensure correctness
    cmd = "cmp "+ntpFile+" "+bakFile
    if verbose > 1:
        print("\t...COMMAND: "+cmd)
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        print("FAILURE: Unable to compare "+ntpFile+" with its backup: "+bakFile )
        print("Result:\n"+json.dumps(result, indent=4))
        testResult["pass"] = False
        return testResult

    if len(result["value"]) > 0:
        print("FAILURE: backup file "+backFile+" does not match original "+ntpFile)
        print("Result:\n"+json.dumps(result, indent=4))
        testResult["pass"] = False
        return testResult

    ##########################
    # Restart NTP and validate the daemon
    # Compare to ensure correctness
    ##########################
    cmd = "./NTPManager.py "+verb+" -validateDaemon"
    if verbose > 1:
        print("\t...COMMAND: "+cmd)
        print("\t-------- this can take several seconds")
    result = CommandParser.runCommand(cmd)
    if result["returnCode"]:
        print("CRITICAL FAILURE: Unable to validate daemon on restored ntp.conf")
        print("Result:\n"+json.dumps(result, indent=4))
        testResult["pass"] = False
        return testResult

    else:
        print("- Successfully restored and validated file "+ntpFile)

    if success:
        #Remove test directory
        cmd = "rm -rf "+workDir
        if verbose > 1:
            print("\t...COMMAND: "+cmd)
        result = CommandParser.runCommand( cmd )
        if result["returnCode"] != 0:
            print("FAILURE: Unable to remove "+workDir+" on completion with command: "+cmd)
            testResult["pass"] = False
            return testResult
        else:
            testResult["pass"] = True

 
    return testResult




        
##
# \brief main function
##
if __name__ == "__main__":

    epilog = """\
Additional Parameter Information:
- changeState params - json string in the form {server:[192.168.1.12, time2.google.com], broadcastdelay:.008, broadcast:[10.0.255.255]} 
    Parameter Descriptions:
    - server:          array of hostnames/ips or 'hwclock' 
    - pool:            array of hostnames/ips>
    - broadcastdelay:  delay for broadcast timing"
    - broadcast:       array of networks to broadcast on"

Example Usage:
   ./NTPManager.py -validate -changeState '{"servers":["time2.google.com"],"broadcast":["10.0.0.255","192.168.2.255"]}' -outputFile /etc/ntp.conf
"""

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description="Aqueti NTP Configurator: "+str(VERSION), epilog = epilog)
    #input args
    parser.add_argument("-changeState", action="store", dest="changeState", help="change state of ntp.conf data specified fields with the given parameters")
    parser.add_argument("-inputJson", action="store", dest="inputJson", help="reference ntp.json file")
    parser.add_argument("-inputFile", action="store", dest="inputFile", help="reference ntp.conf file")

    #output args
    parser.add_argument("-printJson", action="store_const", dest="printJson", const=True, help="Print ntp.conf as a JSON file")
    parser.add_argument("-outputJson", action="store", dest="outputJson", help="output JSON representation of ntp.conf file")
    parser.add_argument("-outputFile", action="store", dest="outputFile", help="output a copy of the ntp.conf file")
    parser.add_argument("-force", action="store_const", dest="force", const=True, help="Force changes even if validation steps fail")

    #Processing args
    parser.add_argument("-checkHash", action="store", dest="checkHash", help="file to check hash for")
    parser.add_argument("-validate", action="store_const", dest="validateDaemon", const=True, help="Validate ntp settings")
    parser.add_argument("-disableTimeDateCtl", action="store_const", dest="disableTimeDateCtl", const=True, help="Disables conflicting timedatectl settings")
#    parser.add_argument("-validateDaemon", action="store_const", dest="validateDaemon", const=True, help="Validate ntpd")
    parser.add_argument("-version", action="store_const", dest="version", const=True, help="prints vrsion information for this script")
    parser.add_argument("-trackStats", action="store_const", dest="trackStats", const=True, help="tracks performance statistics over time")
    parser.add_argument("-v", action="store_const", dest="v", const="True", help="enable verbose output")
    parser.add_argument("-vv", action="store_const", dest="vv", const="True", help="enable very verbose output")

    #Testing args
    parser.add_argument("-test", action="store_const", dest="test", const=True,  help="Runs unit tests for software as a sequence of commands")

    args = parser.parse_args()

    if args.version:
        print("NTPManager version: "+VERSION)
        exit(1)

    inputFile = "/etc/ntp.conf"
    validInfo = True

    #Get verbose settings
    verbose = 0
    if args.v:
        verbose = 1
    if args.vv:
        verbose = 2

    # run the test and exit
    if args.test:
        result = test(verbose)

        if verbose:
            print("Test Result:\n"+json.dumps(result, indent=4))
        if not result["pass"]:
            print("NTPManager failed its unit tests")
        else:
            print("NTPManager passed its unit tests")

        if args.outputJson:
            fp = open(args.outputJson, "w")
            json.dump( result, fp, indent=4)
            fp.close()
        else:
            print(json.dumps(result, indent=4))

        exit(0)

    ########################################
    #Get NTP data into JSON form
    ########################################
    #Avoid duplicate entries
    inputs = bool(args.changeState) + bool(args.inputJson)+bool(args.inputFile)
    if inputs > 1:
        print("ERROR: Only one input option permitted (-changeState, -inputJson, -inputFile)")
        exit(1)
    if inputs == 0:
        info = readNTP("/etc/ntp.conf")
    else:
        #generateFile
        if args.changeState:
            genFields = {"servers":["hwclock"]}

            if args.changeState != "default":
                try:
                    genFields = json.loads( args.changeState)
                except:
                    print("ERROR: invalid fields for generate directive: "+str(args.changeState))
                    print("Please make sure entry is properly quoted")
                    print("ARGS: "+str(args.changeState))
                    exit(1)

            info = generateNTPJson(genFields, verbose)
            if info == False:
                print("Unable to generate ntp data with the following fields:")
                print(json.dumps(genFields, indent=4))
                exit(1)
    
        #Input json reads content from a JSON file
        elif args.inputJson:
            info = readNTPJson( args.inputJson )
            if not info:
                exit(1)
            print("INFO:\n"+json.dumps(info, indent=4))
    
        # read NTP File
        elif args.inputFile:
            print("Reading NTP")
            info = readNTP(args.inputFile)

        else:
            print("No input provided")


    ########################################
    # Processing and analysis
    ########################################
    if args.disableTimeDateCtl:
        cmd = "timedatectl set-ntp 0"
        ret = CommandParser.runCommand(cmd)
        if ret["returnCode"]:
            print("Unable to disable ntp settings in timedatectl. Make sure you run as sudo")
            exit(1)
#    if args.validate:
#        if verbose:
#            print("Validating NTP Data")
#        result = validateNTPData(info, verbose=verbose)
#        if result["valid"]:
#            print("PASS: NTP information passes the validation test. Status: "+result["status"])
#            if verbose > 1:
#                print("VALIDATION RESULT: ")
#                print(json.dumps(result,indent=4))
#
#            validInfo = True
#
#        else:
#            print("FAIL: NTP information does not pass the validation test. Status: "+result["status"])
#            if verbose > 0:
#                print("VALIDATION: ")
#                print(json.dumps(result,indent=4))
#
#            validInfo = False

    ########################################
    # Output information
    ########################################
    if args.printJson:
        print(json.dumps(info, indent=4))

    if args.outputJson:
        fp = open(args.outputJson, "w")
        json.dump( info, fp, indent=4)
        fp.close()

    if args.outputFile:
        if args.outputFile == "/etc/ntp.conf":
            #If we're overwritting ntp.conf, make sure we're validated
            if not validInfo and args.outputFile == "/etc/ntp.conf":
                print("Information not valid. Not recommended to overwrite /etc/ntp.conf")
                
                if not args.force:
                    print("Exiting!")
                    exit(1)

        #Write the data to a file
        out = writeNTPFile(info, args.outputFile)


        #validate the daemon if there is a new /etc/ntp.conf
        if args.outputFile == "/etc/ntp.conf" and not args.force:
            result = validateNTPDaemon(restart = True)

            #If we don't haev a valid result, restore backup
            if not result["valid"]:
                print("FAILED: Daemon not successfully validated.")
                print("Restoring previous ntp.conf")
                ret = restoreNTPFile("/etc/ntp.conf")


    ########################################
    #Stand-alone functionality
    ########################################
    #Validate daemon (no input required
    if args.validateDaemon:
        result = validateNTPDaemon(restart = True, delay=20, verbose = verbose)

        if result["valid"]:
            if verbose > 1:
                print("RESULT:"+json.dumps(result,indent=4))

            if result["hwclock"]:
                print("SUCCESS: daemon is successfully referencing a hardware clock")
            else:
                print("SUCCESS: daemon is successfully referencing an external clock")
        else:
            print("FAILURE: current daemon is not properly configured")
            if verbose:
                print("RESULT:"+json.dumps(result, indent=4))


    if args.checkHash:
        result = checkHash( args.checkHash)

        if not result:
            print("Hash does not match. "+args.checkHash+" has been modified")
        else:
            print("Hash matches. "+args.checkHash+" has not been modified")

    if args.trackStats:
        result = trackStats()
