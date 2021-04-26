#!/usr/bin/python3
import subprocess
from datetime import datetime
import json
import re
import argparse
import shlex
import sys
import os
import time

VERSION = "-1.0.0"
PING_ATTEMPTS_MAX = 10

##
# \brief runs a command line argument and returns the result
#
# This function parses the command based on spaces to generate an array of arguments
# that get passed inot a bash script. The output is then returned as a string
#
# Caveats
# - this function does not return quoted text in quotes. For example, "echo \'hello\'" returns "hello"
def runCommand( entry ):
    result = {}
    result["value"]      = ""
    result["error"]      = ""
    result["returnCode"] = 0


    try:
        commands = entry.split("|")
    except:
        return result

    procs = {}
    index = 0
    info = None

    for command in commands:
        value = None
        info = None
        returnCode = 0

#        cmd = command.rstrip().split(" ")
        cmd = shlex.split(command.rstrip())

        target = None

        #check for redirect. Assume this is a redirection
        if ">" in cmd:
            redir = cmd.index(">")
            target = cmd[redir+1]
            cmd = cmd[0:redir]


        if index == 0:
            try:
                procs[index] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except:
                pass
        else:
            try:
                procs[index] = subprocess.Popen(cmd, stdin=procs[index-1].stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except:
                pass

        #If we had a redirection, try to write file
        if target:
            info,err = procs[index].communicate()
            returnCode = procs[index].returncode
            output=info.decode('utf-8').rstrip()

            f = open(target,'w')
            f.write(output)
            f.close()

            value = ""

        index = index+1

    if len(procs) > 0:
        proc = procs[len(procs)-1]
        if info == None:
            info, err = proc.communicate()

        returnCode = proc.returncode

        if value == None:
            result["value"] = info.decode('utf-8').rstrip()

        if err != None:
            result["error"] = err.decode('utf-8').rstrip()
        else:
            result["error"] = None

    else:
        returnCode = -1

    result["returnCode"] = returnCode
    
    return result
    
##
# \brief runs a sequence of commands that are in an array
# \param [in] sequence array of command objects
# \return True on success, False on failure
#
# The sequence contains a an array of command objects. Each object includes the command itself
# and the expected return value. On failure, the 
#
def runCommandSequence( sequence ):
    success = True
    result = {}
    result["value"]      = ""
    result["error"]      = ""
    result["returnCode"] = 0 

    ret = None
    for item in sequence:
        if not success:
            continue

        rCode = 0
        error = ""
        value = ""

        #Parse expected returns
        if "returnCode" in item.keys():
            rCode = item["returnCode"]
        if "value" in item.keys():
            value = item["value"]
        if "error" in item.keys():
            error = item["error"]

        ret = runCommand(item["command"])
        if ret["error"] != error and error != "":
            result["error"] = ret["error"]
            success = False
        if ret["value"] != value and value != "":
            result["returnCode"] = ret["returnCode"]
            success = False
        if ret["returnCode"] != rCode:
            print("COMMAND: "+str(item["command"]))
            print(str(json.dumps(ret, indent=4)))
            print("RC:"+str(ret["returnCode"])+" != "+str(rCode))
            result["returnCode"] = ret["returnCode"]
            success = False

        result = ret

        if not success:
            result["errorCommand"] = item
            print("RETURN: "+str(json.dumps(result, indent=4)))
            break

#    print("Final: "+str(json.dumps(result, indent=4)))
    return result

##
# \brief print a progess bar on the command line
# \param [in] delay number of seconds to delay
def printProgress( delay ):
    message = ""
    for i in range(delay):
        message = message+'.'

    for i in range(0,delay):
        message = message[:i]+"+"+message[i+1:]
        print(message, end="\r")
        time.sleep(1)



##
# \brief validates that a file exists and its permissions
# \param [in] filename name of the file to test
# \return structure with information about the file
#
def validateFile( filename ):
     valid = {}
     valid["exists"] = False
     valid["size"] = False
     valid["d"] = False
     valid["r"] = False
     valid["w"] = False
     valid["x"] = False

     #see if it exists and is readable
     result = runCommand("test -e "+filename)
     if result["returnCode"] == 0:
         valid["exists"] = True
     else:
         return valid

     #see if it exists and is readable
     result = runCommand("test -r "+filename)
     if result["returnCode"] == 0:
         valid["r"] = True

     #see if it exists and is readable
     result = runCommand("test -w "+filename)
     if result["returnCode"] == 0:
         valid["w"] = True

     #see if it exists and is readable
     result = runCommand("test -x "+filename)
     if result["returnCode"] == 0:
         valid["x"] = True

     #see if it exists and is readable
     valid["size"] = os.path.getsize(filename)


     result = runCommand("test -d "+filename)
     if result["returnCode"] == 0:
         valid["d"] = True

     return valid

##
# \brief Pings a host to see if it is accessible
# \param [in] host hostname or ip address of the server we're trying to reach
def ping( host):
    pingCount = 0
    pingSuccess = False

    #Loop until account or max attempts
    cmd = "ping -c 1 -W 1 "+host+" |grep received |cut -d' ' -f4"
    while pingCount < PING_ATTEMPTS_MAX and not pingSuccess:
        result = runCommand(cmd)
        if result["value"] == "1":
            pingSuccess = True
        else:
            pingCount = pingCount + 1

    return pingSuccess
 
##
# \brief checks to see if the current user is a root user
# \return True on success, False on failure
def checkSudo():
    result = runCommand("printenv")
    if not "SUDO_COMMAND" in result["value"]:
        return False

    return True

##
# \brief function to do a deep compare of two objects
#
def compareObjects( object1, object2):
    result={"equal":True, "missing":[], "extra":[], "mismatch":[]}
    
    #Compare each key in object 1, compare
    for key in object1.keys():
        #if it key is not in object 2 it is missing
        if key not in object2.keys():
            result["extra"].append(key)
            result["equal"] = False

        #If they are both objects, we could recurse
        elif isinstance( object1[key], dict) and isinstance( object2[key], dict):
            sub = compareObjects(object1[key],object2[key])
            subres = {"mismatch":[], "missing":[], "extra":[]}
            if len(sub["missing"]) > 0:
                subres["missing"].append({key:sub["missing"]})
            if len(sub["extra"]) > 0:
                subres["extra"].append({key:sub["extra"]})
            if len(sub["mismatch"]) > 0:
                subres["mismatch"].append({key:sub["mismatch"]})

            obj = {key:subres}
            result["mismatch"].append(obj)
            result["equal"] = False

        #if the key is in object 2 and they do not match, it is a mismatch
        elif object1[key] != object2[key]:
            result["mismatch"].append(key)
            result["equal"] = False


    #If there is a key in object2 but not object1, it is considered extra
    for key in object2.keys():
        if not key in object1.keys():
            result["missing"].append(key)
            result["equal"] = False

    return result



##
# \brief this function verifies that the command classes are working correctly
#
def test(verbose=True):
    commandSuccess = True
    commands = [
        {
            "cmd":"uname -a |grep Linux | cut -c-6",
            "value":"Linux",
            "error":"",
            "returnCode":0
        },
        {
            "cmd":"echo hello",
            "value":"hello",
            "error":"",
            "returnCode":0
        },
        {
            "cmd":"echo 'hi there'",
            "value":"hi there",
            "error":"",
            "returnCode":0
        },
        {
            "cmd":"echo hi you",
            "value":"hi you",
            "error":"",
            "returnCode":0
        },
        {
            "cmd":"echo \'hello again\'",
            "value":"hello again",
            "error":"",
            "returnCode":0
        },
        {
            "cmd":"adsfasdfasdfs",
            "value":"",
            "error":"",
            "returnCode":-1
        },
        {
            "cmd":"touch /etc/hostname",
            "value":"",
            "error":"touch: cannot touch '/etc/hostname': Permission denied",
            "returnCode":1
        },
        {
            "cmd":"echo parser > /tmp/CMDPARSER.tmp",
            "value":"",
            "error":"",
            "returnCode":0
        }
    ]

    """
    #SDF removed due to ssh dependency. Need new test
    {  
        "cmd":"ssh -V 2>&1 |cut -d' ' -f 1",
        "value":"OpenSSH_7.6p1",
        "error":"",
        "returnCode":0
    }
    """

    #Loop through commands to make sure we get expected results
    for command in commands:
        cmd = command["cmd"]
        if verbose:
            print("COMMAND: "+str(cmd))
        result = runCommand(cmd)
        if result["returnCode"] != command["returnCode"]:
            if verbose:
                print("\treturn code: "+str(result["returnCode"])+", expected: "+str(command["returnCode"]))
            commandSuccess = False
        if result["value"] != command["value"]:
            if verbose:
                print("\tValue: "+str(result["value"]+", expected:"+str(command["value"])))
            commandSuccess = False
        if result["error"] != command["error"]:
            if verbose:
                print("\tError: "+str(result["error"]+", expected:"+str(command["error"])))
            commandSuccess = False


    #command sequences
    seqSuccess = True
    sequences = [
        {
            "sequence":[ 
                { "command":"echo parser > CMD_PARSER.tmp" },
                { 
                    "command":"cat CMD_PARSER.tmp",
                    "value":"parser"
                },
                { 
                    "command":"rm CMD_PARSER.tmp",
                }
            ]
        },
        {
            "sequence":[
                {    
                    "command":"touch /etc/hostname",
                    "error":"touch: cannot touch '/etc/hostname': Permission denied",
                    "returnCode":1
                },
            ], 
            "error":"touch: cannot touch '/etc/hostname': Permission denied",
            "returnCode":1
        },
        {
            "sequence":[
                {    
                    "command":"touch /etc/hostname",
                    "error":"touch: cannot touch '/etc/hostname': Permission denied",
                    "returnCode":1
                }
            ],
            "error":"touch: cannot touch '/etc/hostname': Permission denied",
            "returnCode":1
        }
    ]

    for sequence in sequences:
        value = ""
        error = ""
        returnCode = 0

        if "value" in sequence.keys():
            value = sequence["value"]
        if "error" in sequence.keys():
            error = sequence["error"]
        if "returnCode" in sequence.keys():
            returnCode = sequence["returnCode"]

        if verbose:
            print("SEQ:"+str(sequence["sequence"]))
        result = runCommandSequence(sequence["sequence"])

        if result["returnCode"] != returnCode:
            if verbose:
                print("\tseq return code: "+str(result["returnCode"])+", expected: "+str(returnCode))
            seqSuccess = False
        if result["error"] != error:
            if verbose:
                print("\terror: "+str(result["error"])+", expected: "+str(error))
            seqSuccess = False
        if result["value"] != value:
            if verbose:
                print("\tMyvalue: "+str(result["value"])+", expected: "+str(value))
            seqSuccess = False


    #Test files
    fileSuccess = True
    tempfile = "/tmp/CommandParser.test"

    #Check if the validation file exists
    result = validateFile(tempfile)
    if result["exists"]:
        print("Temporary file: "+tempfile+" exists. Cannot complete validateFile test")
        fileSuccess = False

    #Create the file
    if fileSuccess:
        #create the tempfile
        result = runCommand("touch "+tempfile)
        if result["returnCode"] != 0:
            print("validateFile: Unable to create temporary file: "+tempfile)
            fileSuccess = False
            
    if fileSuccess:
        result = validateFile(tempfile)
        if not result["exists"]:
            print("validateFile: Unable to verify "+tempfile+" exists")
            fileSuccess = False
        if result["size"] != 0:
            print("validateFile: "+tempfile+" size is non-zero after creation")
            fileSuccess = False

        #Change permissions to rwx
        result = runCommand("chmod 777 "+tempfile)
        if result["returnCode"] != 0:
            print("validateFile: Unable to change permissions to 777")
            fileSuccess = False
        else:
            result = validateFile(tempfile)
            if not result["x"]:
                print("validateFile: Invalid executable permission for 777")
                print(json.dumps(result, indent=4))
                exit(1)
                fileSuccess = False
            if not result["r"]:
                print("validateFile: Invalid read permission for 777")
                fileSuccess = False
            if not result["w"]:
                print("validateFile: Invalid write permission for 777")
                fileSuccess = False
            if not result["exists"]:
                print("validateFile: Unable to validate file existence for 777")
                fileSuccess = False

        #Change permissions to rwx
        result = runCommand("chmod -x "+tempfile)
        if result["returnCode"] != 0:
            print("validateFile: Unable to change permissions to -x")
            fileSuccess = False
        else:
            result = validateFile(tempfile)
            if result["x"]:
                print("validateFile: Incorrect executable permission for -x")
                fileSuccess = False
            if not result["r"]:
                print("validateFile: Invalid read permission for -x")
                fileSuccess = False
            if not result["w"]:
                print("validateFile: Invalid write permission for -x")
                fileSuccess = False
            if not result["exists"]:
                print("validateFile: Unable to validate file existence for -x")
                fileSuccess = False

        #Change permissions to rwx
        result = runCommand("chmod -r "+tempfile)
        if result["returnCode"] != 0:
            print("validateFile: Unable to change permissions to -r")
            fileSuccess = False
        else:
            result = validateFile(tempfile)
            if result["x"]:
                print("validateFile: Incorrect executable permission for -r")
                fileSuccess = False
            if result["r"]:
                print("validateFile: Invalid read permission for -r")
                fileSuccess = False
            if not result["w"]:
                print("validateFile: Invalid write permission for -r")
                fileSuccess = False
            if not result["exists"]:
                print("validateFile: Unable to validate file existence for -r")
                fileSuccess = False

        #Check /etc/hostname for no write access
        result = validateFile("/etc/hostname")
        if result["w"]:
            print("validateFile: Invalid write permission for /etc/hostname")
            fileSuccess = False
        if not result["exists"]:
            print("validateFile: Unable to validate file existence for /etc/hostname")
            fileSuccess = False

        #check if /etc is a directory
        result = validateFile("/etc")
        if not result["d"]:
            print("validateFile: /etc not detected as a directory")
            fileSuccess = False

        #remove tempfile
        result = runCommand("rm "+tempfile)
        if result["returnCode"] != 0:
            print("validateFile: Unable to delete temporary file "+tempfile)
            fileSuccess = False

    #Test the ping function
    pingSuccess = True
    if not ping("localhost"):
        print("ping failure: Unable to ping localhost")
        pingSuccess = False
    if not ping("127.0.0.1"):
        print("ping failure: Unable to ping 127.0.0.1")
        pingSuccess = False
    if ping("ping thisisnotreal"):
        print("ping failure: success ping of invalid hostname")
        pingSuccess = False


    #Test SUDO validate (assume non-sudo user)
    sudoSuccess = checkSudo()
    success = commandSuccess and seqSuccess and fileSuccess and pingSuccess 

    if sudoSuccess:
        print("Running as sudo")
    else: 
        print("Not running as sudo")

    #Test comparison
    #SDF needs more extensive testing
    O1={"A":{"B":1,"C":3}}
    O2={"A":{"B":2, "D":"A"},"test":"123"}

    result = compareObjects(O1, O2)
    print("COMPARE:"+json.dumps(result, indent=4))



    if verbose:
        print("Command Success:  "+str(commandSuccess))
        print("Sequence Success: "+str(seqSuccess))
        print("File Success:     "+str(fileSuccess))
        print("Ping Success:     "+str(pingSuccess))
        print("Success:           "+str(success))


    if success:
        print("CommandParser Successfully passed all tests")
    else:
        print("CommandParser Failed")
    return success




##
# \brief entry function
if __name__ == "__main__":
    verbose = 0

    parser = argparse.ArgumentParser(description=str("AQUETI Validation Script "+str(VERSION)))
    parser.add_argument("-test", action="store_const", dest="test", const="True", help="Run unit tests")
    parser.add_argument("-v", action="store_const", dest="v", const="True", help="verbose printing")
    args = parser.parse_args()

    if args.v:
        verbose = 1

    if args.test:
        test(verbose)
        
    else:
        print("Aqueti argument parser")


