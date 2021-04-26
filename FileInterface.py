#!/usr/bin/python3
###########################################################
# FileInterface.py
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
#
# TODO:
#    - make json representation of conf and yaml files consistent
###########################################################
import json
import CommandParser
import argparse
import copy
from datetime import datetime
import time
import hashlib
import os
import yaml

VERSION="0.0.1"
BAK_DIR = "/var/log/aqueti/"
MAX_BAK_FILES = 10
META_LINE = "#############################################"

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
#
def readYaml( source ):
    yamlData = {"comments":[]}
    metadata = []
    #pull off comments
    with open( source, 'r') as fptr:
        fileInfo = fptr.read()

    lines = fileInfo.splitlines(1)
    index = 0
    yd = ""

    meta = 0
    fileMeta = 0
    for line in lines:
        line = line.rstrip()

        if META_LINE in line:
            meta = meta + 1
            continue

        elif meta > 0 and meta < 2:
            if "Written by FileInterface.py" in line:
                genVersion = line.split(" ")[-1]
                yamlData["fileVersion"] = genVersion
                fileMeta = 1
 
            elif len(line) > 2:
                if "# Date:" in line:
                    yamlData["timestamp"] = line[8:]
                    continue
                elif "# Hash:" in line:
                    fileHash = line.split(" ")[-1].lstrip()
                else:
                    metadata.append( line )
                continue

        else:
            yd = yd + line+"\n"

    yData = yaml.load(yd)

    yamlData["data"] = yData
    yamlData["metadata"] = metadata
    return yamlData

##
# \brief writes the data in a yaml object to a file
#
# This function will write the lines in the "comments" array in the yData
# object as a header to the yaml file. The information in the "data"
# object will then be added in yaml form.
#
# A YAML file can have multiple comments in the beginning but only single line comments afterwards
def writeYaml( yData, dest ):

    #make sure yData is an object
    if not isinstance( yData, object):
        print("ERROR: writeYaml can only write objects")

    #Make sure we have the appropriate fields
    if not "data" in yData.keys():
        print("ERROR: writeYaml assumes an object with a yaml sub-object")
        return False

    #Add the yaml data to the buffer
    data = yaml.dump(yData["data"], default_flow_style=False)

    newHash = hashlib.md5(str(data).encode())
    newHash = str(newHash.hexdigest())

    #Build the header
    header = META_LINE+"\n"
    if "metadata" in yData.keys():
        for item in yData["metadata"]:
            if item[0] == "#":
                header =header + item+"\n"
            else:
                print("Metadata "+item+" does not have a leading #. Discarding")
        header = header + "#\n"

    header = header + "# Written by FileInterface.py version "+VERSION+"\n"    
    header = header + "# Date: "+ str(datetime.now())+"\n"
    header = header + "# Hash: "+ str(newHash)+"\n"
    header = header + META_LINE+"\n"

    data = header + data

    with open(dest, 'w') as fptr:
        fptr.write(data)
    fptr.close()

    #Verify data was properly written
    d2 = readYaml( dest )
    if d2["data"] != yData["data"]:
        print("Saved data does not match")
        print("yData:\n"+json.dumps(yData,indent=4))
        print("d2:\n"+json.dumps(d2,indent=4))
        return False

    return True


##
# \brief reads in the specifed configuration file into a JSON format
# \param [in] filename name to read
# \param [in] delim delimiter in the file
#
# This function for converting a Linux config file into a python dictionary.
# Lines in the config file that begin with a "#" are treated as comments. All
# other lines must begin with a keyword followed by subsequent fields. The
# generated dictionary will create use the key word as the key and the 
# subsequent entries as an array of strings
#
def readConf( filename, delim=None ):
   
    fileData = {}
    fileData["version"] = VERSION

    header = []
    fileInfo = []

    #check if file exists
    info = CommandParser.validateFile( filename )
    if not info["exists"]:
        print("readConf Unable to access "+filename+". The file does not exist")
        return False

    if not info["r"]:
        print("Unable to read "+filename)
        return False
 

    #Read the file into memory
    fp = open(filename,"r")
    data = fp.read()
    fp.close()

    count = 0
    #Convert file into JSON representation
    #For each non-comment line, the first word becomes the key. Subsequent words
    #are written to an array
    entry = {} 
    metadata = []
    comments = []
    entries  = []
    lines    = []
    key = None

    #Each line sequence is a new entry
    headerCount = 0


    #Find the header, if htere is one
    count = 0
    meta = 0
    fileMeta = 0
    for line in data.splitlines(1):
        line = line.rstrip()

        if META_LINE in line:
            meta = meta + 1
            continue

        elif meta > 0 and meta < 2:
            if "Written by FileInterface.py" in line:
                genVersion = line.split(" ")[-1]
                fileData["fileVersion"] = genVersion
                fileMeta = 1
            
            elif len(line) > 2:
                if "# Date:" in line:
                    fileData["timestamp"] = line[8:]
                    continue
                elif "# Hash:" in line:
                    fileHash = line.split(" ")[-1].lstrip()
                else:
                    metadata.append( line )
                continue

        #Find the comments and append them to the comments array. This assumes
        #that comments and subsequent info values do not have separation. If 
        #there is separation, the spacing will generate a comments-only entry

        #If the line is a comment or blank, we check if there is a key. If so, we need 
        #to write the previous comment information before adding the currently line to
        #the next comment array
        #If we have a blank line, assign a comment key
        elif len(line)  <= 1:
            key = "comments"

        elif line[0] == "#":
            comments.append(str(line))

        #Line has info. Generate the entry
        elif len(line) > 1:
            info = line.split(delim)
    
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

            if len(entries) > 0:
                entry["info"] = entries

            #Only add data if we have a value in the entry
            if "comments" in entry.keys() or "info" in entry.keys():
                fileInfo.append(entry)

            comments = []
            entry = {}
            entries = []
            key = None

    fileData["metadata"] = metadata
    fileData["data"] = fileInfo

    return fileData

##
# \brief function to write the json data into a new conf file
# \param [in] data dictionary with file data
# \param [in] backup backup file location. 
# \param [in] version flag to add version info to the file
# \param [in] forceUpdate flag to replace existing version info, even if no change
# 
# \return stucture with a success field to indicate success
#
# This function backups the existing conf file and writes a new
# one based on the values in data. This process will overwrite 
# any existing backup files.
# 
# If the version parameter is set, the outpu file will include additional version
# information including the version of this software, the date the file was 
# generated and a hash number for the file (excluding the hash line) as a
# header. These lines  
#
# ####################################################
# # Created by Aqueti FileInterface version 0.0.1
# # Date: 2020-09-10 15:18:54.820720
# # Hash: 11b685736354feb02b0b19a9f9b24ef5
# ####################################################
#
def writeConf( data, target, delim=" ", backup=True, backupDir = BAK_DIR, createDir=False):
    result = {"success":False, "backupFile":None }

    #Check path exists
    tpath, tfile = os.path.split(target)

    ret = CommandParser.validateFile(tpath)
    if not ret["exists"]:
        if createDir:
            print("Creating directory: "+tpath)
            cmd = "mkdir -p "+tpath
            ret = CommandParser.runCommand( cmd)
            if ret["returnCode"]:
                print("Unable to create directory for target ("+tpath+")")
                return result
        else:
            message = "Target path "+tpath+" does not exist."
            return result

    #See if we have a file to backup. If not, set backup to False
    ret = CommandParser.validateFile( target )
    if not ret["exists"]:
        print("WARNING: File "+target+" does not exist. Unable to backup")
        backup = False

    #buffer to hold the output
    fileBuffer    = ""
    versionBuffer = ""

    #Loop through all keys in the object, generate the necessary comments
    #and lines. Each key is an object that contains an array of comments
    #and a line that starts with key followed by an array of info
    index = 0
    for entry in data["data"]:
        if "comments" in entry.keys():
            #If we have a header, data starts at offset 5, otherwise, it starts at offset 0
            for line in entry["comments"]:
                fileBuffer = fileBuffer + line.rstrip()+ "\n"

        #Handle actual data
        if "info" in entry.keys():
            for value in entry["info"]:
                line = ""
                for item in value:
                    line = line + str(item) + delim

            fileBuffer = fileBuffer + line.rstrip(delim)
        fileBuffer = fileBuffer +"\n"


    #Add empty line after items
    fileBuffer = fileBuffer+"\n"

    #generate hash from the buffer 
    newHash = hashlib.md5(str(fileBuffer).encode())
    newHash = str(newHash.hexdigest())

    #Generate a version buffer from metadata and a date/hash
    versionBuffer = versionBuffer + META_LINE+"\n"

    if "metadata" in data.keys():
        for line in data["metadata"]:
            versionBuffer = versionBuffer + line + "\n"

    versionBuffer = versionBuffer + "#\n"
    versionBuffer = versionBuffer + "# Written by FileInterface.py version "+VERSION+"\n"    
    versionBuffer = versionBuffer + "# Date: "+ str(datetime.now())+"\n"
    versionBuffer = versionBuffer + "# Hash: "+ str(newHash)+"\n"
    versionBuffer = versionBuffer + META_LINE+"\n"

    fileBuffer = versionBuffer + fileBuffer

    #If backup true, copy the existing file to a backup
    if backup:
        ret = backupConf( target, backupDir = backupDir )
        if not ret["success"]:
            print("Unable to backup "+target)
            result["success"] = False
            result["error"] = ret
            result["backupFile"] = None
            return result

        else:
            result["backupFile"] = ret["backupFile"]


    #write the new file to disk
    fp = open(target, "w")
    fp.write(fileBuffer)
    fp.close()

    result["success"] = True

    return result

##
# \brief creates a backup of a file
# \param [in] target path/name of the file to backup
# \param [in] destRoot destination directory to backup to. 
# \return dictionary with function completion status
#    {
#        "success": bool            indicates if function succeeded
#        "message": string          message generated during operation
#        "error": dict              structure with command line error info
#        "backupFile" = backupFile
#    }
#
# This function support two modes of operation. I can replace the target
# specified by target with the file explicitly described with the 
#
# The backup file be the dest variable
# appended with the source file information. This means if source = /etc/ntp.conf 
# dest = /var/log/aqueti, the backup file will be written to
# /var/log/aqueti/ntp.conf
#
def backupConf( target, createDir = True, backupDir=BAK_DIR, maxBackupFiles = MAX_BAK_FILES ):
    result = { "success":False}

    #Convert the target to a path/file
    targetDir, targetFile = os.path.split(target)


    #Strip the tailing slash if it exists
#    backupDir = os.path.split(backupDir)[0]

    #Generate the name for the destination file
    destPath = backupDir +"/"+targetDir+"/"
    backupFile = destPath+targetFile+"_"+str(datetime.now().timestamp())

    #Make sure the source file exists and is valid
    status = CommandParser.validateFile( target )
    if not status["exists"]:
         message = "Unable to back up "+target+". File does not exist"
         print(message)
         result["message"] = message
         return result
    elif status["d"]: 
         message = "Unable to back up "+target+". The file is a directory" 
         print(message)
         result["message"] = message
         return result
  
    #Make sure that the destination directoyr exists
    status = CommandParser.validateFile( destPath )
    if not status["exists"]:
        if  not createDir:
            message = "Unable to backup to "+destPath+". The directory does not exist and creation is disabled"
            print(message)
            result["message"] = message
            return result
        else:
             result = CommandParser.runCommand("mkdir -p "+ destPath )
             if result["returnCode"]:
                 message = "Failed to create directory "+destPath 
                 print(message)
                 result["message"] = message
                 result["error"] = json.dumps(result, indent=4)
                 return result
             
    #At this point, the full destination directory should exist
    status = CommandParser.validateFile( destPath )
    if not status["exists"]:
        message="Unable to backup to "+destPath+". Directory does not exist and was not created"
        print(message)
        result["message"] = message
        return result
         
    elif not status["d"]:
        message = "Unable to backup to "+destPath+". This is a file, not a directory"
        print(message)
        result["message"] = message
        return result
    elif not status["w"]:
        message = "Unable to backup to "+destPath+". The directory does have write access"
        print(message)
        result["message"] = message
        return result

    #Copy the file
    cmd = "cp "+target+" "+backupFile
    result = CommandParser.runCommand( cmd )
    if result["returnCode"]:
        message = "Unable to backup file "+target+" to "+backupFile
        print(message)
        result["message"] = message
        result["error"] = json.dumps(result, indent=4)
        return False

    #Clear outdated files if needed
    if maxBackupFiles > 0:
        res = clearBackups( target, backupDir = backupDir, maxBackupFiles = maxBackupFiles )

    result["message"] = "Successfully backed up "+target+" to "+ backupFile
    result["backupFile"] = backupFile
    result["success"] = True
    return result

##
# \brief function to limit the number of backup files that are archived
#
def clearBackups( target, backupDir=BAK_DIR, maxBackupFiles = MAX_BAK_FILES ):
    status = {"removed":0, "files":0, "success":False}

    #Convert the target to a path/file
    targetDir, targetFile = os.path.split(target)
    backupDir = backupDir+"/"+targetDir

    #Get a list of files and sort
    fileList = os.listdir( backupDir )
    fileList = sorted(fileList)

    #Find the most recent file matching file
    files = []
    refTs  = 0
    removed = 0
    for item in fileList:
        if targetFile in item:
            entry = {}
            entry["ts"] = float(item.split("_")[-1])
            entry["name"] = backupDir+"/"+item

            #We're not at our limit
            if len(files) < maxBackupFiles:
                files.append(copy.deepcopy(entry))
            #We exceeded our limit and this is newer
            elif entry["ts"] > files[0]["ts"]:
                os.remove(files[0]["name"])
                removed = removed + 1
                files = files[1:]
                files.append(copy.deepcopy(entry))
               
            files = sorted(files, key = lambda i: i["ts"])

    status["removed"] = removed
    status["files"]   = len(files)
    status["success"] = True
    return status
       
               
##
# \brief function to replace the specified file with a backed up version
# \param [in] target the name of the file to restore.
# \param [in] backupDir root directory where backup files are stored
# \param [in] backupFile specific name of a file to restore
# \return dictionary with function completion status
#    {
#        "success": bool            indicates if function succeeded
#        "message": string          message generated during operation
#        "error": dict              structure with command line error info
#    }
#
# This function support two modes of operation. I can replace the target
# specified by target with the file explicitly described with the 
# backupFile variable. The alternative is to restore the most recent file
# that is in the target path using the backupDir as the root path. For example
# if target="/etc/ntp.conf" and backupDir="/var/aqueti/backup", this function
# would copy the most recent ntp.conf backup in /var/aqueti/backup/etc/ntp.conf 
# to /etc/ntp.conf.
#  
# If a backupFile variable is provided, the system will replace the file
# at the target path with the one specified by the backupFile and any 
# backup Dir references will be ignored
#
# This function assumes the file is of the form:
#       destPath+sourceFile+"_"+str(datetime.now().timestamp())
#
def  restoreConf( target, backupDir=BAK_DIR, backupFile = None ):
    result={"success":False}

    #Convert the target to a path/file
    targetDir, targetFile = os.path.split(target)

    #If no backup file, figure out which one to reference
    if backupFile == None:
        #Generate the name for the destination file
        sourcePath, sourceFile = os.path.split(target)
        refPath = backupDir + sourcePath

        #Find the most recent file matching file
        fileList = os.listdir( refPath )
        refTs  = 0
        for item in fileList:
            if targetFile in item:
                ts = float(item.split("_")[-1])
            
                if ts > refTs:
                    refTS = ts
                    backupFile = refPath+"/"+item

        #Make sure we got data
        if backupFile == None:
            message = "No backup files were found for "+target+" in "+refPath
            print(message)
            result["message"] = message
            return result

    #We have a backup file. Do checks and copy
    fileInfo = CommandParser.validateFile( backupFile )
    if not fileInfo["exists"]:
        message = "Unable to restore "+target+", backup file "+backupFile+" does not exit"
        print(message)
        result["message"] = message
        return result

    elif fileInfo["d"]:
        message = "Unable to restore "+target+", backup file "+backupFile+" is directory"
        print(message)
        result["message"] = message
        return result

    elif not fileInfo["r"]:
        message = "Unable to restore "+target+", backup file "+backupFile+" is not readable"
        print(message)
        result["message"] = message
        return result

    #We have a valid backup file.
    #Do checks on target
    fileInfo = CommandParser.validateFile( target )
    if fileInfo["d"]:
        message = "Unable to replace "+target+". Target is a directory"
        print(message)
        result["message"] = message
        return result

    elif not fileInfo["w"]:
        message = "Unable to replace "+target+". Target requires write access"
        print(message)
        result["message"] = message
        return result
         
    #All is good. Time to copy
    cmd = "cp "+backupFile+" "+target
    ret = CommandParser.runCommand( cmd )
    if ret["returnCode"]:
         message = "Unable to restore file "+backupFile+" to "+target
         print(message)
         result["message"] = message
         result["error"] = json.dumps(result, indent=4)
         return False

    #success
    result["backupFile"] = backupFile
    result["message"] = "Successfully restored "+backupFile+" to "+ target
    result["success"] = True

    return result

##
# \brief check the hash of a configuration file
# \return True if the has matches, False if there is a mismatch
#
def checkHash( target ):
    #Make sure the file exists
    ret = CommandParser.validateFile( target )
    if ret["d"] or not ret["r"]:
        print("ERROR: "+target+" is inaccessible. Unable to check hash")
        return False

    #See if it's JSON loadable
    try:
        data = readJson(target)
        oldHash = data["configMetadata"]["hash"]

        #Strip the old hash and recalculate
        del  data["configMetadata"]["hash"]
        
        #calculate new hash and insert
        newHash = hashlib.md5(str(data).encode())
        newHash = str(newHash.hexdigest())
        
        if newHash != oldHash:
            print("Hash mismatch! New: "+str(newHash)+" != "+str(oldHash))
            return False
        else:
            return True
    except:
        pass

    #read the file file into a buffer
    ntpFile = open(target,"r")
    data = ntpFile.read()
    ntpFile.close()

    fileBuffer = ""

    #extract hash line
    meta = 0
    lines = data.splitlines(1)
    fileHash = None
    for line in lines:

        if META_LINE in line:
            meta = meta + 1
            continue

        elif meta > 0 and meta < 2:
            if "# Hash:" in line:
                fileHash = line.split(" ")[-1].rstrip()
            continue

        #If meta > 1, then build the file buffer
        elif meta > 1:
            fileBuffer = fileBuffer + line
         
    hashInfo = hashlib.md5(fileBuffer.encode())
    newHash = hashInfo.hexdigest()

    if newHash != fileHash:
        return False

    return True

##
# \brief writes a python object to a json file
# \return True on success, False on failure
#
def writeJson(data, dest):

    #Make a deep copy to not corrupt local copy with header info
    data = copy.deepcopy(data)

    metadata = {}
    oldHash = None

    #make sure data is an object
    if not isinstance( data, object):
        print("ERROR: writeJson can only write objects")

    #Check if we have an configuratino metadata
    if "configMetadata" in data.keys():
        metadata = data["configMetadata"]
        if not isinstance( metadata, object):
            print("ERROR: configMetadata field is not an object")
            return False

        if not "generator" in metadata.keys():
            print("ERROR: invalid configMetadata information")
            return False

        if not "version" in metadata.keys():
            print("ERROR: invalid configMetadata information")
            return False
 
        if not "date" in metadata.keys():
            print("ERROR: invalid configMetadata information")
            return False

        if not "hash" in metadata.keys():
            print("ERROR: invalid configMetadata information")
            oldHash = metadata["hash"]
            del metadata["hash"]
            return False

    #Generate new metadata fileds
    metadata["generator"] = "FileInterface.py"
    metadata["version"] = VERSION
    metadata["date"] =  str(datetime.now())+"\n"  

    data["configMetadata"] = metadata

    #calculate new hash and insert
    newHash = hashlib.md5(str(data).encode())
    newHash = str(newHash.hexdigest())
    metadata["hash"] = newHash


    with open(dest, 'w') as fp:
        json.dump(data, fp)
    fp.close()

    #Verify data was properly written
    d2 = readJson( dest )

    if d2 != data:
        print("ERROR writing to "+dest+". Unable to validate")
        return False

    return True


    

##
# \brief reads in a JSON file
# \return python object with data on success, False on failure
#
def readJson(filename):
    #Make sure the file exists
    ret = CommandParser.validateFile( filename )
    if ret["d"] or not ret["r"]:
        print("ERROR: "+target+" is inaccessible")
        return False

    #read the file file into a buffer
    try:
        fp = open(filename,"r")
        data = json.load(fp)
        fp.close()
    except:
        return False    

    return data

##
# \brief Verifies that the has for a json file is correct
# \param [in] filename name of the file to check
# return True on success, False on failure
#
def checkJsonHash(filename):
    data = readJson(filename)
    if data == False:
        print("ERROR: Unable to extract Json Data from "+filename)
        return False
    
    try:
        oldHash = data["configMetadata"]["hash"]
    except:
        print("ERROR: Unable to extract hash from "+filename)
        return False

    #Strip the old hash and recalculate
    del  data["configMetadata"]["hash"]
    
    #calculate new hash and insert
    newHash = hashlib.md5(str(data).encode())
    newHash = str(newHash.hexdigest())
    
    if newHash != oldHash:
        print("ERROR: Hash mismatch!")
        return False

    return True

##
# \brief Unit test function for the class
#
# This test works by recursively running a sequence of OS commands. To be successful, the
# unit test needs to be run as root on a system where the ntp configuration can be modified.
def test(verbose = 0):
    #Vareiable to set test results
    testResult = {}
    testResult["description"]       = "FileInterface Unit test"
    testResult["timestamp"]         = str(datetime.now())
    testResult["version"]           = VERSION
    testResult["pass"]              = True
    testResult["test"]              = {}
    testResult["test"]["writeConf"] = "unknown"
    testResult["test"]["readConf"] = "unknown"
    testResult["test"]["writeConf_delim"] = "unknown"
    testResult["test"]["readConf_delim"] = "unknown"
    testResult["test"]["writeYaml"] = "unknown"
    testResult["test"]["readYaml"]  = "unknown"
    testResult["test"]["writeJson"] = "unknown"
    testResult["test"]["readJson"] = "unknown"
    testResult["test"]["checkHash"] = "unknown"

    testDir = "/tmp/FileInterfaceTest"
    backupDir = testDir+"/backup"
    backupFile = None

    #Conventional Test data
    testdata = {
        "version": "0.0.1",
        "data": [
            {
                "comments": [
                    "# This is a test comment"
                ],
            },
            {
                "comments": [
                    "# Tracks clock drift over time"
                ],
                "info": [
                    [
                        "driftfile",
                        "/var/lib/ntp/ntp.drift"
                    ]
                ]
            }
        ]
    }

    #Check on the testDir. If it doesn't exist, create it.
    status = CommandParser.validateFile( testDir )
    if not status["exists"]:
        ret = CommandParser.runCommand( "mkdir -p "+testDir)
        if ret["returnCode"]:
            testResult["test"]["createTestDir"] = "fail"
            testResult["pass"] = False
            return testResult
        
        testResult["test"]["createTestDir"] = "pass"

    #If it exists, but it's not a writeable directory
    elif not status["d"] and not status["w"]:
        print("FAILURE: "+testDir+" exists but is not a writeable directory")
        testResult["test"]["createTestDir"] = "fail"
        testResult["pass"] = False
        return testResult

    #Check on the BackupDir. If it doesn't exist, create it.
    status = CommandParser.validateFile( backupDir )
    if not status["exists"]:
        ret = CommandParser.runCommand( "mkdir -p "+backupDir)
        if ret["returnCode"]:
            testResult["test"]["createBackupDir"] = "fail"
            testResult["pass"] = False
            return testResult

        testResult["test"]["createBackupDir"] = "pass"

    #If it exists, but it's not a writeable directory
    elif not status["d"] and not status["w"]:
        print("FAILURE: "+backupDir+" exists but is not a writeable directory")
        testResult["test"]["createBackupDir"] = "fail"
        testResult["pass"] = False
        return testResult

    #Yaml TestData
    yTestData = {"metadata":["# People tracker","# test application"], "data":{}}
    yTestData["data"]["person"] = {"name":"John Doe", "address":{"street":"1 easy lane","city":"anytown"}}

    timestamp =  str(datetime.now())
    testdata["metadata"] = ["# TestConfig version 12"]

    # Save a JSON object to a file, then read the file back. The data should be
    # the same except for the timestamp. The timestamps should not be off by
    #
    target = testDir+"/test/level1/temp.conf"
    result = writeConf( testdata, target, backupDir = backupDir, createDir = True  )
    if not result["success"]:
        testResult["test"]["writeConf"] = "fail"
        testResult["test"]["info"] = result

    #Otherwise, we have at least one reference file. We read it in to compare
    fileData = readConf( target)

    #Compare timestamp timin
    fdts = datetime.strptime(fileData["timestamp"], '%Y-%m-%d %H:%M:%S.%f')
    dts = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
     
    difference = float(fdts.timestamp() -dts.timestamp())

    fileData.pop("timestamp")
    fileData.pop("fileVersion")

    if difference > 1.0:
        print("File timestamp difference > 1.0 seconds")
        testResult["test"]["writeConf"] = "fail"
        testResult["test"]["readConf"] = "fail"
        testResult["pass"] = False
    if fileData != testdata or difference > 1.0:
        print("DATA:\n"+json.dumps(testdata, indent=4))
        print("FileData:\n"+json.dumps(fileData, indent=4))
        print("Data mismatch")
        testResult["test"]["writeConf"] = "fail"
        testResult["test"]["readConf"] = "fail"
        testResult["pass"] = False
        
    else:
        testResult["test"]["writeConf"] = "pass"
        testResult["test"]["readConf"] = "pass"


    #Write testData with = delim
    target = testDir+"/test/level1/equal.conf"
    result = writeConf( testdata, target, backupDir = backupDir, delim="=", createDir = True )
    if not result["success"]:
        testResult["test"]["writeConf"] = "fail"
        testResult["test"]["info"] = result

    fileData = readConf( target, delim="=")
    if fileData["data"] != testdata["data"]:
        print("test:\n"+json.dumps(testdata, indent=4))
        print("FILE:\n"+json.dumps(fileData, indent=4))
        testResult["test"]["writeConf_delim"] = "fail"
        testResult["test"]["readConf_delim"] = "fail"
        testResult["pass"] = False
    else:
        testResult["test"]["writeConf_delim"] = "pass"
        testResult["test"]["readConf_delim"] = "pass"


    #Backup a file
    result = backupConf(target, backupDir = backupDir,  maxBackupFiles = 100)
    if not result["success"]:
        testResult["test"]["backup"] = "fail"
        testResult["pass"] = False
    else:
        backupFile = result["backupFile"]

    #Compare to ensure direct copies
    ret = CommandParser.runCommand( "cmp "+target+" "+backupFile)
    if ret["returnCode"]:
        testResult["test"]["backup"] = "fail"
        testResult["pass"] = False

    else:
        testResult["test"]["backup"] = "pass"

    #Compare the hash of the target. It should initially pass. 
    ret = checkHash( target )
    if not ret:
        testResult["test"]["checkHash"] = "fail"
        testResult["pass"] = False

    else:
        #Append data to the target, checkHash should file
        modify = False
        try:
            fptr = open(target, "a")
            fptr.write("CHANGE")
            fptr.close()
            modify = True
        except:
            print("Unable to modify "+target)
            testResult["test"]["checkHash"] = "fail"
            testResult["pass"] = False

        if modify:
            ret = checkHash( target )
            if ret:
                print("checkHash return succeess after a file was modified.")
                testResult["test"]["checkHash"] = "fail"
                testResult["pass"] = False
            else:
                testResult["test"]["checkHash"] = "pass"
   
    #Check clear backups
    #Create 25 backup files, but limit number to 20
    for i in range(1,25):
        result = backupConf(target, backupDir = backupDir,  maxBackupFiles = 20)
   
    #reduce the number to 5 (delete 15)
    res = clearBackups( target, backupDir = backupDir, maxBackupFiles = 5 )
    if not res["success"]:
        testResult["test"]["clearBackups"] = "fail"
        testResult["pass"] = False
    elif res["removed"] != 15:
        print("Number of removed files is "+str(res["removed"])+", expected 15")
        testResult["test"]["clearBackups"] = "fail"
        testResult["pass"] = False
    elif res["files"] != 5:
        print("Number of remaining files is "+str(res["files"])+", 5")
        testResult["test"]["clearBackups"] = "fail"
        testResult["pass"] = False
    else:
        testResult["test"]["clearBackups"] = "pass"
        testResult["pass"] = True

    #Restore target
    ret = restoreConf(target, backupDir = backupDir)
    if not ret["success"]:
        testResult["test"]["restoreConf"] = "fail"
        testResult["pass"] = False
    else:
        testResult["test"]["restoreConf"] = "pass"

    #Test Read/write yaml functionality
    target = testDir+"/test/level1/temp.yaml"
    result = writeYaml( yTestData, target )
    if not result:
        print("ERROR: Failed to write file "+target ) 
        testResult["test"]["writeYaml"] = "fail"
        testResult["pass"] = False
    else:
        #Read file data back in
        fileData = readYaml(target)
        if fileData == False:
            print("ERROR: readYaml failed for file: "+target )
            testResult["test"]["readYaml"] = "fail"
            testResult["pass"] = False
        else:
            if fileData["data"] != yTestData["data"] or fileData["metadata"] != yTestData["metadata"]:
                print("Yaml write/read mismatch")
                print("FILEDATA:\n"+json.dumps(fileData, indent=4))
                print("TESTDATA:\n"+json.dumps(yTestData, indent=4))
                exit(1)
                testResult["test"]["writeYaml"] = "fail"
                testResult["test"]["readYaml"] = "fail"
                testResult["pass"] = False
            else:
                testResult["test"]["writeYaml"] = "pass"
                testResult["test"]["readYaml"] = "pass"

    #Test read/write JSON functionality
    jsonData = {"message":"test"}
    target = testDir+"/test/level1/temp.json"
    result = writeJson( jsonData, target)
    if not result:
        print("ERROR: Failed to write file "+target ) 
        testResult["test"]["writeJson"] = "fail"
        testResult["pass"] = False

    else:
        readData = readJson(target)

        header = readData["configMetadata"]
        del readData["configMetadata"]
 
        if readData != jsonData:
            print("JSON: Data mismatch")
            print("READ:"+json.dumps(readData))
            print("REF :"+json.dumps(jsonData))
            testResult["test"]["readJson"] = "fail"
            testResult["test"]["writeJson"] = "fail"
            testResult["pass"] = False
        else:
            testResult["test"]["readJson"] = "pass"
            testResult["test"]["writeJson"] = "pass"

    #Check json hash
    if testResult["test"]["writeJson"] == "pass":
        result = checkHash(target)
        if not result:
            testResult["test"]["checkHash"] = "fail"
            

    

    #Remove test directory
    ret = CommandParser.runCommand( "rm -r "+testDir)
    if ret["returnCode"]:
        print("FAILURE: Unable to remove "+testDir)
        testResult["test"]["removeTestDir"] = "fail"
        testResult["pass"] = False
    else:
        testResult["test"]["removeTestDir"] = "pass"

    return testResult

        
##
# \brief main function
##
if __name__ == "__main__":
    verbose = 0

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

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description="FileInterface version: "+str(VERSION), epilog = epilog)
    parser.add_argument("-outputJson", action="store", dest="outputJson", help="output JSON representation of ntp.conf file")
    parser.add_argument("-version", action="store_const", dest="version", const=True,  help="Runs unit tests for software as a sequence of commands")
    parser.add_argument("-test", action="store_const", dest="test", const=True,  help="Runs unit tests for software as a sequence of commands")

    args = parser.parse_args()

    if args.version:
        print("NTPManager version: "+VERSION)
        exit(1)

    # run the test and exit
    if args.test:
        result = test(verbose)

        if verbose:
            print("Test Result:\n"+json.dumps(result, indent=4))
        if not result["pass"]:
            print("FileInterace failed its unit tests")
        else:
            print("FileInterface passed its unit tests")

        if args.outputJson:
            fp = open(args.outputJson, "w")
            json.dump( result, fp, indent=4)
            fp.close()
        else:
            print(json.dumps(result, indent=4))

        exit()
