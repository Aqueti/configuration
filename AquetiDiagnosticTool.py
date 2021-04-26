#!/usr/bin/python3
#
# This script provides tools to analyze memory utilization
import argparse
import threading
#import psutil
import logging
import time

VERSION="0.0.1.0"

##
# \brief Class to monitor process status
class ProcessMonitor:

    ##
    # \brief Initialization Function
    # \param [in] verbose how much information to include [0-2]
    # \param [in] logFile file to write to. None will print to screen. 
    #
    def __init__(self, pid, logFile = None, verbose = 1 ):
        self.running = True;
        self.verbose = verbose

        #Given the process name, extract the pid
        
    ##
    # \brief main processing loop
    #
    def mainLoop(self):
        i = 0

        while self.running:
            logging.info("Iter: "+str(i))
            print("Iter: "+str(i))

            time.sleep(1)
            i = i + 1


    def stop(self):
        print("Running: "+self.running)
        self.running = False


# \brief Main function
if __name__ == "__main__":

    epilog = """\
Examples: 
   sudo ./AquetiDiagnosticTools.py
"""

    #Build up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=str("Aqueti Diagnostic Tool "+str(VERSION)), epilog = epilog)


    args = parser.parse_args()

    #Create a monitor class
    processMonitor = ProcessMonitor( 1 )


    #Spawn process monitor thread
    proc = threading.Thread(target=processMonitor.mainLoop())
    proc.start()
    
    time.sleep(10)

    print("Waking up!")

    processMonitor.stop()
    proc.join()


