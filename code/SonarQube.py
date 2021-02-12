import subprocess
import time
import signal
import os
import re

from codetiming import Timer

# Main sonarqube method
def sq_analyze(input_path):
    # We keep track of the time it takes to analyse the different projects in a separate "times" file
    f = open("times", 'a+')
    f.close()
    apk_path = os.path.join(input_path, "apks")
    print(apk_path)
    # We find all relevant apk files
    files = os.listdir(apk_path)
    files = [file for file in files if re.match(".*.apk", file)]
    for file in files:
        # We find the name of a project without the extension to proceed
        name = ".".join(file.split(".")[0:-1])
        # If we have not decompiled the apk to a jar file, we do this now
        if name+"dex2jar.jar" not in os.listdir(apk_path):
            try:
                apk2jar(apk_path, file)
            except:
                pass
        else:
            print("Skipped %s -> %s" % (file, name+"dex2jar.jar"))
        # If we have not decompiled the jar file to java files we do this now
        if name+"_2java" not in os.listdir(apk_path):
            try:
                jar2java(apk_path, name+"dex2jar.jar", name)
            except:
                pass
        else:
            print("Skipped %s -> %s" % (name+"dex2jar.jar", name+"_2java"))
        # We add the sonarqube properties file if necessary and analyse the project,
        # unless there exists a .skip file in the source folder of the project
        if (name+"_2java") in os.listdir(apk_path):
            add_sonar_properties(apk_path, name)
            if not exists_in_sonar(apk_path, name) and not ".skip" in os.listdir(os.path.join(apk_path, name+"_2java")):
                t = Timer()
                t.start()
                result = True
                while result:
                    result = sonar_scan(apk_path, name)
                # We write the time it took analysing the project in the times file
                f = open("times", 'a+')
                f.write("%s\t\t%d\n" % (name, t.stop()))
                f.close()
                f = open(os.path.join(apk_path, name+"_2java", ".skip"), "x")
                f.close()
            else:
                print("\n\n\nTHIS WAS ALREADY SCANNED (%s)" % name)


# Decompile from apk to a jar file. dex2jar should be part of the PATH variable
def apk2jar(path, file):
    print("APK2Jar Processing: " + path+"/"+file)
    subprocess.run("dex2jar -o %s %s" % (os.path.join(path, ".".join(file.split(".")[0:-1])+"dex2jar.jar"), os.path.join(path, file)), shell=True)


# Decompile from jar to java files. jar2java should be part of the PATH variable
def jar2java(path, file, name):
    print("Jar2Java Processing: " + path+"/"+file + "\n")
    # print("jar2java %s -od %s" % (os.path.join(path, file), os.path.join(path, name+"_2java")))
    delay = 12*2
    # Sometimes the process does not terminate properly. We will wait for a delay and kill the process if necessary.
    # It seems sometimes projects are correctly decompiled despite jar2java not terminating,
    # other times projects will not decompile at all.
    try:
        r = subprocess.Popen("jar2java %s -od %s" % (os.path.join(path, file), os.path.join(path, name+"_2java")), shell=True, preexec_fn=os.setsid)
        print("Process opened")
        while r.poll() is None and delay >= 0:
            time.sleep(5)
            delay -= 1
            print("Waiting for poll or delay")
    finally:
        if r.poll() is None:
            os.killpg(os.getpgid(r.pid), signal.SIGTERM)
            r.wait()


# Method to add the SonarQube properties file to the source folder.
def add_sonar_properties(path, name):
    with open(os.path.join(path, name+"_2java", "sonar-project.properties"), "w+") as property_file:
        property_file.write("sonar-project.properties\nsonar.projectKey=%s\nsonar.java.binaries=/tmp/empty" % name)
    with open(os.path.join(path, name+"_2java", ".gitignore"), "w+") as git_ign_file:
        git_ign_file.write("")


# Method performing the actual SonarQube scan. sonar-scanner should be in the PATH variable
def sonar_scan(apk_path, name):
    should_continue = True
    print("IN SONAR SCAN!!\n\n")
    orig_path = os.getcwd()
    # Move process to the correct source folder
    os.chdir("%s" % (os.path.join(apk_path, name+"_2java")))
    # Start the sonar-scanner
    p = subprocess.Popen("sonar-scanner > scanner_logs.log", shell=True, preexec_fn=os.setsid, stderr=subprocess.DEVNULL)
    # Move process back to the original folder
    os.chdir(orig_path)
    try:
        # In the sonar-scanner loop we are continually checking for 'hanging' files. Analysis does not terminate for
        # these files. When these files are detected, they are moved to the .gitignore file and analysis resets.
        print("Checking tail in %s" % (os.path.join(apk_path, name + "_2java", "scanner_logs.log")))
        print("Checking gitignore in %s" % (os.path.join(apk_path, name + "_2java", ".gitignore")))
        while p.poll() is None:
            time.sleep(5)
            # Check sonar-scanner output
            lines = subprocess.check_output(
                "tail -3 %s" % (os.path.join(apk_path, name+"_2java", "scanner_logs.log")), shell=True)
            lines = lines.decode("utf-8").split("\n")
            del lines[-1]
            # Check whether the amount of lines is 3. If this is not the case, the analysis has not started up fully.
            if len(lines) == 3:
                # If the last three lines of sonar-scanner are the same, we might have detected a 'hanging' file
                if lines[0] == lines[1] and lines[1] == lines[2]:
                    print("Lines are the same!")
                    print(lines[0])
                    # Account for random sonar-scanner INFO and ERROR messages, not concerning a particular file
                    if len(lines[2].partition("current file: ")) == 3:
                        blocking_file = lines[0].partition("current file: ")[2]
                    else:
                        print("\n False alarm on blocking file! \n")
                        continue
                    print("\n\n\n\n\n-----------------\nBLOCKING FILE FOUND!!! + "+str(blocking_file)+"\n--------\n\n\n\n\n\n")
                    print("BLOCKING FILE: " + str(blocking_file)+ " " + str(type(blocking_file)))
                    # Add the blocking file to the .gitignore file
                    with open(os.path.join(apk_path, name+"_2java", ".gitignore"), 'a+') as gitignore:
                        gitignore.write(blocking_file + "\n")
                        if str(blocking_file) == "":
                            print("Blocking file == \"\"")
                            should_continue = False
                            return
                        else:
                            print("Returning true due to blocking file...")
                            # Returning true so the process is restarting in the sq_analyse(...)-loop
                            return True
                else:
                    print("Last lines are not the same!")
                    if re.match("INFO: [0-9]+/[0-9]+.*", lines[2]):
                        progress = lines[2].partition(", current_file")[0]
                        print(progress)
                    else:
                        print("No INFO lines yet")
            else:
                print("Len lines is not 3!")
                print(lines)
    finally:
        print("in finally clause")
        if p.poll() is None:
            print("Killing")
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            p.wait()
            # Account for "" blocking file
            if not should_continue:
                return False
            # If process was killed we should restart
            return True
        else:
            # If process terminated we do not have to restart
            print("Process was already finished")
            print("P returncode: " + str(p.returncode))
            return False


"""
# Code that might be useful in future:
# We work with a .skip file to see which projects should be analysed now.
# It should also be possible to strip the SonarQube web page and check whether versions have been analysed already.
# This was a first approach at that and it does work for some projects, but is very dependent on SonarQube loading
# times. Therefore it was abandoned and replaced with the .skip method.

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from bs4 import BeautifulSoup
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By



def exists_in_sonar(apk_path, name):
    return False
    options = Options()
    #    options.headless = True
    driver = webdriver.Firefox(options=options)
    driver.implicitly_wait(30)
    print("Driver is looking at: " + "http://localhost:9000/dashboard?id=%s" % name)
    driver.get("http://localhost:9000/dashboard?id=%s" % name)
    WebDriverWait(driver, 50).until(
        EC.invisibility_of_element_located((By.CLASS_NAME, 'global-loading'))
    )
    soup = BeautifulSoup(driver.page_source, parser="html.parser")
    print("SOUP FOUND: " + str(soup.find_all("h2", text="The requested project does not exist.")))
    findings = soup.find_all("h2", text="The requested project does not exist.")
    driver.quit()
    return len(findings) == 0
"""


