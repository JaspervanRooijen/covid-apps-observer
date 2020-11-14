import subprocess
import time
import signal
import os
import re

from codetiming import Timer

def sq_analyze(input_path):
    f = open("times", 'a+')
    f.write("Here we go")
    f.close()
    apk_path = os.path.join(input_path, "apks")
    print(apk_path)
    files = os.listdir(apk_path)
    files = [file for file in files if re.match(".*.apk", file)]
    print(files)
    for file in files:
        name = ".".join(file.split(".")[0:-1])

        if name+"dex2jar.jar" not in os.listdir(apk_path):
            apk2jar(apk_path, file)
        else:
            print("Skipped %s -> %s" % (file, name+"dex2jar.jar"))
        if name+"_2java" not in os.listdir(apk_path):
            jar2java(apk_path, name+"dex2jar.jar", name)
        else:
            print("Skipped %s -> %s" % (name+"dex2jar.jar", name+"_2java"))
        if (name+"_2java") in os.listdir(apk_path):
            add_sonar_properties(apk_path, name)
            if not exists_in_sonar(apk_path, name):
                t = Timer()
                t.start()
                result = True
                while result:
                    result = sonar_scan(apk_path, name)
                f = open("thetimestheyareachanging", 'a+')
                f.write("%s\t\t%d\n" % (name, t.stop()))
                f.close()
            else:
                print("\n\n\nTHIS WAS ALREADY SCANNED (%s)" % name)


def apk2jar(path, file):
    print("APK2Jar Processing: " + path+"/"+file)
    subprocess.run("dex2jar -o %s %s" % (os.path.join(path, ".".join(file.split(".")[0:-1])+"dex2jar.jar"), os.path.join(path, file)), shell=True)


def jar2java(path, file, name):
    print("Jar2Java Processing: " + path+"/"+file)
    # print("jar2java %s -od %s" % (os.path.join(path, file), os.path.join(path, name+"_2java")))
    subprocess.run("jar2java %s -od %s" % (os.path.join(path, file), os.path.join(path, name+"_2java")), shell=True)


def add_sonar_properties(path, name):
    with open(os.path.join(path, name+"_2java", "sonar-project.properties"), "w+") as property_file:
        property_file.write("sonar-project.properties\nsonar.projectKey=%s\nsonar.java.binaries=/tmp/empty" % name)
    with open(os.path.join(path, name+"_2java", ".gitignore"), "w+") as git_ign_file:
        git_ign_file.write("")


def sonar_scan(apk_path, name):
    print("IN SONAR SCAN!!\n\n")
    # print(apk_path) ../data/data_nl_custom/apks
    # print(name) # org.who.infoapp___2.1.1
    orig_path = os.getcwd()
    os.chdir("%s" % (os.path.join(apk_path, name+"_2java")))
    p = subprocess.Popen("sonar-scanner > scanner_logs.log", shell=True, preexec_fn=os.setsid, stderr=subprocess.DEVNULL)
    os.chdir(orig_path)
    try:
        print("Checking tail in %s" % (os.path.join(apk_path, name + "_2java", "scanner_logs.log")))
        print("Checking gitignore in %s" % (os.path.join(apk_path, name + "_2java", ".gitignore")))
        while p.poll() is None:
            time.sleep(5)
            lines = subprocess.check_output(
                "tail -3 %s" % (os.path.join(apk_path, name+"_2java", "scanner_logs.log")), shell=True)
            lines = lines.decode("utf-8").split("\n")
            del lines[-1]
            if len(lines) == 3:
                if lines[0] == lines[1] and lines[1] == lines[2]:
                    print("Lines are the same!")
                    print(lines[0])
                    blocking_file = lines[0].partition("current file: ")[2]
                    print("\n\n\n\n\n -----------------\nBLOCKING FILE FOUND!!! + "+blocking_file+"\n--------\n\n\n\n\n\n")
                    with open(os.path.join(apk_path, name+"_2java", ".gitignore"), 'a+') as gitignore:
                        gitignore.write(blocking_file + "\n")
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
            return True
        else:
            print("Process was already finished")
            print("P returncode: " + str(p.returncode))
            return False


from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from bs4 import BeautifulSoup
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By



def exists_in_sonar(apk_path, name):
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


