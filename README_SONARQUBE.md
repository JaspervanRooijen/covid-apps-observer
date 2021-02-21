# COVID Android Apps Observer - SonarQube Analysis
---------------------------
## How to Install:
1. Install Ivano's project:
```
  git clone https://github.com/iivanoo/covid-apps-observer # Ivano's project (currently without SQ support)
  git clone https://github.com/JaspervanRooijen/covid-apps-observer # Jasper (currently with SQ support)
```
2. Follow the instructions as seen in ./code/README.md
3. Install Java 8
4. Install SonarQube (https://www.sonarqube.org/ (v8.5.1))
5. Install Sonar-scanner (https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/  (v4.5))
6. Add the “sonar-scanner” command to `$PATH`.
7. Install dex2jar (https://github.com/pxb1988/dex2jar)
8. Add dex2jar to the `$PATH` using the following script:
```
#!/bin/bash
/path/to/installation/dex2jar/dex-tools/build/distributions/dex-tools-2.1-SNAPSHOT/d2j-dex2jar.sh -f "$@"
```
9. Install jd-cli (https://github.com/kwart/jd-cli/releases/tag/jd-cmd-1.1.0.Final (v1.1.0))
10. Add jar2java to the `$PATH` using the following script:
```
#!/bin/bash
java -jar path/to/installation/jd-cli-1.1.0.Final-dist/jd-cli.jar "$@"
```
11. Create a directory `/tmp/empty`
