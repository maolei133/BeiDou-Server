@echo off
@title BeiDou
chcp 65001

.\jdk-21.0.2\bin\java.exe -Dspring.config.location=application.yml -Dlog4j2.disable.jmx=true -Dcom.sun.management.jmxremote=false -jar BeiDou.jar
pause