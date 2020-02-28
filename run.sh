#!/bin/sh

KEY_JAR=$1

for file in *.key; do
    if [ $file != "project.key" ]; then
        echo $file
        java -Xms4g -Xmx12g -jar ${KEY_JAR} --auto ${file}
    fi
done
