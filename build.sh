#!/bin/bash

javac -g -target 1.4 -source 1.4 -cp /usr/local/java_card_kit-2_2_2/lib/api.jar:/usr/local/java_card_kit-2_2_2/lib/gp211.jar -d out/production/gpg_card/ java/net/ss3t/javacard/gpg/Gpg.java
