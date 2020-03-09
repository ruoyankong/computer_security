#!/usr/bin/env python3
import sys
import hashlib

method = "HEAD"
username = "travis6"
realm = "Cheese"
nonce = "XeJvWfSWBQA=3a79c1a441184a3d177cdff0ca0b5fa59c1c5ff2"
uri = "/secret/cheese"
cnonce = "Njc5YzU0ODg0N2UwMzkyZjZlY2M0MmY1NTQ4MWY0NDY="
nc = "00000001"
qop = "auth"
response = "799eeb5b3eb565c33d42b0fbadb52795"
algorithm = "MD5"


#HA2 = hashlib.md5("{}:{}".format(method, uri).encode("utf-8")).hexdigest()
HA2 = hashlib.md5((method + ":" + uri).encode("utf-8")).hexdigest()


def dic_attack(pwd):
    HA1 = hashlib.md5((username + ":" + realm + ":" +
                       pwd).encode("utf-8")).hexdigest()
    predict = hashlib.md5((
        HA1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + HA2).encode("utf-8")).hexdigest()
    return predict == response


with open('/usr/share/dict/words') as test:
    testpwd = test.readline()[:-1]
    while testpwd:
        if dic_attack(testpwd):
            print("Password is {}".format(testpwd))
        testpwd = test.readline()[:-1]
