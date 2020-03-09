import hashlib
import pandas as pd
import string
charset = [chr(i) for i in range(256)]
mac = pd.read_csv("./output.csv")

key = ""
for i in range (19, -1, -1):
    for c in charset:
        tmp = mac.ix[i, "raw_text"]
        if i == 0:
            tmp = ""
        text = hashlib.sha1((tmp+key+c).encode("utf-8")).hexdigest()
        if text == mac.ix[i, "encode_text"]:
            key += c
            break
print(key)