#!/bin/usr/python3

#script loops through given dataset and checks for any red flags 
#that might signify malicious events. Each flag event has a score
#attached to it. A summary report is produced at the end with 
#uid/ip sorted by their total score. A higher score represents 
#a higher chance of being malicious. 



import pandas as pd
import csv,re,datetime
import numpy

#set up file to collect flaged IPs
#score measures the severity
fileName="flag.csv"
with open(fileName,'w') as fileObj:
    csvFile=csv.writer(fileObj)
    csvFile.writerow(["uid","ip","score","flag"])

#get log data
header=['ts','uid','orig_ip','orig_p','resp_ip','resp_p','trans_depth','method','host','uri','referrer','user_agent','rqst_bdy_len','resp_bdy_len','sts_cd','sts_msg','info_code','info_msg','filename','tags','username','blank','prxy_id','orig_fuids','orig_mime_typ','resp_fuids','resp_mime_typ']
colTypes={'ts':numpy.float64,
           'uid': object,
           'orig_ip' : object,
           'orig_p' : numpy.int64,
           'resp_ip' : object,
           'resp_p' : numpy.int64,
           'trans_depth' :numpy.int64,
           'method' : object,
           'host' : object,
           'uri' : object,
           'referrer' : object,
           'user_agent' : object,
           'rqst_bdy_len' : object,
           'resp_bdy_len' : object,
           'sts_cd' : object,
           'sts_msg' : object,
           'info_code' : object,
           'info_msg' : object,
           'filename' : object,
           'tags' : object,
           'username' : object,
           'passwd' : object,
           'prxy_id': object,
           'orig_fuids' : object,
           'orig_mime_typ' : object,
           'resp_fuids' : object,
           'resp_mime_typ' : object}

log=pd.read_csv("http.log",delimiter="\t",names=header,
                dtype=colTypes)

log.index=pd.to_datetime(log['ts'],unit='s')


# 1. flag all uids that runs more than x(say 10) request in 10s (set at 10s and total request > 100 to reduce run time)
# a high number of request in a short time frame might represent some form of automation being used. might signify tools
# like dirbuster etc...

# get all ids with more than 10 requests
cnt=log[["uid","orig_ip",'ts']].groupby(["uid","orig_ip"]).count()
cnt=cnt.loc[cnt["ts"]>100]
#regroup requests in terms of 10s blocks
resample='10s'
threshold=10
with open(fileName,'a+') as fileObj:
    csvWriter=csv.writer(fileObj)
    for index,row in cnt.iterrows():
        max=log["uid"].loc[log["uid"]==index[0]].resample(resample).count().max()
        if max>threshold: 
            csvWriter.writerow([index[0],index[1],10,str(max)+" request in "+resample])    


# 2. flag all uids with unknown HTTP methods - as they may be probing the system
# Assume these are usual methods accepted by the company's server

commonMthds=["HEAD","GET","POST","OPTIONS","TRACE",
             "PUT","DELETE","CONNECT","PROPFIND","RPC_CONNECT"
            ,"SEARCH","DESCRIBE","GNUTELLA","CHECKIN","CHECKOUT"
            ,"COPY","LABEL","PATCH","LOCK","UNLOCK","POLL"
            ,"PROPPATCH","REPORT","X-MS-ENUMATTS","UNSUBSCRIBE","UPDATE"
            ,"SUBSCRIBE","BCOPY","BDELETE","BMOVE","BPROPFIND"
            'BPROPPATCH', 'MERGE', 'MKACTIVITY', 'MKCOL', 'MKWORKSPACE',
            'MOVE', 'NOTIFY', 'ORDERPATCH','BPROPFIND', 'BPROPPATCH', 
            'RPC_IN_DATA', 'RPC_OUT_DATA','UNCHECKOUT','VERSION-CONTROL']

flag=log[["uid","orig_ip","method"]].loc[~log['method'].isin(commonMthds)]
#output to flag CSV
with open(fileName,'a+') as fileObj:
    csvWriter=csv.writer(fileObj)
    for index,row in flag.iterrows():
       csvWriter.writerow([row[0],row[1],10,"unknown HTTP Method:" +row[2]+" was used"])

# 3. flag all uids with red flags in username/prxy_id/uri. words like 'php' or hex char are red flags
# additonal fields can be added to check for red flags
wordList=["decoding","decode","\\\\x","php",
          "select","root"]

toCheck=["username","uri","prxy_id"]


def checkFields(fields):
    flag=log[["uid","orig_ip",fields]].loc[log[fields].str.contains(('|'.join(wordList)),regex=1,flags=re.IGNORECASE)]

    with open(fileName,'a+') as fileObj:
        csvWriter=csv.writer(fileObj)
        for index,row in flag.iterrows():
            csvWriter.writerow([row[0],row[1],10,fields + " contains red flags:" +row[2]+" was used"])

for fields in toCheck:
    checkFields(fields)

#create summary report
flag=pd.read_csv(fileName)
summary=flag.groupby(["uid","ip"]).sum().sort_values("score",ascending=0)
summary.to_csv('summary.csv')
