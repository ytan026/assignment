#!/usr/bin/python3

import io, requests,sys ,re,csv
try:
    #to check slate3k, if not install
    from slate3k import PDF
    from ipwhois.net import Net
    from ipwhois.asn import IPASN

except:
    print("please download slate3k and ipwhois")

url= "https://www.welivesecurity.com/wp-content/uploads/2017/06/Win32_Industroyer.pdf"


def getPdf(url):
    #get URL file
    try:
        resp=requests.get(url)
    except:
        print("Error requesting file")
        sys.exit(1)
    if resp.status_code!=200:
        print("Error requsting file: " + str(resp.status_code) + " error")
        sys.exit(1)
    
    buf=io.BytesIO(resp.content)
    txt=PDF(buf)
    #output pdf as string
    return str(txt) 
    
txt=getPdf(url) #request and parse pdf file as str

#search for IP
pattern = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+[.|\[|\]]+[0-9]+')
ip_matches = pattern.finditer(txt)
ip_list = [re.sub('[\[\]]','',match.group(0)) for match in ip_matches] #cant find any refrence to the use of [] in ip. going to remove it for ASN lookup
    
#search for hash (40 char long, upper case)
pattern = re.compile(r'[A-Z0-9]{40}')
matches=pattern.finditer(txt)
hash_list = [match.group(0) for match in matches]
  
#search for URLs
pattern = re.compile(r'[Hh]ttps?://(www\.)?(\w+)(\.\w+)') #semes to have no URLS IOCs in the report. But a search for URL lookup will be roughly like this
matches=pattern.finditer(txt)
url_list=[match.group(0) for match in matches]
print("URLs:")
if url_list==[] :
    print("no URLs Found")
else:
    for url in url_list:
        print(url)

for match in matches:
    print(match.group(0))
print("IP:")
for ip in ip_list:
    print(ip)
print("\nHashes:")
for hash in hash_list:
    print(hash)

def ASN_look_up(ip): #returns IP, ASN and Country
    net=Net(ip)  
    obj=IPASN(net)
    results=obj.lookup()
    return [ip,results['asn'],results['asn_country_code']]
  
ASN_list=[ASN_look_up(ip) for ip in ip_list]


return_path = "ASN.csv"

with open(return_path,'w') as file:
    writeFile=csv.writer(file)
    writeFile.writerow(["IP","ASN","Country"])
    for a in ASN_list:
        writeFile.writerow(a)