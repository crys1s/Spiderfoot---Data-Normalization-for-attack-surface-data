import os
import sys
import requests
import pandas as pd
from Wappalyzer import Wappalyzer, WebPage
import subprocess
from builtwith import builtwith
import re
import openpyxl
import json

argument = sys.argv[1]                  #Input CSV file location
if os.path.exists(argument):
    print(argument)
else:
    print ("Sorry! Error in file specified")
    exit()

location = argument

data = pd.read_csv(location)           #Reads the input CSV file

#Type of report
print('Specify the type of report: \n 1)Wappalyzer \n 2)Open TCP Ports \n 3)All')
x= int(input('Report Type: '))
if x>3:
    print("\nWrong Selection\n")
    exit()

#Output File Name
outname=input(str('Enter the output file name: '))

#Filtering of the input CSV file - Drops th unnecessary columns
data.drop('Date Found', inplace=True, axis=1)
data.drop('Internal ID', inplace=True, axis=1)
data.drop('Parent ID', inplace=True, axis=1)
#data.drop('Risky', inplace=True, axis=1)
data.drop('Module', inplace=True, axis=1)
data.drop('Children', inplace=True, axis=1)
data.drop('Correlations', inplace=True, axis=1)
data.drop('Distance', inplace=True, axis=1)
data.drop('Starred', inplace=True, axis=1)
data.drop('Annotation', inplace=True, axis=1)


#Deletes duplicates and Filtering
filtereddata=pd.DataFrame(data, columns=['Type','Data','Source Data'])
filtereddata = data.drop_duplicates(
    subset = ['Type','Source Data'],
    keep = 'last').reset_index(drop = True)
filtereddata.sort_values(by=['Type'], inplace= True)

#Storage to CSV
#filtereddata.to_csv(outname+'.csv',index=False)

#Summary and Grouping of Data
group=filtereddata.groupby(['Type'])
summary=pd.DataFrame(group.size().reset_index(name="Group Count"))

#Types or Categories listed
types = summary['Type'].tolist()

#Web Analysis using Wappalyzer
if x==1 or x==3:
    ip=pd.DataFrame(group.get_group('IP Address').reset_index(drop = True), columns=['Type','Data','Source Data'])
    ip.drop('Type', inplace=True, axis=1)
    weblist=ip['Source Data'].tolist()          #Subdomain list for Wappalyzer
    datalist=ip['Data'].tolist()                #IP list for Wappalyzer

    class Wapp(object):
        def __init__(self):

            # colors
            self.G = '\033[92m'  # Green
            self.R = '\033[91m'  # Red
            self.Y = '\033[93m'  # Yellow

        def wappalyzer(self, target, verbose=False):
            url=target
            print(url)
            wapoutput=""
            try:
                api_key = "enter API Key"
                headers = {
                    "x-api-key": api_key
                    }


            except Exception as e:
                print(self.R + e)
                print('Error analyzing ' + url)


    #test=Wapp()
    print('\n Number of Subdomains to be scanned for tecnologies: '+str(len(weblist)))
    Waplist=[]              #Storage list for Wappalyzer
    BWlist=[]               #Storage list for BuiltWith
    Statuscode=[]           #Status code list for requests made
    RawData=[]              #Storage list for JSON
    Redirect=[]             #Storage list for URL Redirections
    ScannedURL=[]           #Storage list for WAP Scanned URLS
    for i in range (len(weblist)):
        wapoutput=""
        
        print('Scan no: ', str(i))
        url=weblist[i]
        subdomain='http://' + url
        #print('\n' + subdomain)

        try:
            response = requests.get(subdomain, allow_redirects=False, verify=False, timeout=20)
            #print(response.url)
            if response.status_code != 404:
                print("The URL ", subdomain, " was redirected to:", response.headers['location'])
                finalurl=response.headers['location']
                Redirect.append(finalurl)
                print(finalurl)
            
                print("Status Code: ", response.status_code)
                Statuscode.append(str(response.status_code))
        # if the request succeeds 
                #test.wappalyzer(url)
                #Waplist.append(test.wappalyzer(url))
                
                api_key = "YrhEZStCbR5djsbyIyYp8aLXuXWqkQBO6ttGKSdD"
                headers = {
                    "x-api-key": api_key
                    }
                
                scanresponse = requests.get("https://api.wappalyzer.com/v2/lookup/?urls="+finalurl+"&sets=all", headers=headers)
                #print(response.text)

                data = json.loads(scanresponse.text)
                RawData.append(data)
                #print(data)
                for item in data:
                    print("URL:", item['url'])
                    wapurl=str(item.get("url")) +"\n"
                    for tech in item['technologies']:
                        wapoutput+="URL: "+str(item.get("url")) +"\n"
                        #print("Name:", tech.get("name"))
                        wapoutput+="Name:"+str(tech.get("name")) +"\n"
                        #print("Version:", tech.get("versions"))
                        wapoutput+="Version:"+str(tech.get("versions")) +"\n"
                        #print("Categories:", [cat['name'] for cat in tech['categories']])
                        wapoutput+="Categories:"+str([cat['name'] for cat in tech['categories']])+"\n\n"
                        wapoutput=wapoutput.replace("[","").replace("]","")
                        #print(wapoutput)


                #wapoutput=str(test.wappalyzer(url))
                #wapoutput=wapoutput.replace("{","").replace("}","").replace("'","")
                Waplist.append(wapoutput)
                ScannedURL.append(wapurl)
                #bwoutput=str(builtwith(finalurl))
                #bwoutput=bwoutput.replace("{","").replace("}","").replace("'","").replace("[","").replace("]","")
                #BWlist.append(bwoutput)
            
            else:
                print("Status Code: ", response.status_code)
                Statuscode.append(str(response.status_code))
                print('URL not reachable - Error:', response.status_code)
                Waplist.append('URL Unreachable')  
                Redirect.append('URL Unreachable')
                Statuscode.append('URL Unreachable')
                ScannedURL.append('URL Unreachable')
                RawData.append('URL Unreachable')
        except requests.exceptions.ConnectTimeout:
            print('URL not reachable')
            Waplist.append('URL Unreachable - Check Status Code')
            continue
        except TimeoutError:
            print('URL not reachable')
            Waplist.append('URL Unreachable - Check Status Code') 
            continue
        except Exception as e:
            print(e)
            print('Error analyzing ' + url)
            Waplist.append(str(e))
            Redirect.append(str(e))
            Statuscode.append(str(e))
            RawData.append(str(e))
            ScannedURL.append(str(e))
            continue
        #print(Waplist)
        technologies=pd.DataFrame(list(zip(datalist,weblist,Waplist,Redirect,Statuscode,ScannedURL,RawData)), columns=['Data','Source Data','Wappalyzer','Redirect URL','Status Code','Scanned URL','Raw JSON'])
        #technologies.sort_values(by=['Source Data'], inplace= True)
        #print(technologies)
        with pd.ExcelWriter(outname+'.xlsx', mode='w') as writer1:
            summary.to_excel(writer1,sheet_name='Summary',index=False)
            filtereddata.to_excel(writer1,sheet_name='Data',index=False)
            technologies.to_excel(writer1,sheet_name='Wappalyzer',index=False)

#-------------------------------------------------------------------------------------------------------------------------------------------------------------------

#High Risk Open Ports List
HighRiskOpenPortsMaster=['21/','22/','23/','25/','110/','111/','135/','139/','143/','445/','993/','995/','1723/','3306/','3389/','5900/','8080/']
HighRiskOpenPortsDefined=['FTP','SSH','Telnet','SMTP','POP3','RPCBind','MSRPC','NetBIOS-SSN','IMAP','Microsoft-DS','IMAPS','POP3S','PPTP','MySQL','MS-WBT-Server','VNC','HTTP-Proxy']


#IP Nmap Scans
if x==2 or x==3:
    portscan=pd.DataFrame(group.get_group('IP Address').reset_index(drop = True), columns=['Data'])
    portscanfiltered=portscan.drop_duplicates(subset = ['Data'],keep = 'first').reset_index(drop = True)
    iplist=portscanfiltered['Data'].tolist()
    print('\n Number of IPs to be scanned: ' + str(len(iplist)))

    R = '\033[91m'  # red
    G = '\033[92m'  #green

    scanresult=''
    allscans=['']*(len(iplist))
    allscans1=['']*(len(iplist))
    lines=['']*(len(iplist))
    HighRiskResult=['']*(len(iplist))
    Ports=['']*(len(iplist))
    for i in range (len(iplist)):
        try:
            print('Scan no: ', str(i))
            scanip=iplist[i]
            print('Scan IP: ', scanip)
            scanresult = ""
            nmap='nmap -Pn --top-ports 1000 -sV ' + scanip
            process = subprocess.Popen(['nmap','-Pn','--top-ports','1000',scanip],
                                stdout=subprocess.PIPE, 
                                universal_newlines=True)
            while True:
                output = process.stdout.readline()
    #            print(output.strip())   
                scanoutput = output.strip()
                #Results
                scanresult +='\n' 
                scanresult += scanoutput
                # Return Code Check
                return_code = process.poll()
                if return_code is not None:
                    #print('RETURN CODE', return_code)
                    # Process has finished, read rest of the output 
                    for output in process.stdout.readlines():
                        print(output.strip())
                    break
            print(scanresult)
            allscans[i]=scanresult
        except Exception as e:
            print(e)
            print('Error scanning ' + scanip)
            allscans1[i]=e
            continue

     
    #Output Formatting 
    for i in range (len(iplist)):
        HighRisk=''
        scan=''
        Ports[i]=[]
        lines=allscans[i].split('\n')
        for j in range (len(lines)):
            searchline=lines[j]
            #print (searchline)
            r1=re.findall(r'^\d+',searchline)
            if r1 != []:
                Ports[i]=Ports[i]+r1
            r2=re.findall(r'/([a-zA-Z]+(\s+[a-zA-Z]+)+)',searchline)
            if r2 != []:
                scan=scan+searchline+'\n'
        Ports[i]=list(map(int, Ports[i]))
        allscans1[i]=scan
        #print(Ports[i])

        #High Risk Open Ports Detection Logic  
        searchline=str(lines)
        #print (searchline)
        #print('\n')
        for k in range (len(HighRiskOpenPortsMaster)):
            searchtext=str(HighRiskOpenPortsMaster[k])
            if searchtext in searchline:
                HighRisk = HighRisk + '\n' + searchtext + HighRiskOpenPortsDefined[k]
                print(HighRisk)
            HighRiskResult[i] = HighRisk    
        print('Open Ports for scan ' + str(i) + ': ' + HighRiskResult[i]) 
    
    
           
    ports=pd.DataFrame(list(zip(iplist,allscans,allscans1,Ports)), columns=['IP','Nmap Scan Result','Formatted Scan Report','Open Ports'])
    HighRiskOpenPorts=pd.DataFrame(list(zip(iplist,HighRiskResult)), columns=['IP','High Risk Open Ports'])


#Storage to Excel
with pd.ExcelWriter(outname+'.xlsx') as writer1:
    summary.to_excel(writer1,sheet_name='Summary',index=False)
    filtereddata.to_excel(writer1,sheet_name='Data',index=False)
    if x==1 or x==3:
        technologies.to_excel(writer1,sheet_name='Wappalyzer',index=False)
    if x==2 or x==3:
        ports.to_excel(writer1,sheet_name='Nmap Port Scan',index=False)
        HighRiskOpenPorts.to_excel(writer1,sheet_name='High Risk Open Ports',index=False)
#Whois and Other Data types
    for i in range (len(types)):
        head=types[i]
        if head == "Domain Whois":
            headdata=pd.DataFrame(group.get_group(types[i]).reset_index(drop = True), columns=['Type','Data','Source Data'])
            headdata.to_excel(writer1,sheet_name=head,index=False)

