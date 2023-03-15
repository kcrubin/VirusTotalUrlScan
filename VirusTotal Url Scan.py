import requests
import json
import csv

### VT endpoint url
vt_url = 'https://www.virustotal.com/vtapi/v2/url/report'
apikey = 'api key'
list_of_urls = []

### Url to be scanned
#scan_url = 'hxxps://poin-kredivo.com/index1.html'

### scanning the list of urls from the csv file
with open('url_list.csv','r') as csvfile:
    reader = csv.reader(csvfile)
    ## which column are the urls in ?
    column_index = 0
    next(reader)
    for row in reader:
        list_of_urls.append(row[0])
        
    #print(list_of_urls[2]) 
 
    
    for url in list_of_urls:
        params = {'apikey': apikey, 'resource': url}
        response = requests.get(vt_url, params=params)
        output_json = response.json()

        # Count the number of talse values in the json out
        true_count = sum(scan['detected'] == True for scan in output_json['scans'].values())
        ## if detected by one or more AVs
        if true_count>0:
            print(url,' is malicious\n')
            print('AV Detection Counts: ',true_count,'\n\n')
        else:
            print(url,' is not malicious or not found in VT database\n\n')

