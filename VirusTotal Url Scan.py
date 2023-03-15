import requests
import json
import csv

### VT endpoint url
url = 'https://www.virustotal.com/vtapi/v2/url/report'
apikey = 'your api key here'

### Url to be scanned
#scan_url = 'hxxps://poin-kredivo.com/index1.html'

### scanning the list of urls from the csv file
with open('url_list.csv','r') as csvfile:
    reader = csv.reader(csvfile)
    ## which column are the urls in ?
    column_index = 0
    
    for url in reader:
        params = {'apikey': apikey, 'resource': url}
        response = requests.get(url, params=params)
        output_json = response.json()

        # Count the number of talse values in the json out
        true_count = sum(scan['detected'] == True for scan in output_json['scans'].values())
        ## if detected by one or more AVs
        if true_count>0:
            print(url,' is malicious\n')
            print('AV Detection Counts: ',true_count)
        else:
            print(url,' is not malicious or not found in VT database')