import requests
import json
import csv

### VT endpoint url
url = 'https://www.virustotal.com/vtapi/v2/url/report'
apikey = '9a778917f9b7db67353ff95ec42d148224109142444c4183575187fb8dfcb3dd'

### Url to be scanned
#scan_url = 'hxxps://poin-kredivo.com/index1.html'
scan_url = 'https://www.google.com'

# ## scanning the list of urls from the csv file
#with open('url_list.csv','r') as csvfile:
#    reader = csv.reader(csvfile)
    #skip the header
#    next(reader)
    ## which column are the urls in ?
    #column_index = 0
    
    
    # for row in reader:
    #     url = row[0]
    #     print(url)
        
params = {'apikey': apikey, 'resource': scan_url}
response = requests.get(url, params=params)
output_json = response.json()
#print(output_json)

# Count the number of talse values in the json out
true_count = sum(scan['detected'] == True for scan in output_json['scans'].values())
## if detected by one or more AVs
if true_count>0:
    print(scan_url,' is malicious\n')
    print('AV Detection Counts: ',true_count)
else:
    print(scan_url,' is not malicious or not found in VT database')