import os
import sys
import requests
import hashlib
import json



def computeMD5hash(my_string):
    m = hashlib.md5()
    m.update(my_string.encode('utf-8'))
    return m.hexdigest()
    
def make_query(hostname):
     '''
     const site_hash = md5(hostname)

     const partial_hash = site_hash.slice(0, 5)
  
     const full_url = 'https://api.punkspider.io/api/partial-hash/' + partial_hash
     '''
  
     site_hash = hostname
     site_hash = computeMD5hash(site_hash)
     partial_hash = site_hash[0:5]
     full_url = 'https://api.punkspider.io/api/partial-hash/' + partial_hash
     return full_url,partial_hash,site_hash
     
     
def check_vulns(keys):
    flagged = []
    for i,v in keys.items():
        if int(v) > 0:
           flaggy = {}
           flaggy['Vuln_Type'] = i
           flaggy['Vuln_count'] = v
           print("VALID VULNS LOCATED FOR PARTIAL HASH MATCH!!!!!!!!!!!!!")
           flagged.append(flaggy)
    
    if flagged:
       return True,flagged
    

def submit_target(hostname):
    #this.post_data('http://api.punkspider.org/api/scans/schedule', this.current_url)
    json_arg = {hostname: hostname}    
    response = requests.post('http://api.punkspider.org/api/scans/schedule',json=json_arg)
    
    
def deduce_vulns(hostname):
    full_url,partial_hash,full_hash = make_query(hostname)
    if full_url:
       print("Encoding Successful making web request")
       try:
          response = requests.get(full_url,timeout=3,verify=False)
          if response:
             json_data = json.loads(response.text) 
             print(json_data)
             for key,value in json_data.items():
                 
                 partial = key[0:5]
                 if partial_hash == partial:
                    print("partial_hash_match {}".format(full_hash))
                    try:
                       truth_seeker,flagged = check_vulns(value['vulns'])
                       
                       if truth_seeker:
                          print(value['vulns'].values())
                          flagged_match = {}
                          
                          flagged_match['full_url'] = full_url
                          flagged_match['hostname'] = hostname
                          flagged_match['rating'] = value['rating']
                          flagged_match['partial_match'] = partial_hash
                          flagged_match['full_hash'] = full_hash
                          flagged_match['host_hash'] = key
                          flagged_match['flagged'] = flagged
                          flagged_match['scanned_date'] = value['scannedDate']
                         
                          if full_hash == key:
                             flagged_match['Host_Is_Vuln'] = True
                             
                          if flagged_match:
                             return flagged_match
                       
                    except Exception as ex6:
                       #print(ex6)
                       pass
       except Exception as ex2:
         #print(ex2)
         pass
'''         
hostnames = sys.argv[1]
lineList = [line.rstrip('\n') for line in open(hostnames)]
for hosts in lineList:
    try:
        deduce_vulns(hosts)
    except Exception as ex3:
      #print(ex3)
       pass
'''

rootdir = sys.argv[1]
results = []
results_total = 0

for subdir, dirs, files in os.walk(rootdir):

    for file_info in files:
        
        print(os.path.join(subdir, file_info))

        temp_file = os.path.join(subdir, file_info)
 
        try:
            lineList = [line.rstrip('\n') for line in open(temp_file)]
            for hosts in lineList:
                try:
                    results = deduce_vulns(hosts)
                    if results:
                       print(results)
                       with open('data.json', 'a') as f:
                         json.dump(results, f, indent=4)
                except Exception as ex3:
                  #print(ex3)
                  pass
           
        except:
            pass

                  
