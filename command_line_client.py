#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jun  2 19:08:17 2022

@author: antonzubchenko
"""


import requests
import time
import csv
import redis
import pandas
import numpy as np
from csv import reader
import os
from flask import Flask, render_template, redirect
from datetime import datetime
from datetime import timedelta

def prepare_report(filepath):

    apikey = 'c3b03e7e6f95c7aa74a501a0abdc00c2ea415e41ef9ba11e2fb410b22a2c7347' # define apikey
    
    apikeys = ['c3b03e7e6f95c7aa74a501a0abdc00c2ea415e41ef9ba11e2fb410b22a2c7347',# define reserve apikeys
               'a62124d4b023edcdc7f055a8b98b39510da74bd20b4280c28a4cbf2d9d674838',
               '57a6cd1aee8dd5287829bca01b1b73f49d4f1c3ad4f7a303a303abb152caec89', 
               'eed74cb84944d2508e3c30d2168eba06bbb8f322cb07402e30cf33cbe1bc9e3d']
    keys_length = len(apikeys)
    
    url = 'https://www.virustotal.com/vtapi/v2/file/report'                    
                                                                                

    # Define Redis server connection points
    redis_host = "redis"                                                        # use "localhost" if running inside python IDE
    redis_port = 6379
    redis_password = ""
    r = redis.StrictRedis(host=redis_host, port=redis_port, password=redis_password, decode_responses=True)
    
    
    
    hashes = ""                                                                 # accumulates hashes that will get queried in the same request
    
    response_entries = []                                                       # accumulate formatted responses
    with open(filepath) as fp:                                                  # open provided file
        line = fp.readline()                                                    # read the first line
        i = 0
        while line:                                                             # execute until the file is completely read 
            if i < 3:                                                           # Either find the value in cache or append to the string that 
                                                                                # will be used for quering (up to 4 caches)
                
                check_key = r.get(line[:-1])                                    # check if this hash value has been cached 
                                                                                # in Redis (key: hash value, value: formatted response as a string)
                redis_val = check_key.split(",") if check_key != None else None # if key is in Redis, split value into list of strings
                
                if check_key == None:                                           # if key is not cached, add hash from file into string of hashes 
                    
                    hashes = hashes + ", " + line[:-1] if hashes != "" else line[:-1]
                    i = i + 1
                elif redis_val[3] != "":                                        # if key in cache, check the timestamp of scan, add hash from file 
                                                                                # into string of hashes if the scan is older than 1 day
                                                                                # otherwise push cached value into the list of responses
                    date_time_str = redis_val[3]
                    date_time_obj = datetime.strptime(date_time_str, "%Y-%m-%d %H:%M:%S")
                    past = datetime.now() - timedelta(days=1)
                    if past < date_time_obj: 
                        response = [redis_val[0], redis_val[1], redis_val[2], redis_val[3]]
                        response_entries.append(response)
                    else:
                        hashes = hashes + ", " + line[:-1] if hashes != "" else line[:-1]
                        i = i + 1
                        
                else:                                                           #  if there is a cached value, but no scan date, we have to check the server again 
                    hashes = hashes + ", " + line[:-1] if hashes != "" else line[:-1]
                    i = i + 1
                
                line = fp.readline()
                
    
            else:                                                               # once the hashes string consists of 4 hashes we can query and analyze the response   
                params = {'apikey': apikey, 'resource': hashes}
                    
                response_scans = requests.get(url, params=params)               # send a request                               
                k = 1
                while (response_scans.status_code == 204 and k < keys_length):  # if the response is empty, it's due to reaching the api's limit 
                    apikey = apikeys[k]                                         # change the apikey and try requesting again
                    params = {'apikey': apikey, 'resource': hashes}         
                    response_scans = requests.get(url, params=params)
                    if response_scans.status_code == 200:                       # if the request was successful keep that key for future queries
                        break
                    k = k + 1                                                   
                if k == keys_length:                                            # if we ran out of keys - no options left: we have to wait until tomorrow
                    return 0
                    
                response_scans_json = response_scans.json()                     # extract response as a json
                
                
                for entry in response_scans_json:                               # there are going to be 4 scans so we need to go over them one by one
                  
                    if entry['response_code'] == 1:                             # if Virus Total has info on a particular hash -> construct a response according
                                                                                # to the following schema: hash_value| Fortinet detection name | Number of engines detected | Scan Date |
                        hash_value = entry['resource']
                        fortinet_detection_name = entry['scans']['Fortinet']['result']
                        engines_detected = entry['positives']
                        scan_date = entry['scan_date']
                        response = [hash_value, fortinet_detection_name, engines_detected, scan_date] 
                        response_entries.append(response)
                        
                        
                    elif entry['response_code'] == 0:                           # handles the case when Virus Total has no information on the hash 
                        hash_value = entry['resource']
                        response = [hash_value, None, None, None]
                        response_entries.append(response)
    
                
                i = 0                                                           # reset values and time out for 16 seconds
                hashes = ""
                time.sleep(16)
                
    if i < 4 and i > 0:                                                         # if there are hashes left to query after finishing the file reading
    
                
                params = {'apikey': apikey, 'resource': hashes}
                    
                response_scans = requests.get(url, params=params)
                keys_length = len(apikeys)
                k = 1
                while (response_scans.status_code == 204 and k < keys_length):
                    apikey = apikeys[k]
                    
                    params = {'apikey': apikey, 'resource': hashes}
                    response_scans = requests.get(url, params=params)
                    if response_scans.status_code == 200:
                        break
                    
                    k = k + 1
                if k == keys_length:
                    return 0
                

                response_scans_json = response_scans.json()
                
                
                if i == 1:                                                      # if only one hash - the response is a string
                    entry = response_scans_json
                    print(entry)
                    if entry['response_code'] == 1:
                        hash_value = entry['resource']
                        fortinet_detection_name = entry['scans']['Fortinet']['result']
                        engines_detected = entry['positives']
                        scan_date = entry['scan_date']
                        response = [hash_value, fortinet_detection_name, engines_detected, scan_date]
                        response_entries.append(response)
                        
                    elif entry['response_code'] == 0: 
                        hash_value = entry['resource']
                        response = [hash_value, None, None, None] 
                        response_entries.append(response)
                
    
                else:                                                           # if more than one hash - the response is a list
                    
                    for entry in response_scans_json:
                      
                        if entry['response_code'] == 1:
                            hash_value = entry['resource']
                            fortinet_detection_name = entry['scans']['Fortinet']['result']
                            engines_detected = entry['positives']
                            scan_date = entry['scan_date']
                            response = [hash_value, fortinet_detection_name, engines_detected, scan_date] #sounds hashable to me
                            response_entries.append(response)
    
                        elif entry['response_code'] == 0: 
                            hash_value = entry['resource']
                            response = [hash_value, None, None, None] #sounds hashable to me
                            response_entries.append(response)
                            
    
        
    
    with open("out.csv", "w", newline="") as f:                                 # Write a csv file with the results
        headerList = ["hash_value (MD5 or Sha256)"," Fortinet detection name","Number of engines detected"," Scan Date "]
        writer = csv.writer(f)
        writer.writerow(headerList)
        writer.writerows(response_entries)
    
                                                                                # Populate Redis cache with the results from csv rows (that are list of strings)
    
    try:
        r = redis.StrictRedis(host=redis_host, port=redis_port, password=redis_password, decode_responses=True)

        with open('out.csv', 'r') as read_obj:
            csv_reader = reader(read_obj)
            
            for row in csv_reader:
                joined_string = ",".join(row)
                key = row[0]
                r.set(key, joined_string)
                
            
     
       
    except Exception as e:
        print(e)
    
                                                                                # Read the created csv file. Format it, and output an HTML table
    file = pandas.read_csv("out.csv")   
    file["Number of engines detected"] = file["Number of engines detected"].astype('Int64')
    file = file.replace({np.nan:None})
    
    head, tail = os.path.split(filepath)
    
    filepath = tail[0:-4]
    file.to_html("templates/" + filepath +"_out_Table.html")
    
    
    return 1
    
     
           

