'''
Created on 4 Oct 2012

@author: freakyclown, modified by monkeynut.
Version 0.3
'''
import httplib
import sys

host = sys.argv[1]
conn = httplib.HTTPConnection(host)
dir = sys.argv[2]
conn.request("GET", "/")
response = conn.getresponse()
data = response.read()



headers = {"X-XSS-Protection":['1; mode=block'], 
    "X-Content-Type-Options":['nosniff'],
    "X-Frame-Options":['DENY','SAMEORIGIN'],
    "Cache-Control":['no-store, no-cache','no-cache, no-store'],
    "X-Content-Security-Policy":[None],
    "Content-Security-Policy":[None],
    "WebKit-X-CSP":[None],
    "Strict-Transport-Security":[None],
    "Access-Control-Allow-Origin":[None],
    "Origin":["!=None"]}

def passed(bar):
    print "+PASS --> ", bar
    
def failed(bar):
    print "+FAIL --> ", bar

def info(host):
    print "######### header check v0.2 ########"
    print " HOST --> ", host
    print "####################################"
    
info(host)

for h in headers.keys():
    headval = response.getheader(h)
    if headval in headers[h]:
        passed(h+': '+str(headval))
    else:
        failed(h+': '+str(headval))
