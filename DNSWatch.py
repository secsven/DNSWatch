#!/usr/bin/env python

from scapy.all import sniff 
import smtplib
import os,sys 
import time
import logging
import csv

# Domain Watch
# Sniffs the wire and waits for a special token requested as a domain record (A) - sends an email to a matching consultant for that record
# run as root

# CONFIG
DEBUG=1
# only allow one request every 5 seconds
DELAY=5

# Mail stuff
MAILSERVER="mail.example.com"
FROM="no-reply@example.com"
SUBJ="Someone just knocked on your door (DNS queried)"

# DOMAIN TO WATCH
TUNNELDOMAIN=".alerttunnel.example.com."

# Initialise logging
logging.basicConfig(filename='/var/log/dnstunnel.log',level=logging.INFO,format='%(asctime)s %(message)s')

# List of registered people
PEOPLES=[]
with open('consultants.csv') as csvfile:
 reader = csv.reader(csvfile, delimiter=',', quoting=csv.QUOTE_NONE)
 for row in reader:
  PEOPLES.append([row[0],row[1],int(time.time())])

def findConsultant(packet):
 # save the IP as a string
 SRCIP=str(packet.payload.src)
 # save the query domain as a string
 DSTDOMAIN=str(packet.payload.payload.payload.qd.qname)
 # get the current time to compare it later with the last time a query was received
 CMPT=int(time.time())
 # loop through our people
 for PEOPLE in PEOPLES:
  # in case the domainname queried matches a defined record
  if PEOPLE[0]+TUNNELDOMAIN in DSTDOMAIN:
   # check if the last time the domain was accessed is > then DELAY
   if int(PEOPLE[2]) < CMPT-DELAY:
    if DEBUG==1:
     logging.info("* DNSWatch hit: "+PEOPLE[0]+TUNNELDOMAIN+" and "+DSTDOMAIN+" sending email to: "+PEOPLE[1])
   # send email with the email address that macthes to that domain
    MSG="From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n" % (FROM, PEOPLE[1], SUBJ)
    TEXT="DNSWatch: A system made an attempt to resolve your personal unique domain name (%s). The origin IP is: %s" % (DSTDOMAIN, SRCIP)
    sendmymail(FROM, PEOPLE[1], MSG, TEXT)
    # update the timestamp
    PEOPLE[2]=int(time.time())

def sendmymail(FROM, TO, MSG, TEXT):
 try:
  # start handler
  server = smtplib.SMTP(MAILSERVER)
  # send email
  failed = server.sendmail(FROM, TO, MSG+TEXT)
  server.quit()
 except Exception, e:
  logging.info("Oh nos - email")
  logging.info(e)

def daemonize():
 """ Become a daemon"""
 if os.fork(): os._exit(0)
 os.setsid()
 sys.stdin  = sys.__stdin__  = open('/dev/null','r')
 sys.stdout = sys.__stdout__ = open('/dev/null','w')
 sys.stdout = sys.__stderr__ = os.dup(sys.stdout.fileno())

if __name__=='__main__':
 if DEBUG!=1:
  daemonize()
 while True:
  time.sleep(10)
  try:
   # only sniff for UDP traffic, once a packet is found start the findConsultant function
   res=sniff(filter="udp dst port 53", prn=findConsultant)
  except Exception, e:
   logging.info("Oh nos - sniff")
   logging.info(e)
