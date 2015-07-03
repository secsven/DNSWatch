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
# sven schlüter @ context information security 2015

# CONFIG
DEBUG=1

# Mail stuff
MAILSERVER="mail.example.com"
FROM="no-reply@example.com"
SUBJA="Someone just knocked on your door (DNS queried)"
SUBJB="Burp just knocked on your door (DNS queried)"

# DOMAIN TO WATCH
TUNNELDOMAIN=".alerttunnel.example.com."

# Initialise logging
logging.basicConfig(filename='/var/log/dnstunnel.log',level=logging.INFO,format='%(asctime)s %(message)s')

# List of registered people
PEOPLES=[]
with open('consultants.csv') as csvfile:
 reader = csv.reader(csvfile, delimiter=',', quoting=csv.QUOTE_NONE)
 for row in reader:
  PEOPLES.append([row[0].lower(),row[1],int(time.time())])

def findConsultant(packet):
 # save the IP as a string
 SRCIP=str(packet.payload.src)
 # save the query domain as a string
 DSTDOMAIN=str(packet.payload.payload.payload.qd.qname).lower()
 if DEBUG > 5:
  logging.info(repr(SRCIP)+" - "+repr(DSTDOMAIN))
 if TUNNELDOMAIN in DSTDOMAIN and not "polling" in DSTDOMAIN:
  # loop through our people
  for PEOPLE in PEOPLES:
   # in case the domainname queried matches a defined record
   if PEOPLE[0] in DSTDOMAIN:
    logging.info("* DNSWatch hit: "+PEOPLE[0]+TUNNELDOMAIN+" and "+DSTDOMAIN+" sending email to: "+PEOPLE[1])
    # send email with the email address that matches to that domain
    if "burp" in DSTDOMAIN:
     MSG="From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n" % (FROM, PEOPLE[1], SUBJB)
     TEXT="DNSWatch: Burp performed an injection which was used to resolve your personal unique domain name (%s). The origin IP is: %s\nYou should check the logs for the token to find the issue" % (DSTDOMAIN, SRCIP)
    else:
     MSG="From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n" % (FROM, PEOPLE[1], SUBJA)
     TEXT="DNSWatch: A system made an attempt to resolve your personal unique domain name (%s). The origin IP is: %s" % (DSTDOMAIN, SRCIP)
    sendmymail(FROM, PEOPLE[1], MSG, TEXT)

def sendmymail(FROM, TO, MSG, TEXT):
 try:
  # start handler
  server = smtplib.SMTP(MAILSERVER)
  # no verify, no use ...
  server.starttls()
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
  time.sleep(0.5)
  try:
   # only sniff for UDP traffic, once a packet is found start the findConsultant function
   res=sniff(filter="udp dst port 53", prn=findConsultant)
  except Exception, e:
   logging.info("Oh nos - sniff")
   logging.info(e)
