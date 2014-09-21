##!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import re
import string
from lxml import etree
try:
    from .util import *
except Exception as e:
    from util import *
import base64

class BurpToMarkdown:
    def __init__(self, options):
        self.options=options
        self.template=string.Template(self.options['template'])
        if self.options['merge']:
            self.template=string.Template(self.options['merge_template'])
            self.merge_findinglist_template=string.Template(self.options['merge_findinglist_template'])

        self.process()

    def process(self):
        if not os.path.exists(self.options['output_dir']):
            os.makedirs(self.options['output_dir'])

        tree = etree.parse(self.options['load_file'])
        issues=tree.xpath('//issues/issue')
        counter=1
        findings={}
        for issue in issues:
            serialNumber=self.value(issue.xpath('./serialNumber//text()'),'N/A')
            btype=self.value(issue.xpath('./type//text()'),'N/A')
            name=self.value(issue.xpath('./name//text()'),'N/A')
            host=self.value(issue.xpath('./host//text()'),'N/A')
            host_ip=self.attrib(issue.xpath('./host'),'ip','N/A')
            path=self.value(issue.xpath('./path//text()'),'N/A')
            location=self.value(issue.xpath('./location//text()'),'N/A')
            severity=self.value(issue.xpath('./severity//text()'),'N/A')
            if severity!='N/A':
                severity=severity.title()
            if severity == 'Information':
                severity = 'Info'
            confidence=self.value(issue.xpath('./confidence//text()'),'N/A')
            issueBackground=self.value(issue.xpath('./issueBackground//text()'),'N/A')
            remediationBackground=self.value(issue.xpath('./remediationBackground//text()'),'N/A')
            issueDetail=self.value(issue.xpath('./issueDetail//text()'),'N/A')
            issueDetailItems=self.blist(issue.xpath('./issueDetailItems//text()'),'')
            remediationDetail=self.value(issue.xpath('./remediationDetail//text()'),'N/A')
            requestresponse_request=self.value(issue.xpath('./requestresponse/request//text()'),'N/A')
            requestresponse_response=self.value(issue.xpath('./requestresponse/response//text()'),'N/A')
            requestresponse_request_method=self.attrib(issue.xpath('./requestresponse/request'),'method','N/A')
            requestresponse_request_base64=self.attrib(issue.xpath('./requestresponse/request'),'base64','N/A')
            requestresponse_response_base64=self.attrib(issue.xpath('./requestresponse/response'),'base64','N/A')
            requestresponse_responseRedirected=self.value(issue.xpath('./requestresponse/responseRedirected//text()'),'N/A')
            dirname=slugify('%s-%04d-%s-%s-burp'%(severity, counter, host, name))
            d={'serialNumber':serialNumber, 'type':btype, 'name':name, 'host':host, 'host_ip':host_ip, 'path':path, 'location': location, 'severity': severity, 'confidence': confidence, 'issueBackground': issueBackground, 'remediationBackground': remediationBackground, 'issueDetail': issueDetail,'remediationBackground_and_Detail':(remediationBackground+'\n\n'+remediationDetail).strip(), 'remediationDetail': remediationDetail, 'requestresponse_request': requestresponse_request, 'requestresponse_response': requestresponse_response, 'requestresponse_responseRedirected': requestresponse_responseRedirected, 'requestresponse_request_method':requestresponse_request_method, 'requestresponse_request_base64':requestresponse_request_base64, 'requestresponse_response_base64': requestresponse_response_base64,'issueDetailItems':issueDetailItems}
            if not self.options['merge']:
                if not os.path.exists(self.options['output_dir']+'/'+dirname):
                    os.makedirs(self.options['output_dir']+'/'+dirname)
                counter+=1
                temp=self.template
                text=temp.substitute(d)
                request=requestresponse_request if requestresponse_request_base64 != 'true' else base64.b64decode(requestresponse_request)
                response=requestresponse_response if requestresponse_response_base64 != 'true' else base64.b64decode(requestresponse_response)
                if self.options['result_overwrite'] or (not os.path.exists(self.options['output_dir']+'/'+dirname+'/document.md')):
                    tmpfile = open(self.options['output_dir']+'/'+dirname+'/document.md', 'w');
                    tmpfile.write(text)
                    tmpfile.close()
            else :
                slug=slugify('%s-%s-burp'%(severity, name))
                if not findings.get(slug):
                    findings[slug]=[]
                findings[slug].append(d)                            
        for key, values in findings.items():
            findinglist = ''
            for d in values:
                d['path']=d['path'].replace('$','$$').replace('\\', "\\\\")
                d['issueDetailItems']=d['issueDetailItems'].replace('$','$$').replace('\\', "\\\\")
                temp=self.merge_findinglist_template
                text=temp.substitute(d)
                findinglist+=text.strip()+"\n\n"
            d['findinglist']=findinglist
            dirname=key
            if not os.path.exists(self.options['output_dir']+'/'+dirname):
                os.makedirs(self.options['output_dir']+'/'+dirname)
            temp=self.template
            text=temp.substitute(d)
            if self.options['result_overwrite'] or (not os.path.exists(self.options['output_dir']+'/'+dirname+'/document.md')):
                tmpfile = open(self.options['output_dir']+'/'+dirname+'/document.md', 'w');
                tmpfile.write(text)
                tmpfile.close()

    def value(self, x, default):
        try:
            ret=html2markdown(x[0].strip())
        except Exception as e:
            try:
                ret=x.strip()
            except Exception as ee:
                ret=default
        return ret


    def attrib(self, x, attr, default):
        try:
            ret=x[0].attrib[attr]
        except Exception as e:
            try:
                ret=x.attrib[attr]
            except Exception as ee:
                ret=default
        return ret

    def blist(self, x, default):
        try:
            ret=("\n".join(filter(None, ([det.strip() for det in x])))).strip()
        except Exception as e:
            ret=default
        return ret
