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

class NessusToMarkdown:
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
        reporthosts=tree.xpath("//ReportHost")
        counter=1
        findings={}
        for reporthost in reporthosts:
            name=reporthost.get('name')
            reportitems=reporthost.xpath('.//ReportItem')
            for reportitem in reportitems:
                if reportitem.get('port'):
                    port=reportitem.get('port', 'N/A')
                    svc_name=reportitem.get('svc_name', 'N/A')
                    protocol=reportitem.get('protocol', 'N/A')
                    pluginName=reportitem.get('pluginName', 'N/A')
                    pluginFamily=reportitem.get('pluginFamily', 'N/A')
                    solution=self.value(reportitem.xpath('./solution//text()'),'N/A')
                    risk_factor=self.value(reportitem.xpath('./risk_factor//text()'),'N/A')
                    cvss_base_score=self.value(reportitem.xpath('./cvss_base_score//text()'),'N/A')
                    cvss_vector=self.value(reportitem.xpath('./cvss_vector//text()'),'N/A')
                    if risk_factor!='N/A':
                        risk_factor=risk_factor.title()
                    if risk_factor=='None':
                        risk_factor='Info'
                    description=self.value(reportitem.xpath('./description//text()'),'N/A')
                    plugin_output=self.value(reportitem.xpath('./plugin_output//text()'),'N/A')
                    if pluginFamily != 'Settings' and pluginName != '':
                        d={'name':name, 'port':port, 'svc_name':svc_name, 'protocol':protocol, 'pluginName':pluginName, 'pluginFamily':pluginFamily, 'solution': solution, 'risk_factor': risk_factor, 'description': description, 'plugin_output': plugin_output, 'findinglist':'', 'cvss_base_score':cvss_base_score, 'cvss_vector':cvss_vector}
                        if not self.options['merge']:
                            dirname=slugify('%s-%s-%s-%04d-nessus'%(risk_factor, pluginName, name, counter))
                            if not os.path.exists(self.options['output_dir']+'/'+dirname):
                                os.makedirs(self.options['output_dir']+'/'+dirname)
                            counter+=1
                            temp=self.template
                            text=temp.substitute(d)
                            if self.options['result_overwrite'] or (not os.path.exists(self.options['output_dir']+'/'+dirname+'/document.md')):
                                tmpfile = open(self.options['output_dir']+'/'+dirname+'/document.md', 'w');
                                tmpfile.write(text)
                                tmpfile.close()
                        else :
                            slug=slugify('%s-%s-nessus'%(risk_factor, pluginName))
                            if not findings.get(slug):
                                findings[slug]=[]
                            findings[slug].append(d)                            
        for key, values in findings.items():
            findinglist = ''
            for d in values:
                d['plugin_output']=d['plugin_output'].replace('$','$$')
                d['description']=d['description'].replace('$','$$')
                temp=self.merge_findinglist_template
                text=temp.substitute(d)
                findinglist+=text+"\n\n"
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
            ret=html2markdown(x[0].strip(), True)
        except Exception as e:
            try:
                ret=x.strip()
            except Exception as ee:
                ret=default
        return ret
