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

class AcunetixToMarkdown:
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
        counter=1
        findings={}
        #Name, ModuleName, Details, Affects, Parameter, AOP_SourceFile, AOP_SourceLine, AOP_Additional, IsFalsePositive, Severity, Type, Impact, Description, DetailedInformation, Recommendation, Request, Response
        reportitems=tree.xpath('//ReportItem')
        fullurl=self.value(tree.xpath('//StartURL//text()'),'host')
        for reportitem in reportitems:
            Name=self.value(reportitem.xpath('./Name//text()'),'N/A')
            ModuleName=self.value(reportitem.xpath('./ModuleName//text()'),'N/A')
            Details=self.value(reportitem.xpath('./Details//text()'),'N/A')
            Affects=self.value(reportitem.xpath('./Affects//text()'),'N/A')
            Parameter=self.value(reportitem.xpath('./Parameter//text()'),'N/A')
            AOP_SourceFile=self.value(reportitem.xpath('./AOP_SourceFile//text()'),'N/A')
            AOP_SourceLine=self.value(reportitem.xpath('./AOP_SourceLine//text()'),'N/A')
            AOP_Additional=self.value(reportitem.xpath('./AOP_Additional//text()'),'N/A')
            IsFalsePositive=self.value(reportitem.xpath('./IsFalsePositive//text()'),'N/A')
            Severity=self.value(reportitem.xpath('./Severity//text()'),'N/A')
            Type=self.value(reportitem.xpath('./Type//text()'),'N/A')
            Impact=self.value(reportitem.xpath('./Impact//text()'),'N/A')
            Description=self.value(reportitem.xpath('./Description//text()'),'N/A')
            DetailedInformation=self.value(reportitem.xpath('./DetailedInformation//text()'),'N/A')
            Recommendation=self.value(reportitem.xpath('./Recommendation//text()'),'N/A')
            Request=self.value(reportitem.xpath('./TechnicalDetails/Request//text()'),'N/A')
            Response=self.value(reportitem.xpath('./TechnicalDetails/Response//text()'),'N/A')
            d={'Name':Name, 'ModuleName':ModuleName, 'Details':Details, 'Affects':Affects, 'Parameter':Parameter, 'AOP_SourceFile':AOP_SourceFile, 'AOP_SourceLine':AOP_SourceLine, 'AOP_Additional':AOP_Additional, 'IsFalsePositive':IsFalsePositive, 'Severity':Severity, 'Type':Type, 'Impact':Impact, 'Description':Description, 'DetailedInformation':DetailedInformation, 'Recommendation':Recommendation, 'Request':Request, 'Response':Response,'findinglist':''}
            if not self.options['merge']:
                dirname=slugify('%s-%s-%s-%04d-acunetix'%(Severity, fullurl, Name, counter))
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
                slug=slugify('%s-%s-acunetix'%(Severity, Name))
                if not findings.get(slug):
                    findings[slug]=[]
                findings[slug].append(d)                            
        for key, values in findings.items():
            findinglist = ''
            for d in values:
                d['Request']=d['Request'].replace('$','$$')
                d['Response']=d['Response'].replace('$','$$')
                d['Details']=d['Details'].replace('$','$$')
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
            #ret=x[0].strip()
            ret="\n".join([html2markdown(y.strip()) for y in x])
        except Exception as e:
            try:
                ret=x.strip()
            except Exception as ee:
                ret=default
        return ret
