##!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import re
import string
from io import StringIO
from lxml import etree

try:
    from .util import *
except Exception as e:
    from util import *

class NetsparkerToMarkdown:
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
        filelist=[]
        if os.path.isfile(self.options['load_file']):
            filelist.append(self.options['load_file'])
        elif os.path.isdir(self.options['load_file']):
            for name in os.listdir(self.options["load_file"]):
                if os.path.isfile(self.options['load_file']+'/'+name) and len(name)>11 and name[-11:]==".netsparker":
                    filelist.append(self.options["load_file"]+'/'+name)
        counter=1
        findings={}
        for processfile in filelist:
            content=open(processfile).read()
            fileparts=content.split('<!-- Vulnerability Details -->')
            vulns=fileparts[1].split('<h1')
            fullparser=etree.HTMLParser()
            fullhtml=etree.parse(StringIO(content), fullparser)
            Target=self.attrib(fullhtml.xpath("//span[@class='dashboard-url']/a"),'href','N/A')
            for vuln in vulns[1:]:
                vuln='<h1'+vuln
                parser=etree.HTMLParser()
                vulnobj=etree.parse(StringIO(vuln), parser)
                h1=self.value(vulnobj.xpath('//h1//text()'),'N/A')
                Vulnerability=re.sub(r'\d+\\\. ','',h1)
                Risk=self.value(vulnobj.xpath("//div[@class='vuln-block']/div[2]//text()"),'N/A').title()
                VulnDesc=self.value(vulnobj.xpath("//div[@class='vulndesc']//text()"),'N/A')
                if Risk=='Information':
                    Risk='Info'
                if Risk=='Important':
                    Risk='High'
                VulnDetails=vulnobj.xpath("//div[@class='vulnerability-detail']")
                for VulnDetail in VulnDetails:
                    h2=self.value(VulnDetail.xpath('./div/h2//text()'),'N/A')
                    SubVulnerability=re.sub(r'\d+\.\d+\. ','',h2)
                    Link=self.attrib(VulnDetail.xpath('./div/div[2]/a'),'href','N/A')
                    ParamTableRows=VulnDetail.xpath('./div/table//tr')
                    lines=0;
                    ParamTable=''
                    for ParamTableRow in ParamTableRows:
                        ParamTableCells=ParamTableRow.xpath('./td')
                        cells=0
                        for ParamTableCell in ParamTableCells:
                            cell=self.value(ParamTableCell.xpath('.//text()'),'N/A').strip()
                            ParamTable+='| %s '%cell
                            cells+=1
                        ParamTable='%s|\n'%ParamTable
                        if lines==0:
                            sepstr=''
                            for i in range(0,cells):
                                sepstr+='| ------- '
                            sepstr='%s|\n'%sepstr
                            ParamTable+=sepstr
                        lines+=1
                    d={'Target':Target, 'Vulnerability':Vulnerability, 'Risk':Risk, 'VulnDesc':VulnDesc, 'SubVulnerability':SubVulnerability, 'Link':Link, 'ParamTable':ParamTable,'findinglist':''}
                    if not self.options['merge']:
                        dirname=slugify('%s-%s-%s-%04d-netsparker'%(Risk, Target, Vulnerability, counter))
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
                        slug=slugify('%s-%s-netsparker'%(Risk, Vulnerability))
                        if not findings.get(slug):
                            findings[slug]=[]
                        findings[slug].append(d)
        for key, values in findings.items():
            findinglist = ''
            for d in values:
                d['VulnDesc']=d['VulnDesc'].replace('$','$$')
                d['ParamTable']=d['ParamTable'].replace('$','$$')
                d['Link']=d['Link'].replace('$','$$')
                temp=self.merge_findinglist_template
                text=temp.substitute(d)
                findinglist+=text+"\n\n"
            d['findinglist']=findinglist
            filename=key+".md";
            temp=self.template
            text=temp.substitute(d)
            if self.options['result_overwrite'] or (not os.path.exists(self.options['output_dir']+'/'+filename)):
                tmpfile = open(self.options['output_dir']+'/'+filename, 'w');
                tmpfile.write(text)
                tmpfile.close()


    def value(self, x, default):
        try:
            #ret=x[0].strip()
            ret="\n".join([html2markdown(html2markdown(y.strip(), True)) for y in x])
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

