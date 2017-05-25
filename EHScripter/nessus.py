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
        filelist=[]
        if os.path.isfile(self.options['load_file']):
            filelist.append(self.options['load_file'])
        elif os.path.isdir(self.options['load_file']):
            for name in os.listdir(self.options["load_file"]):
                if os.path.isfile(self.options['load_file']+'/'+name) and len(name)>7 and name[-7:]==".nessus":
                    filelist.append(self.options["load_file"]+'/'+name)
        counter=1
        findings={}
        findingsbyip={}
        findingsbyplugin={}
        risklevellistpositions={'info':4,'low':3,'medium':2,'high':1,'critical':0}
        counters={'Info':0,'Low':0,'Medium':0,'High':0,'Critical':0}
        sluggedcounter={}
        for processfile in filelist:
            tree = etree.parse(processfile)
            reporthosts=tree.xpath("//ReportHost")
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
                            d={'name':name, 'port':port, 'svc_name':svc_name, 'protocol':protocol, 'pluginName':pluginName, 'pluginFamily':pluginFamily, 'solution': solution, 'risk_factor': risk_factor, 'risk_factor_style': risk_factor.lower()+'Character', 'description': description, 'plugin_output': plugin_output, 'findinglist':'', 'cvss_base_score':cvss_base_score, 'cvss_vector':cvss_vector.replace('CVSS2#',''), 'slugscore':''}
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
                                slugForMerge=slugify('%s-%s-nessus'%(risk_factor, pluginName))
                                gotit=False
                                if not findings.get(slugForMerge):
                                    counters[risk_factor]=counters[risk_factor]+1;
                                    sluggedcounter[slugForMerge]=counters[risk_factor]
                                slug=slugify('%s-%s-nessus'%(risk_factor, pluginName))
                                slug='s'+risk_factor[0:1]+str(sluggedcounter[slugForMerge]).zfill(3)
                                slug=slug.lower();
                                pluginNameHeader=slug.upper()+" - "+pluginName
                                d['pluginName']=pluginName
                                d['pluginNameHeader']=pluginNameHeader
                                d['slugscore']=slug+'_score.png'
                                d['slug']=slug
                                if not findings.get(slugForMerge):
                                    findings[slugForMerge]=[]
                                m = re.match("^\d+\.\d+\.\d+\.\d+$", name)
                                if m:
                                    nameip="%03d.%03d.%03d.%03d" % tuple(int(ippart) for ippart in name.split("."))
                                else :
                                    nameip=name
                                slugbyip=slugify('%s-%s-%05d-%s-%d'%(nameip, pluginName, int(port), protocol, risklevellistpositions[risk_factor.lower()]))
                                if not findingsbyip.get(slugbyip):
                                    findingsbyip[slugbyip]={'name':name, 'port':port, 'protocol':protocol, 'pluginName':pluginName, 'risk_factor':risk_factor}
                                slugbyplugin=slugify('%d-%s-%s-%05d-%s'%(risklevellistpositions[risk_factor.lower()], pluginName, nameip, int(port), protocol))
                                if not findingsbyplugin.get(slugbyplugin):
                                    findingsbyplugin[slugbyplugin]={'name':name, 'port':port, 'protocol':protocol, 'pluginName':pluginName, 'risk_factor':risk_factor}
                                for dinfindings in findings[slugForMerge]:
                                    if d['name'] == dinfindings['name'] and d['port'] == dinfindings['port'] and d['svc_name'] == dinfindings['svc_name'] and d['protocol'] == dinfindings['protocol'] and d['risk_factor'] == dinfindings['risk_factor'] and d['description'] == dinfindings['description'] and d['plugin_output'] == dinfindings['plugin_output']:
                                        gotit=True
                                if not gotit:
                                    findings[slugForMerge].append(d)
                                    pass
        sumtextbyip="ip;plugin;port;protocol;risk\n"
        sumtexttemplatebyip=string.Template("$name;$pluginName;$port;$protocol;$risk_factor")
        for key  in sorted(findingsbyip.keys()):
            text=sumtexttemplatebyip.substitute(findingsbyip[key])
            sumtextbyip+=text+"\n"
        tmpfile = open(self.options['output_dir']+'/sumbyip.csv', 'w');
        tmpfile.write(sumtextbyip)
        tmpfile.close()
        sumtextbyplugin="risk;plugin;ip;port;protocol\n"
        sumtexttemplatebyplugin=string.Template("$risk_factor;$pluginName;$name;$port;$protocol")
        for key  in sorted(findingsbyplugin.keys()):
            text=sumtexttemplatebyplugin.substitute(findingsbyplugin[key])
            sumtextbyplugin+=text+"\n"
        tmpfile = open(self.options['output_dir']+'/sumbyplugin.csv', 'w');
        tmpfile.write(sumtextbyplugin)
        tmpfile.close()

        for key, values in findings.items():
            findinglist = ''
            for d in values:
                d['plugin_output']=d['plugin_output'].replace('$','$$')
                d['description']=d['description'].replace('$','$$')
                temp=self.merge_findinglist_template
                text=temp.substitute(d)
                findinglist+=text+"\n\n"
            d['findinglist']=findinglist
            if self.options['counter_filename']:
                filename=d['slug']+".md";
            else:
                filename=key+".md";
            temp=self.template
            text=temp.substitute(d)
            if self.options['result_overwrite'] or (not os.path.exists(self.options['output_dir']+'/'+filename)):
                tmpfile = open(self.options['output_dir']+'/'+filename, 'w');
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
