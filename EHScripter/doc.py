##!/usr/bin/env python3
# -*- coding: utf-8 -*-
try:
    from .util import *
except Exception as e:
    from util import *
import os
import re
import itertools
import shutil
import sys
import argparse
import string
import unicodedata
import pygal
import html2text
import cgi
from pygal.style import LightStyle
from pygal.style import Style

class GenerateDoc:
    def __init__(self, options):
        self.options=options
        self.process()


    def explode(self, finding):

        findingtext=open(finding).read()

        separators=[]

        separators.append({'name':'title','re':re.compile(self.options['regex_title'], re.DOTALL|re.MULTILINE|re.UNICODE)})
        separators.append({'name':'category','re':re.compile(self.options['regex_category'], re.DOTALL|re.MULTILINE|re.UNICODE)})
        separators.append({'name':'risklevel','re':re.compile(self.options['regex_risk_level'], re.DOTALL|re.MULTILINE|re.UNICODE)})
        separators.append({'name':'assessmentstate','re':re.compile(self.options['regex_assessment_state'], re.DOTALL|re.MULTILINE|re.UNICODE)})
        separators.append({'name':'relatedrisk','re':re.compile(self.options['regex_related_risk'], re.DOTALL|re.MULTILINE|re.UNICODE)})
        separators.append({'name':'recommendation','re':re.compile(self.options['regex_recommendation'], re.DOTALL|re.MULTILINE|re.UNICODE)})
        separators.append({'name':'table','re':re.compile('^-----------\|', re.DOTALL|re.MULTILINE|re.UNICODE)})

        named=['title']


        pieces=[]
        for position in range(0,len(findingtext)-1):
            chars=findingtext[position:]
            for separator in separators:
                result=separator.get('re').match(chars)
                if result:
                    resultdict=result.group()
                    if separator.get('name') in named:
                        pieces.append({'name': separator.get('name'), 'start':position, 'end':len(findingtext), 'text':result.group(1)})
                    else:
                        pieces.append({'name': separator.get('name'), 'start': position+len(result.group()), 'end':len(findingtext), 'text':False})
                    if len(pieces)>1:
                        pieces[len(pieces)-2]['end']=position
        returndict={}
        for piece in pieces :
            returndict[piece['name']] = piece['text'] if piece['text'] else findingtext[piece['start']:piece['end']].strip()

        return returndict


    def process(self):
        vulns={}
        vulns['critical']=[]
        vulns['high']=[]
        vulns['medium']=[]
        vulns['low']=[]
        vulns['info']=[]

        strlen = 30

        risks=[i.strip() for i in self.options['list_risks'].split(',')]
        categories=[i.strip() for i in self.options['list_categories'].split(',')]

        risklevellistpositions={'info':4,'low':3,'medium':2,'high':1,'critical':0}
        if not os.path.exists(self.options["load_dir"]+'/screenshots'):
            os.makedirs(self.options["load_dir"]+'/screenshots')


        matrix={}
        for category in categories:
            row={}
            for risk in risks:
                row[risk]=0
            matrix[category]=row


        full = ''

        for name in os.listdir(self.options["load_dir"]) :
            name=self.options["load_dir"]+'/'+name
            if os.path.isdir(name) and os.path.isfile(name+'/document.md') :
                risklevelpiece=os.path.basename(name).split('-')[0]
                if risklevelpiece in ['info','low', 'medium', 'high', 'critical']:
                    doc=self.explode(name+'/document.md')
                    vulns[risklevelpiece].append({'f': name+'/document.md', 't':doc.get('title', ''), 'd':name})
                    cs=[i.strip() for i in doc.get('category', '').split(',')]
                    for c in cs:
                        if not c in categories:
                            categories.append(c)
                            row={}
                            for r in risks:
                                row[r]=0
                            matrix[c]=row
                        matrix[c][risks[risklevellistpositions[risklevelpiece]]]+=1
                    if os.path.isdir(name+'/screenshots'):
                        for s in os.listdir(name+'/screenshots'):
                            if os.path.isfile(name+'/screenshots/'+s):
                                shutil.copy(name+'/screenshots/'+s, self.options["load_dir"]+'/screenshots/'+s)

        t='\n\n'
        if self.options["matrix"] :

            t = '\n\n##%s##\n\n'%self.options['txt_matrix']

            t+= '\n| %s |'%self.options['txt_category'].ljust(strlen)

            for r in risks :
                t+= ' %s |'%r.ljust(strlen)


            t+= '\n| %s |'%('-'*strlen)
            for r in risks :
                t+= ' :%s: |'%('-'*(strlen-2))
            t+='\n'
            maxnum=0

            for key in matrix:
                printable=False;
                row=matrix[key]
                sumr=0
                c=0
                xt = ''
                for r in risks:
                    xt+= ' %s |'%str('' if row[r]==0 else row[r]).ljust(strlen)
                    if c==0:
                        sumr+=row[r]*8
                    if c==1:
                        sumr+=row[r]*4
                    if c==2:
                        sumr+=row[r]*2
                    if c==3:
                        sumr+=row[r]
                    c+=1
                    if row[r] > 0 :
                        printable = True
                    if row[r]>maxnum :
                        maxnum=row[r]

                if printable :
                    t+= '| %s |'% key.ljust(strlen)
                    t+=xt

                    t+= '\n'

            t+= '\n%s\n\n'%self.options['txt_matrix']

#            if not self.options.nocombinedmatrix:
#                t+=ct


        if self.options["pie_chart"]:
            t+= '\n\n##%s##\n\n'%self.options['txt_pie']
            custom_style = Style(
              background='#ffffff',
              plot_background='#ffffff',
              foreground='#000000',
              foreground_light='#000000',
              foreground_dark='#000000',
              opacity='1',
              opacity_hover='1',
              colors=('#d43f3a', '#ee9336', '#fdc431', '#4cae4c', '#357abd'))
            # critical #d43f3a R: 212 G: 63  B: 58
            # high     #ee9336 R: 238 G: 147 B: 54
            # medium   #fdc431 R: 253 G: 196 B: 49
            # low      #4cae4c R: 76  G: 174 B: 76
            # info     #357abd R: 53  G: 122 B: 189

            pie_chart = pygal.Pie(width=600, height=450,legend_box_size=15, style=custom_style, print_values=False, truncate_legend=0, truncate_label=20)
            pie_chart.add(self.options['txt_risk_short_critical'], len(vulns['critical']))
            pie_chart.add(self.options['txt_risk_short_high'], len(vulns['high']))
            pie_chart.add(self.options['txt_risk_short_medium'], len(vulns['medium']))
            pie_chart.add(self.options['txt_risk_short_low'], len(vulns['low']))
            pie_chart.add(self.options['txt_risk_short_info'], len(vulns['info']))

            pie_chart.render_to_png(self.options["load_dir"]+'/pie_chart.png')


            t+= "\n\n![%s](pie_chart.png)\n\n"%self.options['txt_pie']

        if self.options["summarized_matrix"] :
            t+='\n\n##%s##\n\n\n'%self.options['txt_summarized_matrix']
            t+='| %s | %s |\n'%(self.options['txt_summarized_matrix_risks'].ljust(strlen), self.options['txt_summarized_matrix_sum'].ljust(strlen))
            t+='| %s | %s |\n'%(('-'*(strlen-0)), ('-'*(strlen-0)))
            t+='| %s | %s |\n'%(self.options['txt_risk_short_critical'].ljust(strlen), str(len(vulns['critical'])).ljust(strlen))
            t+='| %s | %s |\n'%(self.options['txt_risk_short_high'].ljust(strlen), str(len(vulns['high'])).ljust(strlen))
            t+='| %s | %s |\n'%(self.options['txt_risk_short_medium'].ljust(strlen), str(len(vulns['medium'])).ljust(strlen))
            t+='| %s | %s |\n'%(self.options['txt_risk_short_low'].ljust(strlen), str(len(vulns['low'])).ljust(strlen))
            t+='| %s | %s |\n'%(self.options['txt_risk_short_info'].ljust(strlen), str(len(vulns['info'])).ljust(strlen))
            t+='\n\n-\n\n'
        scritical = sorted(vulns['critical'], key=lambda k: k['d'])
        shigh = sorted(vulns['high'], key=lambda k: k['d'])
        smedium = sorted(vulns['medium'], key=lambda k: k['d'])
        slow = sorted(vulns['low'], key=lambda k: k['d'])
        sinfo = sorted(vulns['info'], key=lambda k: k['d'])
        fileList = ''


        if len(scritical)>0:
            t+='\n%s\n\n'%self.options['txt_risk_critical']
            for c in scritical:
                t+='* '+c['t']+'\n'
                fileList+=' ./'+c['f']
                full += "\n\n\n"+open(c['f']).read()
        if len(shigh)>0:
            t+='\n%s\n\n'%self.options['txt_risk_high']
            for h in shigh:
                t+='* '+h['t']+'\n'
                fileList+=' ./'+h['f']
                full += "\n\n\n"+open(h['f']).read()
        if len(smedium)>0:
            t+='\n%s\n\n'%self.options['txt_risk_medium']
            for m in smedium:
                t+='* '+m['t']+'\n'
                fileList+=' ./'+m['f']
                full += "\n\n\n"+open(m['f']).read()
        if len(slow)>0:
            t+='\n%s\n\n'%self.options['txt_risk_low']
            for l in slow:
                t+='* '+l['t']+'\n'
                fileList+=' ./'+l['f']
                full += "\n\n\n"+open(l['f']).read()
        if len(sinfo)>0:
            t+='\n%s\n\n'%self.options['txt_risk_info']
            for i in sinfo:
                t+='* '+i['t']+'\n'
                fileList+=' ./'+i['f']
                full += "\n\n\n"+open(i['f']).read()

        if self.options["preface_markdown_file"] != "" :
            t += "\n\n\n"+open(self.options["preface_markdown_file"]).read()

        #full=full.replace("</ul>","</ul>\n\n")
        #fullines=full.split('\n')
        #convertedlines=[]
        #for line in fullines:
        #    cline=html2text.html2text(line).strip()
        #    cline=cline.replace('\\-\n','- ')
        #    cline=cline.replace('\\-','-')
        #    space_begin = re.compile(r'^\s+')
        #    space_begin_match = space_begin.search(line)
        #    space_end = re.compile(r'\s+$')
        #    space_end_match = space_end.search(line)
        #    space_begin_len=0
        #    space_end_len=0
        #    try:
        #        space_begin_len=len(space_begin_match.group())
        #    except Exception as e:
        #        pass
        #    try:
        #        space_end_len=len(space_end_match.group())
        #    except Exception as e:
        #        pass
        #    convertedlines.append((" "*space_begin_len)+cgi.escape(cline)+(" "*space_end_len))
        #t += "\n".join(convertedlines)
        t += full

        temp=string.Template(t)

        d={'company':self.options['company'], 'partner':self.options['partner']}
        text=t
        try:
            text=temp.substitute(d)
        except Exception as e:
            print('itt egy exception')
            print(e)

        t=text

        piccounter=itertools.count(1)
        t = re.sub("(?<=\!\[)([^\]]+)(?=\])", lambda m:  "%s %s: %s" % (self.options['txt_figure'], next(piccounter), m.group(1)), t)

        tabcounter=itertools.count(1)
        t = re.sub("(?<=\|\n\n)([^\n]+)(?=\n)", lambda m:  "%s %s: %s" % (self.options['txt_table'], next(tabcounter), m.group(1)), t)

        tmpfile = open(self.options["load_dir"]+'/vulns.md', 'w');
        tmpfile.write(t.strip())
        tmpfile.close()
        if len(self.options['reference_doc'].strip())>0:
            command = 'cd %s;pandoc -s --reference-%s %s -o %s -f markdown+tex_math_dollars+pipe_tables-raw_html -t %s %s/vulns.md '%(self.options["load_dir"],self.options['format'],self.options['reference_doc'],self.options['output_file'],self.options['format'],self.options["load_dir"])
        else :
            command = 'cd %s;pandoc -s -o %s -f markdown+tex_math_dollars+pipe_tables-raw_html -t %s %s/vulns.md '%(self.options["load_dir"], self.options['output_file'],self.options['format'],self.options["load_dir"])
        os.system( command )
        print(command)
