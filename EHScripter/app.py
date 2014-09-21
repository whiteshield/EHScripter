##!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter
from tkinter import *
from tkinter.ttk import *
from tkinter import filedialog, messagebox, simpledialog
import re, os, platform
import time
import yaml
from .config import DefaultConfig
from .nessus import NessusToMarkdown
from .burp import BurpToMarkdown
from .acunetix import AcunetixToMarkdown
from .doc import GenerateDoc


class EHScripterApplication(Frame):
    """pandastable viewer app"""
    def __init__(self, parent=None):
        "Initialize the application."

        self.parent=parent
        if not self.parent:
            Frame.__init__(self)
            self.main=self.master
        else:
            self.main=Toplevel()
            self.master=self.main

        #self.currplatform=platform.system()
        self.inputyaml='%s/.EHScripter.yaml'%os.path.expanduser("~")
        self.outputs={'nessus':{},'burp':{},'doc':{},'acunetix':{}}
        self.widgets={'nessus':{},'burp':{},'doc':{},'acunetix':{}}

        #self.style = Style()
        #available_themes = self.style.theme_names()
        #self.style.theme_use('clam')
        #self.style.configure("TButton", padding=2, relief="raised")
        self.main.title('Ethical Hacking Scripter - EHScripter')
        self.loadInput()
        self.saveInput()
        self.setupGUI()

        self.main.protocol('WM_DELETE_WINDOW',self.quit)
        return

    def loadInput(self):
        try:
            with open(self.inputyaml) as in_file:
                self.inputs=yaml.load(in_file)           
        except Exception as e:
            self.inputs={}
        self.inputs=DefaultConfig.check(self.inputs)
        return

    def saveInput(self):
        try:
            with open(self.inputyaml, 'w') as outfile:
                outfile.write( yaml.dump(self.inputs) )
        except Exception as e:
            pass

    def readOutput(self):
        self.inputs['nessus']['load_file']=self.widgets['nessus']['load_file'].get()
        self.inputs['nessus']['output_dir']=self.widgets['nessus']['output_dir'].get()
        self.inputs['nessus']['template']=self.widgets['nessus']['template'].get(1.0,"%s-1c" % END)
        self.inputs['nessus']['merge_template']=self.widgets['nessus']['merge_template'].get(1.0,"%s-1c" % END)
        self.inputs['nessus']['merge_findinglist_template']=self.widgets['nessus']['merge_findinglist_template'].get(1.0,"%s-1c" % END)
        self.inputs['burp']['load_file']=self.widgets['burp']['load_file'].get()
        self.inputs['burp']['output_dir']=self.widgets['burp']['output_dir'].get()
        self.inputs['burp']['template']=self.widgets['burp']['template'].get(1.0,"%s-1c" % END)
        self.inputs['burp']['merge_template']=self.widgets['burp']['merge_template'].get(1.0,"%s-1c" % END)
        self.inputs['burp']['merge_findinglist_template']=self.widgets['burp']['merge_findinglist_template'].get(1.0,"%s-1c" % END)
        self.inputs['acunetix']['load_file']=self.widgets['acunetix']['load_file'].get()
        self.inputs['acunetix']['output_dir']=self.widgets['acunetix']['output_dir'].get()
        self.inputs['acunetix']['template']=self.widgets['acunetix']['template'].get(1.0,"%s-1c" % END)
        self.inputs['acunetix']['merge_template']=self.widgets['acunetix']['merge_template'].get(1.0,"%s-1c" % END)
        self.inputs['acunetix']['merge_findinglist_template']=self.widgets['acunetix']['merge_findinglist_template'].get(1.0,"%s-1c" % END)
        self.inputs['doc']['load_dir']=self.widgets['doc']['load_dir'].get()
        self.inputs['doc']['output_file']=self.widgets['doc']['output_file'].get()
        self.inputs['doc']['reference_doc']=self.widgets['doc']['reference_doc'].get()
        self.inputs['doc']['preface_markdown_file']=self.widgets['doc']['preface_markdown_file'].get()
        self.inputs['doc']['company']=self.widgets['doc']['company'].get()
        self.inputs['doc']['partner']=self.widgets['doc']['partner'].get()
        

        self.inputs['doc']['format']=self.outputs['doc']['format'].get()

        self.inputs['doc']['txt_pie']=self.widgets['doc']['txt_pie'].get()
        self.inputs['doc']['txt_figure']=self.widgets['doc']['txt_figure'].get()
        self.inputs['doc']['txt_table']=self.widgets['doc']['txt_table'].get()
        self.inputs['doc']['txt_category']=self.widgets['doc']['txt_category'].get()
        self.inputs['doc']['txt_matrix']=self.widgets['doc']['txt_matrix'].get()
        self.inputs['doc']['txt_summarized_matrix']=self.widgets['doc']['txt_summarized_matrix'].get()
        self.inputs['doc']['txt_summarized_matrix_risks']=self.widgets['doc']['txt_summarized_matrix_risks'].get()
        self.inputs['doc']['txt_summarized_matrix_sum']=self.widgets['doc']['txt_summarized_matrix_sum'].get()
        self.inputs['doc']['txt_risk_critical']=self.widgets['doc']['txt_risk_critical'].get()
        self.inputs['doc']['txt_risk_high']=self.widgets['doc']['txt_risk_high'].get()
        self.inputs['doc']['txt_risk_medium']=self.widgets['doc']['txt_risk_medium'].get()
        self.inputs['doc']['txt_risk_low']=self.widgets['doc']['txt_risk_low'].get()
        self.inputs['doc']['txt_risk_info']=self.widgets['doc']['txt_risk_info'].get()
        self.inputs['doc']['txt_risk_short_critical']=self.widgets['doc']['txt_risk_short_critical'].get()
        self.inputs['doc']['txt_risk_short_high']=self.widgets['doc']['txt_risk_short_high'].get()
        self.inputs['doc']['txt_risk_short_medium']=self.widgets['doc']['txt_risk_short_medium'].get()
        self.inputs['doc']['txt_risk_short_low']=self.widgets['doc']['txt_risk_short_low'].get()
        self.inputs['doc']['txt_risk_short_info']=self.widgets['doc']['txt_risk_short_info'].get()
        self.inputs['doc']['list_risks']=self.widgets['doc']['list_risks'].get()
        self.inputs['doc']['list_categories']=self.widgets['doc']['list_categories'].get()
        self.inputs['doc']['regex_title']=self.widgets['doc']['regex_title'].get()
        self.inputs['doc']['regex_category']=self.widgets['doc']['regex_category'].get()
        self.inputs['doc']['regex_risk_level']=self.widgets['doc']['regex_risk_level'].get()
        self.inputs['doc']['regex_assessment_state']=self.widgets['doc']['regex_assessment_state'].get()
        self.inputs['doc']['regex_related_risk']=self.widgets['doc']['regex_related_risk'].get()
        self.inputs['doc']['regex_recommendation']=self.widgets['doc']['regex_recommendation'].get()
        
        self.saveInput()

    def nessusRun(self):
        self.readOutput()
        letsgo=True
        if not os.path.isfile(self.inputs['nessus']['load_file']):
            messagebox.showerror("Error", "%s\nNessus input file not exists!"%self.inputs['nessus']['load_file'])
            letsgo=False
        if not os.path.isdir(self.inputs['nessus']['output_dir']):
            try:
                os.makedirs(self.inputs['nessus']['output_dir'])
            except Exception as e:
                letsgo=False
                messagebox.showerror("Error", "%s\nUnable to create output dir!"%self.inputs['nessus']['output_dir'])
        if letsgo:
            NessusToMarkdown(self.inputs['nessus'])
            pass

    def nessusMergeChanged(self):
        if self.outputs['nessus']['merge'].get() :
            self.inputs['nessus']['merge']=True
            self.widgets['nessus']['template'].config(state=DISABLED)
            self.widgets['nessus']['merge_template'].config(state=NORMAL)
            self.widgets['nessus']['merge_findinglist_template'].config(state=NORMAL)
        else:
            self.inputs['nessus']['merge']=False
            self.widgets['nessus']['template'].config(state=NORMAL)
            self.widgets['nessus']['merge_template'].config(state=DISABLED)
            self.widgets['nessus']['merge_findinglist_template'].config(state=DISABLED)

    def nessusResultOverwriteChanged(self):
        if self.outputs['nessus']['result_overwrite'].get() :
            self.inputs['nessus']['result_overwrite']=True
        else:
            self.inputs['nessus']['result_overwrite']=False

    def burpRun(self):
        self.readOutput()
        letsgo=True
        if not os.path.isfile(self.inputs['burp']['load_file']):
            messagebox.showerror("Error", "%s\nBurp input file not exists!"%self.inputs['burp']['load_file'])
            letsgo=False
        if not os.path.isdir(self.inputs['burp']['output_dir']):
            try:
                os.makedirs(self.inputs['burp']['output_dir'])
            except Exception as e:
                letsgo=False
                messagebox.showerror("Error", "%s\nUnable to create output dir!"%self.inputs['burp']['output_dir'])
        if letsgo:
            BurpToMarkdown(self.inputs['burp'])
            pass

    def burpMergeChanged(self):
        if self.outputs['burp']['merge'].get() :
            self.inputs['burp']['merge']=True
            self.widgets['burp']['template'].config(state=DISABLED)
            self.widgets['burp']['merge_template'].config(state=NORMAL)
            self.widgets['burp']['merge_findinglist_template'].config(state=NORMAL)
        else:
            self.widgets['burp']['template'].config(state=NORMAL)
            self.widgets['burp']['merge_template'].config(state=DISABLED)
            self.widgets['burp']['merge_findinglist_template'].config(state=DISABLED)
            self.inputs['burp']['merge']=False

    def burpResultOverwriteChanged(self):
        if self.outputs['burp']['result_overwrite'].get() :
            self.inputs['burp']['result_overwrite']=True
        else:
            self.inputs['burp']['result_overwrite']=False


    def acunetixRun(self):
        self.readOutput()
        letsgo=True
        if not os.path.isfile(self.inputs['acunetix']['load_file']):
            messagebox.showerror("Error", "%s\nAcunetix input file not exists!"%self.inputs['acunetix']['load_file'])
            letsgo=False
        if not os.path.isdir(self.inputs['acunetix']['output_dir']):
            try:
                os.makedirs(self.inputs['acunetix']['output_dir'])
            except Exception as e:
                letsgo=False
                messagebox.showerror("Error", "%s\nUnable to create output dir!"%self.inputs['acunetix']['output_dir'])
        if letsgo:
            AcunetixToMarkdown(self.inputs['acunetix'])
            pass

    def acunetixMergeChanged(self):
        if self.outputs['acunetix']['merge'].get() :
            self.inputs['acunetix']['merge']=True
            self.widgets['acunetix']['template'].config(state=DISABLED)
            self.widgets['acunetix']['merge_template'].config(state=NORMAL)
            self.widgets['acunetix']['merge_findinglist_template'].config(state=NORMAL)
        else:
            self.widgets['acunetix']['template'].config(state=NORMAL)
            self.widgets['acunetix']['merge_template'].config(state=DISABLED)
            self.widgets['acunetix']['merge_findinglist_template'].config(state=DISABLED)
            self.inputs['acunetix']['merge']=False

    def acunetixResultOverwriteChanged(self):
        if self.outputs['acunetix']['result_overwrite'].get() :
            self.inputs['acunetix']['result_overwrite']=True
        else:
            self.inputs['acunetix']['result_overwrite']=False


    def setupNessusFrame(self):
        self.frameNessus = Frame(self.notebook, padding="10 10 10 10")
        Label(self.frameNessus, text="Input file:").grid(column=1, row=1, sticky=(E))
        Label(self.frameNessus, text="Template:").grid(column=1, row=2, sticky=(E))
        Label(self.frameNessus, text="name, port, svc_name, protocol, pluginName, pluginFamily, solution, risk_factor, description, plugin_output, cvss_base_score, cvss_vector, findinglist", wraplength=300).grid(column=5, row=2, sticky=(N, W))
        Label(self.frameNessus, text="Merge:").grid(column=1, row=3, sticky=(E))
        Label(self.frameNessus, text="Merge Template:").grid(column=1, row=4, sticky=(E))
        Label(self.frameNessus, text="Merge Items:").grid(column=4, row=4, sticky=(E))
        Label(self.frameNessus, text="Output dir:").grid(column=1, row=6, sticky=(E))
        Label(self.frameNessus, text="Overwrite results:").grid(column=1, row=7, sticky=(E))

        self.addEntry(self.frameNessus, 'nessus', 'load_file', 2, 1)
        self.addEntry(self.frameNessus, 'nessus', 'output_dir', 2, 6)

        self.outputs['nessus']['merge'] = BooleanVar()
        self.outputs['nessus']['merge'].set(self.inputs['nessus']['merge'])
        self.widgets['nessus']['merge'] = Checkbutton(self.frameNessus, text='', command=self.nessusMergeChanged, variable=self.outputs['nessus']['merge'], onvalue=True, offvalue=False)
        self.widgets['nessus']['merge'].grid(column=2, row=3, sticky=(W, E))

        self.outputs['nessus']['result_overwrite'] = BooleanVar()
        self.outputs['nessus']['result_overwrite'].set(self.inputs['nessus']['result_overwrite'])
        self.widgets['nessus']['result_overwrite'] = Checkbutton(self.frameNessus, text='', command=self.nessusResultOverwriteChanged, variable=self.outputs['nessus']['result_overwrite'], onvalue=True, offvalue=False)
        self.widgets['nessus']['result_overwrite'].grid(column=2, row=7, sticky=(W, E))

        self.widgets['nessus']['template'] = Text(self.frameNessus, width=40, height=10)
        self.widgets['nessus']['template'].insert(INSERT, self.inputs['nessus']['template'])
        self.widgets['nessus']['template'].grid(column=2, row=2, sticky=(W, E,N,S))
        self.widgets['nessus']['template'].config(background='white')
        scroll_template = Scrollbar(self.frameNessus, orient=VERTICAL, command=self.widgets['nessus']['template'].yview)
        scroll_template.grid(column=3, row=2, sticky=(N,S))
        self.widgets['nessus']['template']['yscrollcommand'] = scroll_template.set
        #self.widgets['nessus']['template'].pack(expand=YES, fill=BOTH)

        self.widgets['nessus']['merge_template'] = Text(self.frameNessus, width=40, height=10)
        self.widgets['nessus']['merge_template'].insert(INSERT, self.inputs['nessus']['merge_template'])
        self.widgets['nessus']['merge_template'].grid(column=2, row=4, sticky=(W, E,N,S))
        self.widgets['nessus']['merge_template'].config(background='white')
        scroll_merge_template = Scrollbar(self.frameNessus, orient=VERTICAL, command=self.widgets['nessus']['merge_template'].yview)
        scroll_merge_template.grid(column=3, row=4, sticky=(N,S))
        self.widgets['nessus']['merge_template']['yscrollcommand'] = scroll_merge_template.set
        #self.widgets['nessus']['merge_template'].pack(expand=YES, fill=BOTH)

        self.widgets['nessus']['merge_findinglist_template'] = Text(self.frameNessus, width=40, height=10)
        self.widgets['nessus']['merge_findinglist_template'].insert(INSERT, self.inputs['nessus']['merge_findinglist_template'])
        self.widgets['nessus']['merge_findinglist_template'].grid(column=5, row=4, sticky=(W, E,N,S))
        self.widgets['nessus']['merge_findinglist_template'].config(background='white')
        scroll_merge_findinglist_template = Scrollbar(self.frameNessus, orient=VERTICAL, command=self.widgets['nessus']['merge_findinglist_template'].yview)
        scroll_merge_findinglist_template.grid(column=6, row=4, sticky=(N,S))
        self.widgets['nessus']['merge_findinglist_template']['yscrollcommand'] = scroll_merge_findinglist_template.set
        #self.widgets['nessus']['merge_findinglist_template'].pack(expand=YES, fill=BOTH)
        self.frameNessus.columnconfigure(1, weight=3, minsize=120)
        self.frameNessus.columnconfigure(2, weight=3, minsize=120)
        self.frameNessus.columnconfigure(3, weight=0, minsize=0)
        self.frameNessus.columnconfigure(4, weight=3, minsize=120)
        self.frameNessus.columnconfigure(5, weight=3, minsize=120)
        self.frameNessus.columnconfigure(6, weight=0, minsize=0)
        self.frameNessus.rowconfigure(1, weight=3, minsize=30)
        self.frameNessus.rowconfigure(2, weight=3, minsize=30)
        self.frameNessus.rowconfigure(3, weight=3, minsize=30)
        self.frameNessus.rowconfigure(4, weight=3, minsize=30)
        self.frameNessus.rowconfigure(5, weight=3, minsize=30)
        self.frameNessus.rowconfigure(6, weight=3, minsize=30)
        self.frameNessus.rowconfigure(7, weight=3, minsize=30)
        self.frameNessus.rowconfigure(8, weight=3, minsize=30)

        self.nessusMergeChanged()

        Button(self.frameNessus, text="RUN", command=self.nessusRun).grid(column=1, row=8, columnspan=6)

        #for child in self.frameNessus.winfo_children(): child.grid_configure(padx=5, pady=5)

    def setupBurpFrame(self):
        self.frameBurp = Frame(self.notebook, padding="10 10 10 10")
        Label(self.frameBurp, text="Input file:").grid(column=1, row=1, sticky=(E))
        Label(self.frameBurp, text="Template:").grid(column=1, row=2, sticky=(E))
        Label(self.frameBurp, text="serialNumber, type, name, host, path, location, severity, confidence, issueBackground, remediationBackground, issueDetail, issueDetailItems, remediationDetail, requestresponse_request, requestresponse_request_method, requestresponse_request_base64, requestresponse_response, requestresponse_response_base64, requestresponse_responseRedirected, $findinglist", wraplength=300).grid(column=5, row=2, sticky=(N, W))

        Label(self.frameBurp, text="Merge:").grid(column=1, row=3, sticky=(E))
        Label(self.frameBurp, text="Merge Template:").grid(column=1, row=4, sticky=(E))
        Label(self.frameBurp, text="Merge Items:").grid(column=4, row=4, sticky=(E))
        Label(self.frameBurp, text="Output dir:").grid(column=1, row=6, sticky=(E))
        Label(self.frameBurp, text="Overwrite results:").grid(column=1, row=7, sticky=(E))

        self.addEntry(self.frameBurp, 'burp', 'load_file', 2, 1)
        self.addEntry(self.frameBurp, 'burp', 'output_dir', 2, 6)


        self.outputs['burp']['merge'] = BooleanVar()
        self.outputs['burp']['merge'].set(self.inputs['burp']['merge'])
        self.widgets['burp']['merge'] = Checkbutton(self.frameBurp, text='', command=self.burpMergeChanged, variable=self.outputs['burp']['merge'], onvalue=True, offvalue=False)
        self.widgets['burp']['merge'].grid(column=2, row=3, sticky=(W, E))

        self.outputs['burp']['result_overwrite'] = BooleanVar()
        self.outputs['burp']['result_overwrite'].set(self.inputs['burp']['result_overwrite'])
        self.widgets['burp']['result_overwrite'] = Checkbutton(self.frameBurp, text='', command=self.burpResultOverwriteChanged, variable=self.outputs['burp']['result_overwrite'], onvalue=True, offvalue=False)
        self.widgets['burp']['result_overwrite'].grid(column=2, row=7, sticky=(W, E))

        self.widgets['burp']['template'] = Text(self.frameBurp, width=40, height=10)
        self.widgets['burp']['template'].insert(INSERT, self.inputs['burp']['template'])
        self.widgets['burp']['template'].grid(column=2, row=2, sticky=(W, E,N,S))
        self.widgets['burp']['template'].config(background='white')
        scroll_template = Scrollbar(self.frameBurp, orient=VERTICAL, command=self.widgets['burp']['template'].yview)
        scroll_template.grid(column=3, row=2, sticky=(N,S))
        self.widgets['burp']['template']['yscrollcommand'] = scroll_template.set
        #self.widgets['burp']['template'].pack(expand=YES, fill=BOTH)

        self.widgets['burp']['merge_template'] = Text(self.frameBurp, width=40, height=10)
        self.widgets['burp']['merge_template'].insert(INSERT, self.inputs['burp']['merge_template'])
        self.widgets['burp']['merge_template'].grid(column=2, row=4, sticky=(W, E,N,S))
        self.widgets['burp']['merge_template'].config(background='white')
        scroll_merge_template = Scrollbar(self.frameBurp, orient=VERTICAL, command=self.widgets['burp']['merge_template'].yview)
        scroll_merge_template.grid(column=3, row=4, sticky=(N,S))
        self.widgets['burp']['merge_template']['yscrollcommand'] = scroll_merge_template.set
        #self.widgets['burp']['merge_template'].pack(expand=YES, fill=BOTH)

        self.widgets['burp']['merge_findinglist_template'] = Text(self.frameBurp, width=40, height=10)
        self.widgets['burp']['merge_findinglist_template'].insert(INSERT, self.inputs['burp']['merge_findinglist_template'])
        self.widgets['burp']['merge_findinglist_template'].grid(column=5, row=4, sticky=(W, E,N,S))
        self.widgets['burp']['merge_findinglist_template'].config(background='white')
        scroll_merge_findinglist_template = Scrollbar(self.frameBurp, orient=VERTICAL, command=self.widgets['burp']['merge_findinglist_template'].yview)
        scroll_merge_findinglist_template.grid(column=6, row=4, sticky=(N,S))
        self.widgets['burp']['merge_findinglist_template']['yscrollcommand'] = scroll_merge_findinglist_template.set
        #self.widgets['burp']['merge_findinglist_template'].pack(expand=YES, fill=BOTH)
        self.frameBurp.columnconfigure(1, weight=3, minsize=120)
        self.frameBurp.columnconfigure(2, weight=3, minsize=120)
        self.frameBurp.columnconfigure(3, weight=0, minsize=0)
        self.frameBurp.columnconfigure(4, weight=3, minsize=120)
        self.frameBurp.columnconfigure(5, weight=3, minsize=120)
        self.frameBurp.columnconfigure(6, weight=0, minsize=0)
        self.frameBurp.rowconfigure(1, weight=3, minsize=30)
        self.frameBurp.rowconfigure(2, weight=3, minsize=30)
        self.frameBurp.rowconfigure(3, weight=3, minsize=30)
        self.frameBurp.rowconfigure(4, weight=3, minsize=30)
        self.frameBurp.rowconfigure(5, weight=3, minsize=30)
        self.frameBurp.rowconfigure(6, weight=3, minsize=30)
        self.frameBurp.rowconfigure(7, weight=3, minsize=30)
        self.frameBurp.rowconfigure(8, weight=3, minsize=30)

        self.burpMergeChanged()

        Button(self.frameBurp, text="RUN", command=self.burpRun).grid(column=1, row=8, columnspan=6)

        #for child in self.frameBurp.winfo_children(): child.grid_configure(padx=5, pady=5)

    def setupAcunetixFrame(self):

        self.frameAcunetix = Frame(self.notebook, padding="10 10 10 10")
        Label(self.frameAcunetix, text="Input file:").grid(column=1, row=1, sticky=(E))
        Label(self.frameAcunetix, text="Template:").grid(column=1, row=2, sticky=(E))
        Label(self.frameAcunetix, text="Name, ModuleName, Details, Affects, Parameter, AOP_SourceFile, AOP_SourceLine, AOP_Additional, IsFalsePositive, Severity, Type, Impact, Description, DetailedInformation, Recommendation, Request, Response", wraplength=300).grid(column=5, row=2, sticky=(N, W))
        Label(self.frameAcunetix, text="Merge:").grid(column=1, row=3, sticky=(E))
        Label(self.frameAcunetix, text="Merge Template:").grid(column=1, row=4, sticky=(E))
        Label(self.frameAcunetix, text="Merge Items:").grid(column=4, row=4, sticky=(E))
        Label(self.frameAcunetix, text="Output dir:").grid(column=1, row=6, sticky=(E))
        Label(self.frameAcunetix, text="Overwrite results:").grid(column=1, row=7, sticky=(E))

        self.addEntry(self.frameAcunetix, 'acunetix', 'load_file', 2, 1)
        self.addEntry(self.frameAcunetix, 'acunetix', 'output_dir', 2, 6)

        self.outputs['acunetix']['merge'] = BooleanVar()
        self.outputs['acunetix']['merge'].set(self.inputs['acunetix']['merge'])
        self.widgets['acunetix']['merge'] = Checkbutton(self.frameAcunetix, text='', command=self.acunetixMergeChanged, variable=self.outputs['acunetix']['merge'], onvalue=True, offvalue=False)
        self.widgets['acunetix']['merge'].grid(column=2, row=3, sticky=(W, E))

        self.outputs['acunetix']['result_overwrite'] = BooleanVar()
        self.outputs['acunetix']['result_overwrite'].set(self.inputs['acunetix']['result_overwrite'])
        self.widgets['acunetix']['result_overwrite'] = Checkbutton(self.frameAcunetix, text='', command=self.acunetixResultOverwriteChanged, variable=self.outputs['acunetix']['result_overwrite'], onvalue=True, offvalue=False)
        self.widgets['acunetix']['result_overwrite'].grid(column=2, row=7, sticky=(W, E))

        self.widgets['acunetix']['template'] = Text(self.frameAcunetix, width=40, height=10)
        self.widgets['acunetix']['template'].insert(INSERT, self.inputs['acunetix']['template'])
        self.widgets['acunetix']['template'].grid(column=2, row=2, sticky=(W, E, N, S))
        self.widgets['acunetix']['template'].config(background='white')
        scroll_template = Scrollbar(self.frameAcunetix, orient=VERTICAL, command=self.widgets['acunetix']['template'].yview)
        scroll_template.grid(column=3, row=2, sticky=(N,S))
        self.widgets['acunetix']['template']['yscrollcommand'] = scroll_template.set

        #self.widgets['acunetix']['template'].pack(expand=YES, fill=BOTH)

        self.widgets['acunetix']['merge_template'] = Text(self.frameAcunetix, width=40, height=10)
        self.widgets['acunetix']['merge_template'].insert(INSERT, self.inputs['acunetix']['merge_template'])
        self.widgets['acunetix']['merge_template'].grid(column=2, row=4, sticky=(W, E, N, S))
        self.widgets['acunetix']['merge_template'].config(background='white')
        scroll_merge_template = Scrollbar(self.frameAcunetix, orient=VERTICAL, command=self.widgets['acunetix']['merge_template'].yview)
        scroll_merge_template.grid(column=3, row=4, sticky=(N,S))
        self.widgets['acunetix']['merge_template']['yscrollcommand'] = scroll_merge_template.set
        #self.widgets['acunetix']['merge_template'].pack(expand=YES, fill=BOTH)

        self.widgets['acunetix']['merge_findinglist_template'] = Text(self.frameAcunetix, width=40, height=10)
        self.widgets['acunetix']['merge_findinglist_template'].insert(INSERT, self.inputs['acunetix']['merge_findinglist_template'])
        self.widgets['acunetix']['merge_findinglist_template'].grid(column=5, row=4, sticky=(W, E, N, S))
        self.widgets['acunetix']['merge_findinglist_template'].config(background='white')
        scroll_merge_findinglist_template = Scrollbar(self.frameAcunetix, orient=VERTICAL, command=self.widgets['acunetix']['merge_findinglist_template'].yview)
        scroll_merge_findinglist_template.grid(column=6, row=4, sticky=(N,S))
        self.widgets['acunetix']['merge_findinglist_template']['yscrollcommand'] = scroll_merge_findinglist_template.set
        #self.widgets['acunetix']['merge_findinglist_template'].pack(expand=YES, fill=BOTH)

        self.frameAcunetix.columnconfigure(1, weight=3, minsize=120)
        self.frameAcunetix.columnconfigure(2, weight=3, minsize=120)
        self.frameAcunetix.columnconfigure(3, weight=0, minsize=0)
        self.frameAcunetix.columnconfigure(4, weight=3, minsize=120)
        self.frameAcunetix.columnconfigure(5, weight=3, minsize=120)
        self.frameAcunetix.columnconfigure(6, weight=0, minsize=0)
        self.frameAcunetix.rowconfigure(1, weight=3, minsize=30)
        self.frameAcunetix.rowconfigure(2, weight=3, minsize=30)
        self.frameAcunetix.rowconfigure(3, weight=3, minsize=30)
        self.frameAcunetix.rowconfigure(4, weight=3, minsize=30)
        self.frameAcunetix.rowconfigure(5, weight=3, minsize=30)
        self.frameAcunetix.rowconfigure(6, weight=3, minsize=30)
        self.frameAcunetix.rowconfigure(7, weight=3, minsize=30)
        self.frameAcunetix.rowconfigure(8, weight=3, minsize=30)
        self.acunetixMergeChanged()

        Button(self.frameAcunetix, text="RUN", command=self.acunetixRun).grid(column=1, row=8, columnspan=6)

        #for child in self.frameAcunetix.winfo_children(): child.grid_configure(padx=5, pady=5)

    def setupDocxMacroFrame(self):
        self.frameDocxMacro = Frame(self.notebook, padding="10 10 10 10")
        text=''
        with open('EHScripter/docx.macro') as f: text = f.read()
        macro = Text(self.frameDocxMacro)
        macro.grid(column=0, row=0, sticky=(W, E, N, S))
        s = Scrollbar(self.frameDocxMacro, orient=VERTICAL, command=macro.yview)
        s.grid(column=1, row=0, sticky=(N,S))
        macro['yscrollcommand'] = s.set
        macro.insert(INSERT, text)
        macro.config(background='white')
        self.frameDocxMacro.columnconfigure(0, weight=3)
        self.frameDocxMacro.rowconfigure(0, weight=3)

        #for child in self.frameDocxMacro.winfo_children(): child.grid_configure(padx=5, pady=5)

    def setupOdtMacroFrame(self):
        self.frameOdtMacro = Frame(self.notebook, padding="10 10 10 10")
        text=''
        with open('EHScripter/odt.macro') as f: text = f.read()
        macro = Text(self.frameOdtMacro)
        macro.grid(column=0, row=0, sticky=(W, E, N, S))
        s = Scrollbar(self.frameOdtMacro, orient=VERTICAL, command=macro.yview)
        s.grid(column=1, row=0, sticky=(N,S))
        macro['yscrollcommand'] = s.set
        macro.insert(INSERT, text)
        macro.config(background='white')
        self.frameOdtMacro.columnconfigure(0, weight=3)
        self.frameOdtMacro.rowconfigure(0, weight=3)

        #for child in self.frameDocxMacro.winfo_children(): child.grid_configure(padx=5, pady=5)

    def docRun(self):
        self.readOutput()
        letsgo=True
        if not os.path.isdir(self.inputs['doc']['load_dir']):
            messagebox.showerror("Error", "%s\nDoc input dir not exists!"%self.inputs['doc']['load_dir'])
            letsgo=False
        if len(self.inputs['doc']['reference_doc'])>0 and not os.path.isfile(self.inputs['doc']['reference_doc']) :
            messagebox.showerror("Error", "%s\nReference doc not exists!"%self.inputs['doc']['reference_doc'])
            letsgo=False
        if len(self.inputs['doc']['preface_markdown_file'])>0 and not os.path.isfile(self.inputs['doc']['preface_markdown_file']) :
            messagebox.showerror("Error", "%s\nPreface markdown file not exists!"%self.inputs['doc']['preface_markdown_file'])
            letsgo=False
        if letsgo:
            GenerateDoc(self.inputs['doc'])
            

    def docPieChartChanged(self):
        if self.outputs['doc']['pie_chart'].get() :
            self.inputs['doc']['pie_chart']=True
        else:
            self.inputs['doc']['pie_chart']=False

    def docMatrixChanged(self):
        if self.outputs['doc']['matrix'].get() :
            self.inputs['doc']['matrix']=True
        else:
            self.inputs['doc']['matrix']=False

    def docSummarizedMatrixChanged(self):
        if self.outputs['doc']['summarized_matrix'].get() :
            self.inputs['doc']['summarized_matrix']=True
        else:
            self.inputs['doc']['summarized_matrix']=False

    def docFormatChanged(self):
        if self.outputs['doc']['format'].get()=='odt':
            self.outputs['doc']['reference_doc'].set(self.inputs['doc']['reference_doc'].replace('.docx','.odt'))
            self.outputs['doc']['output_file'].set(self.inputs['doc']['output_file'].replace('.docx','.odt'))
        else:
            self.outputs['doc']['reference_doc'].set(self.inputs['doc']['reference_doc'].replace('.odt','.docx'))
            self.outputs['doc']['output_file'].set(self.inputs['doc']['output_file'].replace('.odt','.docx'))

    def setupDocFrame(self):
        self.frameDoc = Frame(self.notebook, padding="10 10 10 10")
        Label(self.frameDoc, text="Input dir:").grid(column=1, row=1, sticky=(E))
        Label(self.frameDoc, text="Reference doc:").grid(column=1, row=2, sticky=(E))
        Label(self.frameDoc, text="Preface markdown file:").grid(column=1, row=3, sticky=(E))
        Label(self.frameDoc, text="Pie chart:").grid(column=1, row=4, sticky=(E))
        Label(self.frameDoc, text="Matrix:").grid(column=1, row=5, sticky=(E))
        Label(self.frameDoc, text="Summarized matrix:").grid(column=1, row=6, sticky=(E))
        Label(self.frameDoc, text="Output file:").grid(column=1, row=7, sticky=(E))
        Label(self.frameDoc, text="Company name:").grid(column=1, row=8, sticky=(E))
        Label(self.frameDoc, text="Partner name:").grid(column=1, row=9, sticky=(E))
        Label(self.frameDoc, text="Pie:").grid(column=1, row=11, sticky=(E))
        Label(self.frameDoc, text="Figure:").grid(column=1, row=12, sticky=(E))
        Label(self.frameDoc, text="Table:").grid(column=1, row=13, sticky=(E))
        Label(self.frameDoc, text="Category:").grid(column=1, row=14, sticky=(E))
        Label(self.frameDoc, text="Matrix:").grid(column=1, row=15, sticky=(E))
        Label(self.frameDoc, text="Summarized Matrix:").grid(column=1, row=16, sticky=(E))
        Label(self.frameDoc, text="Risk Header:").grid(column=1, row=17, sticky=(E))
        Label(self.frameDoc, text="SUM Header:").grid(column=1, row=18, sticky=(E))
        Label(self.frameDoc, text="Critical long:").grid(column=1, row=19, sticky=(E))
        Label(self.frameDoc, text="High long:").grid(column=1, row=20, sticky=(E))
        Label(self.frameDoc, text="Medium long:").grid(column=1, row=21, sticky=(E))
        Label(self.frameDoc, text="Low long:").grid(column=1, row=22, sticky=(E))
        Label(self.frameDoc, text="Info long:").grid(column=1, row=23, sticky=(E))
        Label(self.frameDoc, text="Critical short:").grid(column=3, row=19, sticky=(E))
        Label(self.frameDoc, text="High short:").grid(column=3, row=20, sticky=(E))
        Label(self.frameDoc, text="Medium short:").grid(column=3, row=21, sticky=(E))
        Label(self.frameDoc, text="Low short:").grid(column=3, row=22, sticky=(E))
        Label(self.frameDoc, text="Info short:").grid(column=3, row=23, sticky=(E))
        Label(self.frameDoc, text="Risk list:").grid(column=1, row=24, sticky=(E))
        Label(self.frameDoc, text="Category list:").grid(column=1, row=25, sticky=(E))
        
        Label(self.frameDoc, text="REGEX Title:").grid(column=3, row=11, sticky=(E))
        Label(self.frameDoc, text="REGEX Category:").grid(column=3, row=12, sticky=(E))
        Label(self.frameDoc, text="REGEX Risk level:").grid(column=3, row=13, sticky=(E))
        Label(self.frameDoc, text="REGEX Assessment state:").grid(column=3, row=14, sticky=(E))
        Label(self.frameDoc, text="REGEX Related risk:").grid(column=3, row=15, sticky=(E))
        Label(self.frameDoc, text="REGEX Recommendation:").grid(column=3, row=16, sticky=(E))

        self.outputs['doc']['format'] = StringVar()
        self.outputs['doc']['format'].set(self.inputs['doc']['format'])
        docx = Radiobutton(self.frameDoc, text='docx', variable=self.outputs['doc']['format'], value='docx', command=self.docFormatChanged)
        odt = Radiobutton(self.frameDoc, text='odt', variable=self.outputs['doc']['format'], value='odt', command=self.docFormatChanged)
        docx.grid(column=3, row=2, sticky=(W, E))
        odt.grid(column=4, row=2, sticky=(W, E))


        self.addEntry(self.frameDoc, 'doc', 'load_dir', 2, 1)
        self.addEntry(self.frameDoc, 'doc', 'reference_doc', 2, 2)
        self.addEntry(self.frameDoc, 'doc', 'preface_markdown_file', 2, 3)

        self.outputs['doc']['pie_chart'] = BooleanVar()
        self.outputs['doc']['pie_chart'].set(self.inputs['doc']['pie_chart'])
        self.widgets['doc']['pie_chart'] = Checkbutton(self.frameDoc, text='', command=self.docPieChartChanged, variable=self.outputs['doc']['pie_chart'], onvalue=True, offvalue=False)
        self.widgets['doc']['pie_chart'].grid(column=2, row=4, sticky=(W, E))

        self.outputs['doc']['matrix'] = BooleanVar()
        self.outputs['doc']['matrix'].set(self.inputs['doc']['matrix'])
        self.widgets['doc']['matrix'] = Checkbutton(self.frameDoc, text='', command=self.docMatrixChanged, variable=self.outputs['doc']['matrix'], onvalue=True, offvalue=False)
        self.widgets['doc']['matrix'].grid(column=2, row=5, sticky=(W, E))

        self.outputs['doc']['summarized_matrix'] = BooleanVar()
        self.outputs['doc']['summarized_matrix'].set(self.inputs['doc']['summarized_matrix'])
        self.widgets['doc']['summarized_matrix'] = Checkbutton(self.frameDoc, text='', command=self.docSummarizedMatrixChanged, variable=self.outputs['doc']['summarized_matrix'], onvalue=True, offvalue=False)
        self.widgets['doc']['summarized_matrix'].grid(column=2, row=6, sticky=(W, E))

        self.addEntry(self.frameDoc, 'doc', 'output_file', 2, 7)


        self.addEntry(self.frameDoc, 'doc', 'company', 2, 8)
        self.addEntry(self.frameDoc, 'doc', 'partner', 2, 9)
        
        Button(self.frameDoc, text="RUN", command=self.docRun).grid(column=1, row=10, columnspan=4)

        self.addEntry(self.frameDoc, 'doc', 'txt_pie', 2, 11)
        self.addEntry(self.frameDoc, 'doc', 'txt_figure', 2, 12)
        self.addEntry(self.frameDoc, 'doc', 'txt_table', 2, 13)
        self.addEntry(self.frameDoc, 'doc', 'txt_category', 2, 14)
        self.addEntry(self.frameDoc, 'doc', 'txt_matrix', 2, 15)
        self.addEntry(self.frameDoc, 'doc', 'txt_summarized_matrix', 2, 16)
        self.addEntry(self.frameDoc, 'doc', 'txt_summarized_matrix_risks', 2, 17)
        self.addEntry(self.frameDoc, 'doc', 'txt_summarized_matrix_sum', 2, 18)
        self.addEntry(self.frameDoc, 'doc', 'txt_risk_critical', 2, 19)
        self.addEntry(self.frameDoc, 'doc', 'txt_risk_high', 2, 20)
        self.addEntry(self.frameDoc, 'doc', 'txt_risk_medium', 2, 21)
        self.addEntry(self.frameDoc, 'doc', 'txt_risk_low', 2, 22)
        self.addEntry(self.frameDoc, 'doc', 'txt_risk_info', 2, 23)
        self.addEntry(self.frameDoc, 'doc', 'txt_risk_short_critical', 4, 19)
        self.addEntry(self.frameDoc, 'doc', 'txt_risk_short_high', 4, 20)
        self.addEntry(self.frameDoc, 'doc', 'txt_risk_short_medium', 4, 21)
        self.addEntry(self.frameDoc, 'doc', 'txt_risk_short_low', 4, 22)
        self.addEntry(self.frameDoc, 'doc', 'txt_risk_short_info', 4, 23)
        self.addEntry(self.frameDoc, 'doc', 'list_risks', 2, 24)
        self.addEntry(self.frameDoc, 'doc', 'list_categories', 2, 25)

        self.addEntry(self.frameDoc, 'doc', 'regex_title', 4, 11)
        self.addEntry(self.frameDoc, 'doc', 'regex_category', 4, 12)
        self.addEntry(self.frameDoc, 'doc', 'regex_risk_level', 4, 13)
        self.addEntry(self.frameDoc, 'doc', 'regex_assessment_state', 4, 14)
        self.addEntry(self.frameDoc, 'doc', 'regex_related_risk', 4, 15)
        self.addEntry(self.frameDoc, 'doc', 'regex_recommendation', 4, 16)
        
        self.frameDoc.columnconfigure(1, weight=3, minsize=120)
        self.frameDoc.columnconfigure(2, weight=3, minsize=120)
        self.frameDoc.columnconfigure(3, weight=3, minsize=120)
        self.frameDoc.columnconfigure(4, weight=3, minsize=120)
        self.frameDoc.rowconfigure( 1, weight=3, minsize=30)
        self.frameDoc.rowconfigure( 2, weight=3, minsize=30)
        self.frameDoc.rowconfigure( 3, weight=3, minsize=30)
        self.frameDoc.rowconfigure( 4, weight=3, minsize=30)
        self.frameDoc.rowconfigure( 5, weight=3, minsize=30)
        self.frameDoc.rowconfigure( 6, weight=3, minsize=30)
        self.frameDoc.rowconfigure( 7, weight=3, minsize=30)
        self.frameDoc.rowconfigure( 8, weight=3, minsize=30)
        self.frameDoc.rowconfigure( 9, weight=3, minsize=30)
        self.frameDoc.rowconfigure(10, weight=3, minsize=30)
        self.frameDoc.rowconfigure(11, weight=3, minsize=30)
        self.frameDoc.rowconfigure(12, weight=3, minsize=30)
        self.frameDoc.rowconfigure(13, weight=3, minsize=30)
        self.frameDoc.rowconfigure(14, weight=3, minsize=30)
        self.frameDoc.rowconfigure(15, weight=3, minsize=30)
        self.frameDoc.rowconfigure(16, weight=3, minsize=30)
        self.frameDoc.rowconfigure(17, weight=3, minsize=30)
        self.frameDoc.rowconfigure(18, weight=3, minsize=30)
        self.frameDoc.rowconfigure(19, weight=3, minsize=30)
        self.frameDoc.rowconfigure(20, weight=3, minsize=30)
        self.frameDoc.rowconfigure(21, weight=3, minsize=30)
        self.frameDoc.rowconfigure(22, weight=3, minsize=30)
        self.frameDoc.rowconfigure(23, weight=3, minsize=30)
        self.frameDoc.rowconfigure(24, weight=3, minsize=30)
        self.frameDoc.rowconfigure(25, weight=3, minsize=30)

        #for child in self.frameDoc.winfo_children(): child.grid_configure(padx=5, pady=5)

    def addEntry(self, frame, section, name, column, row):
        self.outputs[section][name] = StringVar()
        self.outputs[section][name].set(self.inputs[section][name])
        self.widgets[section][name] = Entry(frame, textvariable=self.outputs[section][name])
        self.widgets[section][name].grid(column=column, row=row, sticky=(W, E))


    def setupGUI(self):
        self.window = PanedWindow(self.main, orient=HORIZONTAL)
        self.notebook = Notebook(self.main)
        

        self.setupNessusFrame();
        self.setupBurpFrame();
        self.setupAcunetixFrame();
        self.setupDocFrame();
        self.setupDocxMacroFrame();
        self.setupOdtMacroFrame();




        self.notebook.add(self.frameNessus, text='Nessus')
        self.notebook.add(self.frameBurp, text='Burp')
        self.notebook.add(self.frameAcunetix, text='Acunetix')
        self.notebook.add(self.frameDoc, text='DOC')
        self.notebook.add(self.frameDocxMacro, text='DOCX Macro')
        self.notebook.add(self.frameOdtMacro, text='ODT Macro')
        self.window.add(self.notebook)
        self.window.pack(fill=BOTH,expand=1)
        #self.setGeometry()
        return

    def getBestGeometry(self):
        ws = self.main.winfo_screenwidth()
        hs = self.main.winfo_screenheight()
        w=800 
        h=600
        x = (ws/2)-(w/2)
        y = (hs/2)-(h/2)
        g = '%dx%d+%d+%d' % (w,h,x,y)
        return g

    def setGeometry(self):
        self.winsize = self.getBestGeometry()
        self.main.geometry(self.winsize)
        return


    def quit(self):
        self.main.destroy()
        return

