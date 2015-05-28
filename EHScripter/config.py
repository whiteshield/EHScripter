##!/usr/bin/env python3
# -*- coding: utf-8 -*-

class DefaultConfig():
    """default input check"""
    @staticmethod
    def check(inputs={}):
        # for doc generation
        if not inputs.get('doc'):
            inputs['doc']={}
        if not inputs.get('nessus'):
            inputs['nessus']={}
        if not inputs.get('burp'):
            inputs['burp']={}
        if not inputs.get('acunetix'):
            inputs['acunetix']={}
        if not inputs.get('netsparker'):
            inputs['netsparker']={}
        if not inputs.get('doc').get('load_dir')  and inputs.get('doc').get('load_dir') != "":
            inputs['doc']['load_dir']='/projects/test/findings/final'
        if not inputs.get('doc').get('output_file')  and inputs.get('doc').get('output_file') != "":
            inputs['doc']['output_file']='/projects/test/findings/final/result.docx'
        if not inputs.get('doc').get('reference_doc') and inputs.get('doc').get('reference_doc') != "":
            inputs['doc']['reference_doc']='/projects/test/findings/final/reference.docx'
        if not inputs.get('doc').get('format')  and inputs.get('doc').get('format') != "":
            inputs['doc']['format']='docx'
        if not inputs.get('doc').get('preface_markdown_file')  and inputs.get('doc').get('preface_markdown_file') != "":
            inputs['doc']['preface_markdown_file']='/projects/test/findings/final/preface.md'
        if not inputs.get('doc').get('pie_chart') and not inputs.get('doc').get('pie_chart')==False:
            inputs['doc']['pie_chart']=True
        if not inputs.get('doc').get('matrix') and not inputs.get('doc').get('matrix')==False:
            inputs['doc']['matrix']=True
        if not inputs.get('doc').get('summarized_matrix') and not inputs.get('doc').get('summarized_matrix')==False:
            inputs['doc']['summarized_matrix']=True

        if not inputs.get('doc').get('regex_title')  and inputs.get('doc').get('regex_title') != "":
            inputs['doc']['regex_title']='^##(?P<Title>[^#]*)##'
        if not inputs.get('doc').get('regex_category')  and inputs.get('doc').get('regex_category') != "":
            inputs['doc']['regex_category']='^\*\*Category\:\*\*'
        if not inputs.get('doc').get('regex_risk_level')  and inputs.get('doc').get('regex_risk_level') != "":
            inputs['doc']['regex_risk_level']='^\*\*Risk level\:\*\*'
        if not inputs.get('doc').get('regex_assessment_state')  and inputs.get('doc').get('regex_assessment_state') != "":
            inputs['doc']['regex_assessment_state']='^\*\*Assessment state\*\*'
        if not inputs.get('doc').get('regex_related_risk')  and inputs.get('doc').get('regex_related_risk') != "":
            inputs['doc']['regex_related_risk']='^\*\*Related risk\*\*'
        if not inputs.get('doc').get('regex_recommendation')  and inputs.get('doc').get('regex_recommendation') != "":
            inputs['doc']['regex_recommendation']='^\*\*Recommendation\*\*'

        if not inputs.get('doc').get('company')  and inputs.get('doc').get('company') != "":
            inputs['doc']['company']='**Company Inc.**'
        if not inputs.get('doc').get('partner')  and inputs.get('doc').get('partner') != "":
            inputs['doc']['partner']='_Partner Inc._'
        if not inputs.get('doc').get('txt_pie')  and inputs.get('doc').get('txt_pie') != "":
            inputs['doc']['txt_pie']='Vulnerabilities'
        if not inputs.get('doc').get('txt_figure')  and inputs.get('doc').get('txt_figure') != "":
            inputs['doc']['txt_figure']='Figure'
        if not inputs.get('doc').get('txt_table')  and inputs.get('doc').get('txt_table') != "":
            inputs['doc']['txt_table']='Table'
        if not inputs.get('doc').get('txt_category')  and inputs.get('doc').get('txt_category') != "":
            inputs['doc']['txt_category']='Category'
        if not inputs.get('doc').get('txt_matrix')  and inputs.get('doc').get('txt_matrix') != "":
            inputs['doc']['txt_matrix']='Vulnerability matrix'
        if not inputs.get('doc').get('txt_summarized_matrix')  and inputs.get('doc').get('txt_summarized_matrix') != "":
            inputs['doc']['txt_summarized_matrix']='Summarized vulnerability matrix'
        if not inputs.get('doc').get('txt_summarized_matrix_risks')  and inputs.get('doc').get('txt_summarized_matrix_risks') != "":
            inputs['doc']['txt_summarized_matrix_risks']='Risks'
        if not inputs.get('doc').get('txt_summarized_matrix_sum')  and inputs.get('doc').get('txt_summarized_matrix_sum') != "":
            inputs['doc']['txt_summarized_matrix_sum']='SUM'
        if not inputs.get('doc').get('txt_risk_critical')  and inputs.get('doc').get('txt_risk_critical') != "":
            inputs['doc']['txt_risk_critical']='Critical risk issues:'
        if not inputs.get('doc').get('txt_risk_high')  and inputs.get('doc').get('txt_risk_high') != "":
            inputs['doc']['txt_risk_high']='High risk issues:'
        if not inputs.get('doc').get('txt_risk_medium')  and inputs.get('doc').get('txt_risk_medium') != "":
            inputs['doc']['txt_risk_medium']='Medium risk issues:'
        if not inputs.get('doc').get('txt_risk_low')  and inputs.get('doc').get('txt_risk_low') != "":
            inputs['doc']['txt_risk_low']='Low risk issues:'
        if not inputs.get('doc').get('txt_risk_info')  and inputs.get('doc').get('txt_risk_info') != "":
            inputs['doc']['txt_risk_info']='Informative issues:'
        if not inputs.get('doc').get('txt_risk_short_critical')  and inputs.get('doc').get('txt_risk_short_critical') != "":
            inputs['doc']['txt_risk_short_critical']='Critical'
        if not inputs.get('doc').get('txt_risk_short_high')  and inputs.get('doc').get('txt_risk_short_high') != "":
            inputs['doc']['txt_risk_short_high']='High'
        if not inputs.get('doc').get('txt_risk_short_medium')  and inputs.get('doc').get('txt_risk_short_medium') != "":
            inputs['doc']['txt_risk_short_medium']='Medium'
        if not inputs.get('doc').get('txt_risk_short_low')  and inputs.get('doc').get('txt_risk_short_low') != "":
            inputs['doc']['txt_risk_short_low']='Low'
        if not inputs.get('doc').get('txt_risk_short_info')  and inputs.get('doc').get('txt_risk_short_info') != "":
            inputs['doc']['txt_risk_short_info']='Info'
        if not inputs.get('doc').get('list_risks')  and inputs.get('doc').get('list_risks') != "":
            inputs['doc']['list_risks']='Critical,High,Medium,Low,Info'
        if not inputs.get('doc').get('list_categories')  and inputs.get('doc').get('list_categories') != "":
            inputs['doc']['list_categories']='Information Leakage,Authentication,Authorisation,Encryption,Input Validation,Server Configuration,Session Management,Other'

        # for nessus
        if not inputs.get('nessus').get('load_file')  and inputs.get('nessus').get('load_file') != "":
            inputs['nessus']['load_file']='/projects/test/nessus'
        if not inputs.get('nessus').get('merge') and not inputs.get('nessus').get('merge')==False:
            inputs['nessus']['merge']=True
        if not inputs.get('nessus').get('result_overwrite') and not inputs.get('nessus').get('result_overwrite')==False:
            inputs['nessus']['result_overwrite']=True
        if not inputs.get('nessus').get('output_dir')  and inputs.get('nessus').get('output_dir') != "":
            inputs['nessus']['output_dir']='/projects/test/findings/nessus'
        if not inputs.get('nessus').get('merge_template')  and inputs.get('nessus').get('merge_template') != "":
            inputs['nessus']['merge_template']="""##$pluginName##

**Category:** $pluginFamily  
**Risk level:** $risk_factor

**Assessment state**  
$description

Affected services:

$findinglist

**Related risk**  
N/A

**Recommendation**  
$solution

"""
        if not inputs.get('nessus').get('merge_findinglist_template')  and inputs.get('nessus').get('merge_findinglist_template') != "":
            inputs['nessus']['merge_findinglist_template']="""- $name / $port / $protocol / $svc_name

~~~
$plugin_output
~~~

"""
        if not inputs.get('nessus').get('template')  and inputs.get('nessus').get('template') != "":
            inputs['nessus']['template']="""##$name - $pluginName##

**Category:** $pluginFamily  
**Risk level:** $risk_factor

**Assessment state**  
$description

**Related risk**  
N/A

**Recommendation**  
$solution

"""





        # for burp
        if not inputs.get('burp').get('load_file')  and inputs.get('burp').get('load_file') != "":
            inputs['burp']['load_file']='/projects/test/burp'
        if not inputs.get('burp').get('merge') and not inputs.get('burp').get('merge')==False:
            inputs['burp']['merge']=True
        if not inputs.get('burp').get('result_overwrite') and not inputs.get('burp').get('result_overwrite')==False:
            inputs['burp']['result_overwrite']=True
        if not inputs.get('burp').get('output_dir')  and inputs.get('burp').get('output_dir') != "":
            inputs['burp']['output_dir']='/projects/test/findings/burp'
        if not inputs.get('burp').get('merge_template')  and inputs.get('burp').get('merge_template') != "":
            inputs['burp']['merge_template']="""##$name##

**Category:** N/A  
**Risk level:** $severity

**Assessment state**  
$issueBackground

$issueDetail

Affected services:

$findinglist

**Related risk**  
N/A

**Recommendation**  
$remediationBackground

$remediationDetail

"""
        if not inputs.get('burp').get('merge_findinglist_template')  and inputs.get('burp').get('merge_findinglist_template') != "":
            inputs['burp']['merge_findinglist_template']="""- $host$location

~~~
$issueDetail

$issueDetailItems
~~~

"""
        if not inputs.get('burp').get('template')  and inputs.get('burp').get('template') != "":
            inputs['burp']['template']="""##$host - $name##

**Category:** N/A  
**Risk level:** $severity

**Assessment state**  
$issueBackground

$issueDetail

**Related risk**  
N/A

**Recommendation**  
$remediationBackground

$remediationDetail

"""







        # for acunetix
        if not inputs.get('acunetix').get('load_file')  and inputs.get('acunetix').get('load_file') != "":
            inputs['acunetix']['load_file']='/projects/test/acunetix'
        if not inputs.get('acunetix').get('merge') and not inputs.get('acunetix').get('merge')==False:
            inputs['acunetix']['merge']=True
        if not inputs.get('acunetix').get('result_overwrite') and not inputs.get('acunetix').get('result_overwrite')==False:
            inputs['acunetix']['result_overwrite']=True
        if not inputs.get('acunetix').get('output_dir')  and inputs.get('acunetix').get('output_dir') != "":
            inputs['acunetix']['output_dir']='/projects/test/findings/acunetix'
        if not inputs.get('acunetix').get('merge_template')  and inputs.get('acunetix').get('merge_template') != "":
            inputs['acunetix']['merge_template']="""##$Name##

**Category:** $Type  
**Risk level:** $Severity

**Assessment state**  
$Description

Affected links:

$findinglist

**Related risk**  
$Impact

**Recommendation**  
$Recommendation

"""
        if not inputs.get('acunetix').get('merge_findinglist_template')  and inputs.get('acunetix').get('merge_findinglist_template') != "":
            inputs['acunetix']['merge_findinglist_template']="""- $StartURL - $Affects

~~~
$Details
~~~

"""
        if not inputs.get('acunetix').get('template')  and inputs.get('acunetix').get('template') != "":
            inputs['acunetix']['template']="""##$Name - $Affects##

**Category:** $Type  
**Risk level:** $Severity

**Assessment state**  
$Details

$Description

**Related risk**  
$Impact

**Recommendation**  
$Recommendation

"""




        # for netsparker
        if not inputs.get('netsparker').get('load_file')  and inputs.get('netsparker').get('load_file') != "":
            inputs['netsparker']['load_file']='/projects/test/netsparker'
        if not inputs.get('netsparker').get('merge') and not inputs.get('netsparker').get('merge')==False:
            inputs['netsparker']['merge']=True
        if not inputs.get('netsparker').get('result_overwrite') and not inputs.get('netsparker').get('result_overwrite')==False:
            inputs['netsparker']['result_overwrite']=True
        if not inputs.get('netsparker').get('output_dir')  and inputs.get('netsparker').get('output_dir') != "":
            inputs['netsparker']['output_dir']='/projects/test/findings/netsparker'
        if not inputs.get('netsparker').get('merge_template')  and inputs.get('netsparker').get('merge_template') != "":
            inputs['netsparker']['merge_template']="""##$Vulnerability##

**Category:** N/A  
**Risk level:** $Risk

Affected links:

$findinglist

**Assessment state**  
$VulnDesc

**Related risk**  
N/A

**Recommendation**  
N/A

"""
        if not inputs.get('netsparker').get('merge_findinglist_template')  and inputs.get('netsparker').get('merge_findinglist_template') != "":
            inputs['netsparker']['merge_findinglist_template']="""- $SubVulnerability - $Link

$ParamTable

"""
        if not inputs.get('netsparker').get('template')  and inputs.get('netsparker').get('template') != "":
            inputs['netsparker']['template']="""##$Vulnerability - $Target - $SubVulnerability##

**Category:** N/A  
**Risk level:** $Risk

- $SubVulnerability - $Link

$ParamTable

**Assessment state**  
$VulnDesc

**Related risk**  
N/A

**Recommendation**  
N/A

"""






        return inputs


