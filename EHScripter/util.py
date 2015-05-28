import re
import unicodedata
import cgi
import html2text


def slugify(text, delim='-'):
    _punct_re = re.compile(r'[\t !"#$%&\'()*\-/<=>?@\[\\\]^_`{|},.\:]+')
    result = []
    for word in _punct_re.split(text.lower()):
        word = unicodedata.normalize('NFKD', word).encode('ascii', 'ignore')
        if word:
            result.append(word.decode("utf-8"))
    return delim.join(result)


def html2markdown(text, enc=False, withspaces=False):
    text=text.replace("</ul>","</ul>\n\n")
    text_lines=text.split('\n')
    return_lines=[]
    for line in text_lines:
        line=line.replace(' _',r' \_')
        line=line.replace("'_",r"'\_")
        line=line.replace(' *',r' \*')
        if line.find('&'):
            #print (line)
            #line=line.replace('&','ampulla')
            pass
        if enc:
            line = cgi.escape(line)
        converted_text=html2text.html2text(line).strip()
        #h = html2text.HTML2Text()
        #converted_text=h.handle(line).strip()
        converted_text=converted_text.replace('\\-\n','- ')
        converted_text=converted_text.replace('\\-','-')
        converted_text=converted_text.replace(r'\\_',r'\_')
        if withspaces:
            space_begin = re.compile(r'^\s+')
            space_begin_match = space_begin.search(line)
            space_end = re.compile(r'\s+$')
            space_end_match = space_end.search(line)
            space_begin_len=0
            space_end_len=0
            try:
                space_begin_len=len(space_begin_match.group())
            except Exception as e:
                pass
            try:
                space_end_len=len(space_end_match.group())
            except Exception as e:
                pass
            #return_lines.append((" "*space_begin_len)+cgi.escape(converted_text)+(" "*space_end_len))
            return_lines.append((" "*space_begin_len)+converted_text+(" "*space_end_len))
        else:
            #return_lines.append(cgi.escape(converted_text))
            return_lines.append(converted_text)

    return "\n".join(return_lines)

