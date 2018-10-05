#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os,re,argparse,sys,platform
output_count,output_files = 0,0
# These are patterns and filters [Don't Edit it !!!]
regex_globals,payloads='\((.*?)(\$_FILES\[.*?\]|\$_GET\[.*?\]|\$_POST\[.*?\]|\$_REQUEST\[.*?\]|\$_COOKIES\[.*?\]|\$_SESSION\[.*?\]|\$(?!this|e-)[a-zA-Z0-9_]*)(.*?)\)',[["eval","Remote Command Execution",["escapeshellarg","escapeshellcmd"]],["popen","Remote Command Execution",["escapeshellarg","escapeshellcmd"]],["system","Remote Command Execution",["escapeshellarg","escapeshellcmd"]],["passthru","Remote Command Execution",["escapeshellarg","escapeshellcmd"]],["exec","Remote Command Execution",["escapeshellarg","escapeshellcmd"]],["shell_exec","Remote Command Execution",["escapeshellarg","escapeshellcmd"]],["assert","Remote Command Execution",["escapeshellarg","escapeshellcmd"]],["proc_open","Remote Command Execution",["escapeshellarg","escapeshellcmd"]],["call_user_func","Remote Code Execution",[]],["call_user_func_array","Remote Code Execution",[]],["preg_replace","Remote Command Execution",["preg_quote"]],["ereg_replace","Remote Command Execution",["preg_quote"]],["eregi_replace","Remote Command Execution",["preg_quote"]],["mb_ereg_replace","Remote Command Execution",["preg_quote"]],["mb_eregi_replace","Remote Command Execution",["preg_quote"]],["virtual","File Inclusion",[]],["include","File Inclusion",[]],["require","File Inclusion",[]],["include_once","File Inclusion",[]],["require_once","File Inclusion",[]],["readfile","File Inclusion / Path Traversal",[]],["file_get_contents","File Inclusion / Path Traversal",[]],["show_source","File Inclusion / Path Traversal",[]],["fopen","File Inclusion / Path Traversal",[]],["file","File Inclusion / Path Traversal",[]],["fpassthru","File Inclusion / Path Traversal",[]],["gzopen","File Inclusion / Path Traversal",[]],["gzfile","File Inclusion / Path Traversal",[]],["gzpassthru","File Inclusion / Path Traversal",[]],["readgzfile","File Inclusion / Path Traversal",[]],["mysql_query","SQL Injection",["mysql_real_escape_string"]],["mysqli_multi_query","SQL Injection",["mysql_real_escape_string"]],["mysqli_send_query","SQL Injection",["mysql_real_escape_string"]],["mysqli_master_query","SQL Injection",["mysql_real_escape_string"]],["mysqli_master_query","SQL Injection",["mysql_real_escape_string"]],["mysql_unbuffered_query","SQL Injection",["mysql_real_escape_string"]],["mysql_db_query","SQL Injection",["mysql_real_escape_string"]],["mysqli::real_query","SQL Injection",["mysql_real_escape_string"]],["mysqli_real_query","SQL Injection",["mysql_real_escape_string"]],["mysqli::query","SQL Injection",["mysql_real_escape_string"]],["mysqli_query","SQL Injection",["mysql_real_escape_string"]],["pg_query","SQL Injection",["pg_escape_string","pg_pconnect","pg_connect"]],["pg_send_query","SQL Injection",["pg_escape_string","pg_pconnect","pg_connect"]],["sqlite_array_query","SQL Injection",["sqlite_escape_string"]],["sqlite_exec","SQL Injection",["sqlite_escape_string"]],["sqlite_query","SQL Injection",["sqlite_escape_string"]],["sqlite_single_query","SQL Injection",["sqlite_escape_string"]],["sqlite_unbuffered_query","SQL Injection",["sqlite_escape_string"]],["->arrayQuery","SQL Injection",["->prepare"]],["->query","SQL Injection",["->prepare"]],["->queryExec","SQL Injection",["->prepare"]],["->singleQuery","SQL Injection",["->prepare"]],["->querySingle","SQL Injection",["->prepare"]],["->exec","SQL Injection",["->prepare"]],["->execute","SQL Injection",["->prepare"]],["->unbufferedQuery","SQL Injection",["->prepare"]],["->real_query","SQL Injection",["->prepare"]],["->multi_query","SQL Injection",["->prepare"]],["->send_query","SQL Injection",["->prepare"]],["cubrid_unbuffered_query","SQL Injection",["cubrid_real_escape_string"]],["cubrid_query","SQL Injection",["cubrid_real_escape_string"]],["mssql_query","SQL Injection",["mssql_escape"]],["move_uploaded_file","File Upload",[]],["echo","Cross Site Scripting",["htmlentities","htmlspecialchars"]],["print","Cross Site Scripting",["htmlentities","htmlspecialchars"]],["printf","Cross Site Scripting",["htmlentities","htmlspecialchars"]],["xpath","XPATH Injection",[]],["ldap_search","LDAP Injection",["Zend_Ldap","ldap_escape"]],["mail", "Insecure E-mail",[]],["unserialize", "PHP Object Injection",[]],["header","Header Injection",[]],["HttpMessage::setHeaders","Header Injection",[]],["HttpRequest::setHeaders","Header Injection",[]],["http_redirect","URL Redirection",[]],["HttpMessage::setResponseCode","URL Redirection",[]]]
#############
def style_replace(string, old, new, n):
    if string.count(old) >= n:
        left_join,right_join=old,old
        groups = string.split(old)
        sty_split = [left_join.join(groups[:n]), right_join.join(groups[n:])]
        return new.join(sty_split)
    return string.replace(old, new)
def default(path,payload,bug,line,code_text,code_line,colored,occurence):
    header = "Potential vulnerability found : {}".format(payload[1])
    line = "{} in {}".format(line,path)
    vulnerability = style_replace("".join(bug), colored, ""+colored+"", occurence)
    vulnerability = "{}({})".format(payload[0], vulnerability)
    print("Name: " + "\t"+header)
    print("Line: " + "\t"+line)
    print("Code: " + "\t"+vulnerability)
    if not "$_" in colored:
        declared = "Undeclared in the file"
        if code_text != "": declared = "Line "+code_line+" : "+ code_text
        print("Declaration  " + "\t"+declared)
    print("")
def find_line_vulnerability(path,payload,bug,content):
	content = content.split('\n')
	for i in range(len(content)):
		if payload[0]+'('+bug[0]+bug[1]+bug[2]+')' in content[i]:
			return str(i-1)
	return "-1"
def find_line_declaration(declaration, content):
	content = content.split('\n')
	for i in range(len(content)):
		if declaration in content[i]:
			return str(i)
	return "-1"
def cleanerx(content):
    content = content.replace("	"," ")
    content = content.replace("echo ","echo(")
    content = content.replace(";",");")
    return content
def check_protection(payload, match):
    for protection in payload:
		if protection in "".join(match): return True
    return False
def check_global(match):
    globals = ["_GET","_POST","_COOKIES","_REQUEST","_FILES"]
    is_global = False
    for exception1 in globals:
        if exception1 in match: return True
    return False
def check_declaration(content, vulnerability, path):
    regex_declaration = re.compile("(include.*?|require.*?)\([\"\'](.*?)[\"\']\)")
    includes = regex_declaration.findall(content)
    for include in includes:
        relative_include = os.path.dirname(path)+"/"
        try:
            path_include     = relative_include + include[1]
            with open(path_include, 'r') as f:
                content = f.read() + content
        except Exception as e:
            return (False, "","")
    regex_declaration2 = re.compile("\$(.*?)([\t ]*)as(?!=)([\t ]*)\$"+vulnerability[1:])
    declaration2 = regex_declaration2.findall(content)
    if len(declaration2) > 0: return check_declaration(content, "$"+declaration2[0][0], path)
    regex_declaration = re.compile("\$"+vulnerability[1:]+"([\t ]*)=(?!=)(.*)")
    declaration = regex_declaration.findall(content)
    if len(declaration)>0:
        code_text = "$"+vulnerability[1:] +declaration[0][0]+"="+declaration[0][1]
        line_declaration = find_line_declaration(code_text, content)
        regex_constant = re.compile("\$"+vulnerability[1:]+"([\t ]*)=[\t ]*?([\"\'(]*?[a-zA-Z0-9{}_\(\)@\.,!: ]*?[\"\')]*?);")
        false_positive = regex_constant.match(code_text)
        if false_positive: return (True, "","")
        return (False, code_text,line_declaration)
    return (False, "","")
def analysis(path):
  global output_files
  output_files += 1
  with open(path, 'r') as content_file:
    content = content_file.read()
    content = cleanerx(content)
    credz = ['pass', 'secret', 'token', 'pwd']
    for credential in credz:
         content_pure = content.replace(' ','')
         regex = re.compile("\$"+credential+".*?=[\"|'][^\$]+[\"|']", re.I)
         matches = regex.findall(content_pure)
         for vulnerability_content in matches:
             payload = ["","Hardcoded Credential",[]]
             line_vulnerability = -1
             splitted_content = content.split('\n')
             for i in range(len( splitted_content )):
                 regex = re.compile("\$"+credential+".*?=", re.I)
                 matches = regex.findall(splitted_content[i])
                 if len(matches) > 0: line_vulnerability = i
             code_text = vulnerability_content
             line_declaration = str(line_vulnerability)
             occurence = 1
             default(path, payload, vulnerability_content, line_vulnerability, code_text, line_declaration, vulnerability_content, occurence)
    for payload in payloads:
      regex   = re.compile(payload[0]+regex_globals)
      matches = regex.findall(content)
      for vulnerability_content in matches:
        occurence = 0
      	if check_protection(payload[2], vulnerability_content) == False:
            code_text, line_declaration = "",""
            sentence = "".join(vulnerability_content)
            regax = re.compile(regex_globals[2:-2])
            for vulnerabilityerable_var in regax.findall(sentence):
                false_positive = False
                occurence += 1
                if check_global(vulnerabilityerable_var[1]) == False:
                    false_positive, code_text, line_declaration = check_declaration(content, vulnerabilityerable_var[1], path)
                    false_positive = false_positive or check_protection(payload[2], code_text)==True
                line_vulnerability = find_line_vulnerability(path, payload, vulnerability_content, content)
                if not "$_" in vulnerabilityerable_var[1]:
                    if not "$" in code_text.replace(vulnerabilityerable_var[1],''):
                        false_positive = True
                if not false_positive:
                    global output_count
                    output_count = output_count + 1
                    default(path, payload, vulnerability_content, line_vulnerability, code_text, line_declaration, vulnerabilityerable_var[1], occurence)
def recursive(dir,progress):
    progress += 1
    try:
      for name in os.listdir(dir):
        print('\tScanning : '+''*progress+'\r'),
        if os.path.isfile(os.path.join(dir, name)):
            if ".php" in os.path.join(dir, name): analysis(dir+"/"+name)
        else: recursive(dir+"/"+name, progress)
    except OSError, e:
        print("Error 404 - Not Found ?")
        exit(-1)
def scanresults():
    global output_count
    global output_files
    print ("Found {} vulnerability in {} files").format(output_count,output_files)
if __name__ == "__main__":
    sy5 = platform.system()
    if 'Linux' in sy5: os.system('clear')
    if 'Windows' in sy5: os.system('cls')
    file_name = os.path.basename(__file__)
    root, ext = os.path.splitext(file_name)
    printer = '''
██████╗  █████╗ ██╗      █████╗ ███╗   ███╗   ██████╗ ██████╗  ██████╗ 
╚════██╗██╔══██╗██║     ██╔══██╗████╗ ████║   ██╔══██╗██╔══██╗██╔═══██╗
 █████╔╝███████║██║     ███████║██╔████╔██║   ██████╔╝██████╔╝██║   ██║
 ╚═══██╗██╔══██║██║     ██╔══██║██║╚██╔╝██║   ██╔═══╝ ██╔══██╗██║   ██║
██████╔╝██║  ██║███████╗██║  ██║██║ ╚═╝ ██║██╗██║     ██║  ██║╚██████╔╝
╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ 
-------------------------------------------------------------------
This Tool for Source Code Analyzing [Bugs]
Warning: The tool is not 100% accurate in finding the Bugs
-------------------------------------------------------------------
[usage]$~ '''+"{}{}".format(root,ext)+''' -d [PATH]
Ex: '''+"{}{}".format(root,ext)+''' -d /myproject/php'''
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', action ='store', dest='dir', help="Directory to analyse")
    results = parser.parse_args()
    if results.dir != None:
        print("\nAnalyzing '"+results.dir+"' source code")
        if os.path.isfile(results.dir): analysis(results.dir)
        else: recursive(results.dir,0)
        scanresults()
    else:
        print(printer)
