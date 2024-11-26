# Alma User Note Remover.pyw
# Remove user notes matching a specified pattern from a list of primary ID's.
# Meredith Foster, mfoster@wcupa.edu, 8/2019
# Corrected a problem that only occurs on Python 3.9 10/2020.

# UI Handling
import tkinter as tk
import tkinter.ttk as ttk
from tkinter.filedialog import *
from tkinter.scrolledtext import *
from tkinter.messagebox import *
from tkinter.font import *

# API handling
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
import socket
import urllib.parse
import xml.etree.ElementTree as etree

# INI File
import configparser

# Threading - background processing of API calls to avoid locking the UI
import threading

# Regular expression matching, to be sure to match the specified pattern.
import re

# For debugging, not used in production
#from xml.dom import minidom

def write_status(txt):
    we_statustext.configure(state=tk.NORMAL)
    we_statustext.insert(tk.END, txt)
    we_statustext.configure(state=tk.DISABLED)
    we_statustext.see(tk.END)
    tl_window.update_idletasks()

def write_status_bold(txt):
    we_statustext.configure(state=tk.NORMAL)
    we_statustext.insert(tk.END, txt, ('tobold',))
    we_statustext.tag_config('tobold', font=bold_font)
    we_statustext.configure(state=tk.DISABLED)
    we_statustext.see(tk.END)
    tl_window.update_idletasks()

def loadfile_press():
    global idlist
    
    filename = askopenfilename(filetypes=[('Text File (*.txt)', 'TXT'), ('CSV File (*.csv)', 'CSV'), ('All Types (*.*)', '*')], title='Select ID input file')
    
    if filename == '':
        write_status('No file selected (user canceled)\n\n')
        return
        
    load_file.set(filename)
        
    with open(filename, 'r') as fp:
        idlist = fp.read().splitlines()
        
    write_status('Read ' + str(len(idlist)) + ' ID numbers from ' + filename + '\n')

def setup_pattern():
    # Popup callbacks
    def acceptbutton_cb():
        # These need to be declared global to allow this function to assign them
        global regex_pattern
        global api_key
        global api_host
        global case_insensitive
        
        pattern = v_pattern.get()
        if pattern != '':
            # First, make sure the pattern is actually valid, if not, cancel the setup and don't change the configuration
            try:
                pat = re.compile(pattern) # Don't care about the case sensitive flag here, all we want to do is make sure the regex is valid
            except re.error as e:
                write_status_bold('Invalid pattern specified: ' + e.pattern + '\n')
                write_status_bold('Message: ' + e.msg + '\n')
                write_status_bold('Canceling setup.\n\n')
                setupbox.destroy()
            regex_pattern = pattern
            config['Pattern']['regex'] = pattern
            pattern_str.set(pattern)
        case_i = v_case.get()
        if case_i == 0:
            config['Pattern']['case_insensitive'] = 'no'
            case_insensitive = False
            we_bf_caselb.configure(text='Case Sensitive Pattern (default)')
        else:
            config['Pattern']['case_insensitive'] = 'yes'
            case_insensitive = True
            we_bf_caselb.configure(text='Case Insensitive Pattern')
        host = v_api_host.get()
        if host != '':
            api_host = host
            config['API']['api_host'] = host
            # otherwise leave the host as is
        key = v_api_key.get()
        if key != '':
            api_key = key
            config['API']['api_key'] = key
        
        try:
            with open('alma-user-note-remover-settings.ini', 'w') as fp:
                config.write(fp)
        except IOError:
            messagebox.showerror('Write Error', 'Unable to write INI File')
        setupbox.destroy()
        
    def cancelbutton_cb():
        setupbox.destroy()
        
    setupbox = tk.Toplevel()
    setupbox.geometry('900x600')
    setupbox.transient(tl_window)
    setupbox.wm_title('Set up pattern')
    setupbox.rowconfigure(4, weight=1)
    setupbox.columnconfigure(1, weight=1)
    setupbox.protocol('WM_DELETE_WINDOW', cancelbutton_cb)
    
    # Widgets here
    sb_apihost_lb = ttk.Label(setupbox, text='API Host')
    v_api_host = tk.StringVar()
    v_api_host.set(api_host)
    sb_apihost = ttk.Entry(setupbox, textvariable=v_api_host, exportselection=0)
    sb_apikey_lb = ttk.Label(setupbox, text='API Key')
    v_api_key = tk.StringVar()
    v_api_key.set(api_key)
    sb_apikey = ttk.Entry(setupbox, textvariable=v_api_key, exportselection=0)
    sb_pattern_lb = ttk.Label(setupbox, text='Regular Expression Pattern')
    v_pattern = tk.StringVar()
    v_pattern.set(regex_pattern)
    sb_pattern = ttk.Entry(setupbox, textvariable=v_pattern, exportselection=0)
    v_case = tk.IntVar()
    if case_insensitive:
        v_case.set(1)
    else:
        v_case.set(0)
    sb_case = ttk.Checkbutton(setupbox, text='Use the Pattern in a Case Insensitive Manner', variable=v_case)
    sb_accept = ttk.Button(setupbox, text='Accept Changes', command=acceptbutton_cb)
    sb_cancel = ttk.Button(setupbox, text='Cancel', command=cancelbutton_cb)
    sb_apihost_lb.grid(row=0, column=0, sticky=tk.W+tk.E)
    sb_apihost.grid(row=0, column=1, sticky=tk.W+tk.E)
    sb_apikey_lb.grid(row=1, column=0, sticky=tk.W+tk.E)
    sb_apikey.grid(row=1, column=1, sticky=tk.W+tk.E)
    sb_pattern_lb.grid(row=2, column=0, sticky=tk.W+tk.E)
    sb_pattern.grid(row=2, column=1, sticky=tk.W+tk.E)
    sb_case.grid(row=3, column=1, sticky=tk.W+tk.E)
    sb_accept.grid(row=5, column=0, sticky=tk.W+tk.E)
    sb_cancel.grid(row=5, column=2, sticky=tk.W+tk.E)
    
    docstring = """Set the API Host to the your regional API server name.  The general name is api-XX.hosted.exlibrisgroup.com\n
where XX is one of eu, na, ap, ca, or cn.\n\n
Set an API key with production read/write permissions to the Users API.\n\n
Set a pattern to limit what notes will be removed for the given group of Primary ID's.  The pattern is a regular expression.\n
To remove all notes for a user, use the pattern: .*\n\n
The pattern is by default case sensitive, where capitalization matters.  Click the checkbox to use the pattern in a case\n
insensitive manner."""
    sb_docs = tk.Label(setupbox, text=docstring, relief=tk.RIDGE, anchor=tk.NW, justify=tk.LEFT, padx=2, pady=2) # Use the non-ttk version for simpler access to the style
    sb_docs.grid(row=4, column=0, columnspan=3, sticky=tk.W+tk.E+tk.N+tk.S, padx=4, pady=4)
    
    tl_window.wait_window(setupbox)

def run_press():
    if load_file.get() == '':
        write_status("No file of ID's was selected.\n")
        return
    if len(idlist) == 0:
        write_status("ID File contains no valid ID's.\n")
        
    # Once the checks are done, create a thread to run the API handling under, this way it doesn't hang the UI and you can see your progress.
    api_thread = threading.Thread(target=update_users)
    api_thread.start()
    
def update_users():
    global regex_pattern
    # First, pre-compile the regex pattern for use below
    try:
        if case_insensitive:
            pat = re.compile(regex_pattern, flags=re.IGNORECASE)
        else:
            pat = re.compile(regex_pattern)
    except re.error as e:
        write_status_bold('Invalid pattern specified: ' + e.pattern + '\n')
        write_status_bold('Message: ' + e.msg + '\n\n')
        return
    
    i = 1
    for id in idlist:
        if not id.isalnum():
            write_status('ID ' + id + ' is not alphanumeric, skipping.\n')
            continue
    
        # https://api-na.hosted.exlibrisgroup.com/almaws/v1/users/045647?apikey=xxxx
        url = 'https://' + api_host + '/almaws/v1/users/' + id + '?apikey=' + api_key
        request = Request(url)
        request.get_method = lambda: 'GET'
        
        try:
            response = urlopen(request, timeout=30)
        except HTTPError as e:
            if e.code == 400:
                errdata = e.file.read().decode('utf-8')
                if ('Invalid API Key' in errdata) or ('appropriate apikey as a param' in errdata):
                    write_status_bold('API Key not present or invalid: ' + api_key + '\n\n')
                else:
                    print(errdata)
                    write_status_bold('ID ' + id + ' not found.\n')
                    i += 1
                    # If an ID is not found, go to the next one.  Otherwise return.
                    continue
            elif e.code == 401:
                # Does not come up as expected due to the design of the Alma API.
                write_status_bold('API Key not present or invalid: ' + api_key + '\n\n')
            else:
                write_status_bold('Unknown HTTP Error, code: ' + str(e.code) + ' ' + str(e.reason) + '\n\n')
            return
        except URLError as e:
            write_status('Connection error: ' + str(e.reason) + '\n\n')
            return
            
        response_body = response.read()
        userrec = etree.fromstring(response_body) # userrec points to <user>

        notefound = False
        toremove = []
        rolesremove = []
        for subs in userrec: # Everything at the top level under <user>
            if subs.tag == 'user_notes':
                for notes in subs: # all <user_note> tags here
                    if 'segment_type' in notes.attrib:
                        if notes.attrib['segment_type'] == 'Internal':
                            for ncontents in notes:
                                if ncontents.tag == 'note_text':
                                    if pat.match(ncontents.text) != None:
                                        write_status('('+str(i)+') Found matching internal user note, text: ' + ncontents.text + '\n')
                                        toremove.append(notes)
                                        notefound = True
                                    else:
                                        write_status('('+str(i)+') Non-matching internal user note, text: ' + ncontents.text + '\n')
                for x in toremove:
                    subs.remove(x)
                    
            # User roles can cause serious problems with the user write.  Not including a roles block
            # will cause Alma to not touch existing roles, so it's safest just to remove them from the
            # user record that will be POST'ed.
            elif subs.tag == 'user_roles':
                rolesremove.append(subs)
        for x in rolesremove:
            userrec.remove(x)
        
        ## This segment is for debugging purposes, to display the XML to be sure nothing unexpected is changed.
        ## Uncomment the include xml.dom line to use it.
        # tstr = etree.tostring(userrec, encoding='unicode', short_empty_elements=False)
        # reparsed = minidom.parseString(tstr)
        # pstr = reparsed.toprettyxml(indent='    ')
        # write_status(pstr + '\n\n')

        # Here is where the rewritten userrec is sent back to the API in a PUT statement.
        if notefound == False:
            write_status('(' + str(i) + ') ID ' + str(id) + ' does not contain a specified note, skipping.\n\n')
            i += 1
            continue # If no note has been found, skip this record and go to the next.
        
        # PUT cannot reuse the same URL defined above, it doesn't accept the API key as a parameter, must be put into a header field.
        puturl = 'https://' + api_host + '/almaws/v1/users/' + id
        headers = {}
        headers['Content-Type'] = 'application/xml'
        putrequest = Request(puturl, 
                            data=bytes(etree.tostring(userrec, encoding='unicode', short_empty_elements=False), encoding='utf-8'),
                            headers=headers, method='PUT')
        putrequest.add_header('Authorization', 'apikey '+api_key)
        
        try:
            response = urlopen(putrequest, timeout=30)
        except HTTPError as e:
            write_status_bold('(' + str(i) + ') Error found for user ID: ' + str(id) + '\n')
            if e.code == 400:
                errdata = e.file.read().decode('utf-8')
                if ('Invalid API Key' in errdata) or ('appropriate apikey as a param' in errdata):
                    write_status_bold('API Key not present or invalid: ' + api_key + '\n\n')
                else:
                    write_status_bold('HTTP Error returned\n')
                    write_status_bold(str(e) + '\n')
                    write_status_bold(errdata + '\n\n')
                    i += 1
                    continue
            elif e.code == 401:
                # Does not come up as expected due to the design of the Alma API.
                write_status_bold('API Key not present or invalid: ' + api_key + '\n\n')
            else:
                write_status_bold('Unknown HTTP Error, code: ' + str(e.code) + ' ' + str(e.reason) + '\n\n')
            return
        except URLError as e:
            write_status_bold('(' + str(i) + ') Error found for user ID: ' + str(id) + '\n')
            write_status('Connection error: ' + str(e.reason) + '\n\n')
            return
            
        # I don't really care about the respone variable here.
       
        write_status('(' + str(i) + ') ID ' + str(id) + ' processed.\n\n')
        i += 1

    write_status("All ID's processed\n\n")
    
tl_window = tk.Tk()
tl_window.title('Alma User Note Remover')
tl_window.geometry('1024x768')
# For window scaling and resizing...
tl_toplevel = tl_window.winfo_toplevel()
tl_toplevel.rowconfigure(1, weight=1)
tl_toplevel.columnconfigure(0, weight=1)

std_font = Font(family='Helvetica', size=10)
bold_font = Font(family='Helvetica', size=10, weight='bold')

# The buttons and text elements are in a frame to avoid making the overall UI handling too difficult.
we_buttonframe = ttk.Frame(tl_window)
we_buttonframe.columnconfigure(1, weight=1)
we_bf_setup = ttk.Button(we_buttonframe, text='Setup Pattern', command=setup_pattern)
we_bf_caselb = ttk.Label(we_buttonframe, text='')
pattern_str = tk.StringVar()
pattern_str.set('') # This will be filled in below when the INI file is loaded
we_bf_pattern = ttk.Entry(we_buttonframe, textvariable=pattern_str, exportselection=0, state='readonly')
we_bf_loadfile = ttk.Button(we_buttonframe, text='Select ID List', command=loadfile_press)
load_file = tk.StringVar()
load_file.set('')
we_bf_loadstr = ttk.Entry(we_buttonframe, textvariable=load_file, exportselection=0, state='readonly')
we_bf_run = ttk.Button(we_buttonframe, text='Run Cleanup', command=run_press)
we_bf_caselb.grid(column=0, row=0, sticky=tk.W+tk.E)
we_bf_setup.grid(column=3, row=0, sticky=tk.W+tk.E)
we_bf_pattern.grid(column=1, row=0, columnspan=2, sticky=tk.W+tk.E)
we_bf_loadfile.grid(column=0, row=1, sticky=tk.W+tk.E)
we_bf_loadstr.grid(column=1, row=1, columnspan=2, sticky=tk.W+tk.E)
we_bf_run.grid(column=3, row=1, sticky=tk.N+tk.S)
we_buttonframe.grid(column=0, row=0, sticky=tk.W+tk.E, padx=2, pady=2)

# A scrolledtext to log actions
we_statustext = ScrolledText(tl_window, wrap=tk.WORD, state=tk.DISABLED)
we_statustext.grid(column=0, row=1, sticky=tk.N+tk.W+tk.E+tk.S, padx=2, pady=2)

# Variables to drive the rest of the program
idlist = []

config = configparser.ConfigParser()
try:
    with open('alma-user-note-remover-settings.ini', 'r') as f:
        config.read_file(f)
except IOError:
    messagebox.showerror('No INI File', 'No INI File detected')
    sys.exit()

api_key = config['API']['api_key']
api_host = config['API']['api_host']
regex_pattern = config['Pattern']['regex']
case_insensitive = config['Pattern'].getboolean('case_insensitive')
if case_insensitive:
    we_bf_caselb.configure(text='Case Insensitive Pattern')
else:
    we_bf_caselb.configure(text='Case Senstivie Pattern (default)')

pattern_str.set(regex_pattern)

tl_window.update_idletasks()
tl_window.mainloop()
