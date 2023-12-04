import os
import re
import textfsm
import pandas as pd
from datetime import datetime
error_var = 0
log_lst = []
maste_data_dict = {"HOSTNAME":[], "PROTOCOL": [],"SOURCE NAMEDIF": [],"SRC IP": [], 'SRC PORT': [], 'SRC MAC': [], 'SRC VENDOR' : [], 
                    "DEST NAMEDIF": [],"DEST IP": [], 'DEST PORT': [],'DEST MAC': [], 'DEST VENDOR': [], "IDLE": [],"TIME": [],
                   "BYTES": [],"FLAGS": [], 'DEST VIA': []}
def get_value(key):
    ''' gets variable values from settings file.
        MAKE SURE TO PUT THE RIGHT SETTINGS FILE PATH '''
    key = key
    with open("settings.txt") as settings_file:
            settings_file = settings_file.read()
    if '#' in settings_file.split(key)[0].split("\n")[-1]:
        msg = 'value is commented out'
        #print(msg)
        return None
    else:
        #var = settings_file.split(key)[1].split("\n")[0].strip(" ").strip("\"").strip("\'")
        #print(key)
        unstriped = settings_file.split(key)[1].split("\n")[0].strip()
        #print(unstriped[0])
        if unstriped.lower()[0] ==  '[' and unstriped.lower()[-1] == ']':
            var1 = unstriped.strip('[').strip(']').split(',')
            var = [e.strip().strip("'").strip('"') for e in var1]
            return var
        elif '"' == unstriped[0]  or '"' == unstriped[-1] or "'" == unstriped[0]  or "'" == unstriped[-1]:
            #print("is string")
            var = unstriped.strip("\"").strip("\'")
            return var
        elif  unstriped.isnumeric():
            var = int(unstriped)
            return var
        elif unstriped.lower() == 'true':
            var = True
            return var
        elif unstriped.lower() ==  'false':
            var = False
            return var
        else:
            print(f"{unstriped} -invalid variable set in settings") 
def pull_hostname(data):
    try:
        data = data
        hostname2 = data.split("#")
        hostname3 = hostname2[0].split("\n")
        hostname_fin = hostname3[-1]
        hostname_fin = hostname_fin.strip()
        print(f" hostname ({hostname_fin})")
        return hostname_fin
    except:
        print(f"ERROR!!! -pull_hostname()- ADVANCE Contact Purple")
def initializ_spliter():
    #para_fname 
    try:
        inpt_path = sys.argv[1]      #path=
        if inpt_path == '-f':
            inpt_path = get_value('inpt_path=')
            inpt_path = F'path={inpt_path}'
        print('________')
        #print(inpt_path)
        ####################################################################################
        if "path=" in inpt_path:
            path= inpt_path.split("path=")
        else:
            inpt_path = get_value('inpt_path=')
            path = ["", inpt_path]
            print("""--[path] argument issue. this should point to the files inside the folder.
            make sure the format is [name_edit.py path="{path}" replace="{word_to_find_in_file_name}" with="{new_word_to_place}"--
            """)
    except:
        try:
            print('getting input(s) path from settings.txt')
            inpt_path = get_value('inpt_path=')
            path = ["", inpt_path] # DELETE
        except: 
            print("""--CHECK settings.txt if path is a correct format.""")
    return path
def list_file_names():
    try:
        #print("!!!!!!!!!!!")
        #print(path[1])
        directory = path[1].strip("\"") ### 
        #print(directory)
        file_list = []
        for filename in os.scandir(directory):
            if filename.is_file():
                filename_str = r"{}".format(filename)
                file_list.append(filename_str.split("'")[1])
        return file_list
    except:
        print("ERROR -list_file_names()-")
def update_log():
    date_now = datetime.now().strftime("%m-%d-%y_%H-%M-%S") 
    logs = "\n".join(log_lst)
    if os.path.exists(f'{root}\\logs'): 
        pass
    else:    
        os.mkdir(f'{root}\\logs')
    #print(root)
    with open(f'{root}\\logs\\log_{date_now}.txt', 'w') as f:
        f.write(logs)
def calc_depth(root):
    root = root
    master_lst = []
    master_lst.append(root)
    for path in master_lst:
        for e in os.listdir(path):
            p = f'{path}\\{e}'
            if os.path.isdir(p):
                #print(p)
                master_lst.append(p)
    return len(master_lst[-1].split(root)[1].split('\\')) 
def find_mac_and_oui(ip):
    ip = f'{ip} '
    try:
        mac = arp_data.split(ip)[1].split('\n')[0].split()[0].upper()
        mac_halfa = mac[0:4]+mac[5:7]
        org = oui_data.split(mac_halfa)[1].split('\n')[0].split('(base 16)')[1].strip()
    except:
        mac = ''
        org = ''
    return mac, org
if __name__ == '__main__':
    try:
        os.chdir(root)
    except:
        pass
    root = os.getcwd()
    #root = os.getcwd()
    try:
        path = initializ_spliter()
    except:
        #print("--error initializ_spliter()")
        log_lst.append("--error initializ_spliter()")
        update_log()
    try:
        f_lst = list_file_names()
    except:
        #print("--error list_file_names()")
        log_lst.append("--error list_file_names()")
        update_log()
    with open(f'oui.txt',  encoding="utf8") as f:
        oui_data = f.read()
    levels_list = []
    first_level = []
    branches_found_list = []
    print(path[1])
    path_fix = path[1].strip('"')
    first_level.append(path_fix)
    levels_list = {}
    for ctr in range(calc_depth(path[1])):
        print(ctr+1)
        levels_list[str(ctr+1)] = []
    levels_list['1'].append(first_level)
    mac_ip_map_list = []
    ######################################################################################
    for i, level_lst in levels_list.items():        
        #i = i + 1
        log_lst.append(f"(splitter_key_1)------------------------------DIRECTORY LEVEL-{i}-------------------------------------------------")
        print(f'-------------------------------------------------------------------------------- LEVEL {i}')
        update_log()
        #next_key = int(i) + 1
        #levels_list[f'{next_key}'] = []
        for level_lst in level_lst:
            print('-------')
            for path_fix in level_lst:
                log_lst.append(f"DIR-----{path_fix}")
                update_log()
                path_fix_temp = f"{path_fix}"
                path_fix = path_fix_temp
                dir_list = os.chdir(f"{path_fix}")
                if len(os.listdir(dir_list)) > 0:
                    for f_name in os.listdir(dir_list):
                        try:
                            if os.path.isdir(f_name):
                                gate = 0
                            else:
                                gate = 1
                        except:
                            print(f"error-- gate_var - {f_name}")
                            log_lst.append(f"error-- gate_var - {f_name}")
                            update_log()
                        if gate == 1:
                            ####################################################################### regex area
                            log_lst.append(f"--PROCESSING [{f_name}]")
                            update_log()
                            if ".txt" in f_name or ".log" in f_name:
                                try:
                                    txt_file = open(f_name, "r")
                                    print(f"----opening [{f_name}]")
                                    log_lst.append(f"----opening [{f_name}]")
                                    update_log()
                                    text = txt_file.read()
                                    txt_file.close()
                                except:
                                    print("error opening file-- it expects .txt or .log---- saving this file name")
                                    log_lst.append("error opening file-- it expects .txt or .log---- saving this file name")
                                    update_log()
                                    log_lst.append(f" BAD file --{f_name}")
                                    update_log()
                                host_nam = pull_hostname(text) ############################# !!!!!!!!!!! HOSTNAME !!!!!!!!!!
                                ######################################
                                print("pulling data..")
                            ############################################################## here we pull the data from the txt
                            comnd = 0
                            patt = "#*\s*[sS][hH]\S*\s+[cC][oO][nN]\S*\s*\n" #<<<<< ReGEX for all shortcut of show connection
                            match = re.findall(patt , text)
                            arp_patt = "#*\s*[sS][hH]\S*\s+[aA][rR][pP]\s*\n" #<<<<< ReGEX for all shortcut of show arp
                            arp_match = re.findall(arp_patt , text)
                            arp_data = text.split(arp_match[0])[1].split('#')[0]
                            try:
                                comnd = match[0]
                            except:
                                break
                            fsm_results = []
                            i = 0
                            if comnd != 0:
                                sh_conn_text = text.split(comnd)[1].split("#")[0]
                                #print(sh_conn_text)
                                template = open(fr"{root}\template\cisco_asa_sh_conn.textfsm") 
                                re_table = textfsm.TextFSM(template)
                                print("Parsing data..")
                                fsm_results = re_table.ParseText(sh_conn_text)    
                                #print(fsm_results)
                                if len(fsm_results) > 0: ################################ storing data
                                    for data in fsm_results:
                                        maste_data_dict["HOSTNAME"].append(host_nam)
                                        maste_data_dict["PROTOCOL"].append(data[0])
                                        maste_data_dict["SOURCE NAMEDIF"].append(data[1])
                                        maste_data_dict["SRC IP"].append(data[2].split(':')[0])
                                        maste_data_dict["SRC PORT"].append(data[2].split(':')[1])
                                        ip_temp = data[2].split(':')[0]
                                        src_mac, src_org = find_mac_and_oui(ip_temp)
                                        maste_data_dict["SRC MAC"].append(src_mac)
                                        maste_data_dict["SRC VENDOR"].append(src_org)
                                        maste_data_dict["DEST NAMEDIF"].append(data[3])
                                        maste_data_dict["DEST IP"].append(data[4].split(':')[0])
                                        maste_data_dict["DEST PORT"].append(data[4].split(':')[1])
                                        ip_temp = data[4].split(':')[0]
                                        dest_mac, dest_org = find_mac_and_oui(ip_temp)
                                        maste_data_dict["DEST MAC"].append(dest_mac)
                                        maste_data_dict["DEST VENDOR"].append(dest_org)
                                        maste_data_dict["IDLE"].append(data[5])
                                        maste_data_dict["TIME"].append(data[6])
                                        #maste_data_dict["8"].append(data[7])
                                        maste_data_dict["BYTES"].append(data[8])
                                        #maste_data_dict["10"].append(data[9])
                                        maste_data_dict["FLAGS"].append(data[10])
                                        maste_data_dict["DEST VIA"].append('')
                                else:
                                    print("--no data was pulled during textfsm process")
                                    log_lst.append(f"--no data was pulled during textfsm process")
                                    update_log()
                            ####################################################################### ^^^^^^^^^^^^^^^^^^^^
                            else:
                                print("no [sh conn] or [show connection] command found")
                                log_lst.append(f"--no [sh conn] or [show connection] command found")
                                update_log()                 
                        else:
                            if os.path.isdir(f_name):
                                log_lst.append(f"--(NEW PATH FoUND!) -- recording path [{f_name}]")
                                update_log()
                                print(f"""((SKIPED))-- "{f_name}" this is a [FOLDER]""")
                                branch = os.getcwd().split("\\")
                                ii = len(root) - len(branch)
                                num = ii * -1
                                current_branch = branch[num:]   ### temp value ##################################
                                current_branch = "\\".join(current_branch)
                                current_branch_temp =   fr"{current_branch}"
                                current_branch =   current_branch_temp
                                found_branch_dir  = f"{current_branch}\\{f_name}"
                                branches_found_list.append(found_branch_dir)
                            else:
                                print(f"""SHOULD BE IMPOSSIBLE TO GET HERE""")
                    try:            
                        key = len(branches_found_list[0].split(path[1])[1].split('\\'))
                        levels_list[f'{key}'].append(branches_found_list)   
                        branches_found_list = [] #to empty the list
                    except:
                        pass
                    '''for lev in levels_list:
                        if len(lev) == 0:
                            indx = levels_list.index(lev)
                            del levels_list[indx]'''
                    branches_found_list = [] #to empty the list
                os.chdir(root)
                #print(os.getcwd())
                #print(levels_list)
        print("_"*80)
    os.chdir(root)
    update_log()
    print('\n\n')
    print("_"*80)
    print('saving..')
    df = pd.DataFrame(data = maste_data_dict)
    date_now = datetime.now().strftime("%m-%d-%y_%H-%M-%S")
    out_file_name = f'sh_conn_DATA_{date_now}.csv'
    df.to_csv(out_file_name)
    print('saved..')
    print(out_file_name)