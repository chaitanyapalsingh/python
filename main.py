import git
import os
import subprocess
from logger.logger import CustomLogger, CodeTrigger, LogType
# from config import ProjectID , LoggerInstance
from config import APP_VERSION,APP_ID
import json
import datetime

class FileHandler:
    def createSysFolders(output_folderpath):
        if not os.path.exists(os.path.join(os.getcwd(), output_folderpath)): 
            os.makedirs(os.path.join(os.getcwd(), output_folderpath), exist_ok=True)
        
def update_repo(dir_path):  
        try:
            logger.write(CodeTrigger.Property, LogType.Info, f"cve repository pull required")
            command = "git pull origin main"
            subprocess.run(command, capture_output=True, text=True, cwd=dir_path)
            logger.write(CodeTrigger.Property, LogType.Info, f"cve repository updated")
            return True
        except Exception as e:
            logger.write(CodeTrigger.Property, LogType.Error, f"cve repository pull request failed {e}")
            return False

def clone_repo(dir_path):
        logger.write(CodeTrigger.Property, LogType.Info, f"clonning the git repo of cve")
        repo_url = 'https://github.com/CVEProject/cvelistV5.git'
        try:
            git.Repo.clone_from(repo_url, dir_path)
            logger.write(CodeTrigger.Property, LogType.Info, f"cve repository clonned successfully")
            return True
        except Exception as e:
            logger.write(CodeTrigger.Property, LogType.Error, "cve repository clonned failed error -->",f"{e}")
            return False


def check_new_updation(new_log_file,delta_json_path):           
    # new_log_file=os.path.join(os.getcwd(),"delta_log.json") 
    try:
        with open(delta_json_path, 'r') as f:            
            predefined_data = json.load(f)
            # print(predefined_data,"----> local data")               
            fetch_time=predefined_data['fetchTime'] 
    except Exception as e:
        logger.write()
        local_data = []
    # Load predefined JSON data
    empty_json=False
    with open(new_log_file,"r") as file:
        try:
            data = file.read()
            # Check if the JSON object is empty
            if not data.strip():                  
                empty_json=True
            else:
                empty_json= False
        except Exception as e:
            logger.write(CodeTrigger.Property, LogType.Error, "The data is not updated.",e)
    if empty_json :
        with open(new_log_file, 'w') as f:
            json.dump(predefined_data, f, indent=4)
            return True
    try:
        with open(delta_json_path, 'r') as f:
            predefined_data_local = json.load(f)
            fetch_time_local=predefined_data_local['fetchTime'] 
    except Exception as e  :
        logger.write(CodeTrigger.Property, LogType.Error, f"file not found",e)
        exit()
    # # fetch_time_local = local_data[0]['fetchTime']
    # if fetch_time == fetch_time_local:
    #     logger.write(CodeTrigger.Property, LogType.Info, "The data is not updated.")
    #     return False
    if fetch_time > fetch_time_local:
        logger.write(CodeTrigger.Property, LogType.Info, "The data is updated.")
        local_data.insert(0, predefined_data)
        # Write the updated local_data back to the file
        with open(new_log_file, 'w') as f:
            json.dump(local_data, f, indent=4)
        return True
        
def process_deltajson_file(delta_json_path):
    new_cve_list=[]
    update_cve_list=[]
    try:
        with open(delta_json_path, 'r') as f:
            json_data = json.load(f)
            logger.write(CodeTrigger.Property, LogType.Info, "delta.json file loaded")
            logger.write(CodeTrigger.Property, LogType.Info, "start fetching data from delta.json file")
            # Process "new" CVEs
            if "new" in json_data:
                new_cvs=json_data["new"]
                for cve_id in new_cvs:
                    new_cve_list.append(cve_id["cveId"])

            # Process "updated" CVEs
            if "updated" in json_data:
                update_cvs=(json_data["updated"])                    
                for cve_id in update_cvs:
                    update_cve_list.append(cve_id["cveId"])

    except Exception as e:
        logger.write(CodeTrigger.Property, LogType.Error, f"Error loading JSON file: {str(e)}")   
    return new_cve_list,update_cve_list

def write_to_json(cve_id,new_json_data,json_path):

    now = datetime.datetime.now()
    dt_string = now.strftime("%d-%m-%Y_%H%M")
    filename = f"{cve_id}_{dt_string}.json"
    filepath = os.path.join(json_path, filename)

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(new_json_data, f, indent=4)
    logger.write(CodeTrigger.Property, LogType.Info, f"JSON File created")
    

def data_fetch(json_file,cve_id,json_file_path,cve_status,cve_status_value):
    try:
        with open(json_file, "r") as f:
            data = json.load(f)
            new_json_data = {
                "cve_status": cve_status,
                "cve_status_number": cve_status_value,
                **data
            }
            # short_description = data.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value")
            # product_targeted = data.get("containers", {}).get("cna", {}).get("affected", [{}])[0].get("vendor")
            # product_version = data.get("containers", {}).get("cna", {}).get("affected", [{}])[0].get("versions", [{}])[0].get("version")
            # date_published = data.get("cveMetadata", {}).get("datePublished")
            # formatted_date_published = datetime.datetime.strptime(date_published, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d") if date_published else None
            # json_data = {
            #     "CVE ID" : cve_id,
            #     "short_description": short_description,
            #     "product_targeted": product_targeted,
            #     "product_version": product_version,
            #     "formatted_date_published": formatted_date_published
            # }

            write_to_json(cve_id,new_json_data,json_file_path)
    except Exception as e:
        logger.write(CodeTrigger.Property, LogType.Error, f"Error processing JSON file {json_file}: {str(e)}")


def process_cve_list(new_cve_list,update_cve_list,cve_path,json_file_path):
    for cve_id in new_cve_list:
        cve_year = cve_id[4:8]
        cve_status = "new"
        cve_status_value = 1
        # years_path = os.path.join(local_repo_path, 'cves')
        year_folder_path = os.path.join(cve_path, cve_year)

        if os.path.isdir(year_folder_path):
            for series in os.listdir(year_folder_path):
                json_file = os.path.join(year_folder_path, series, cve_id + '.json')
                if os.path.exists(json_file):
                    data_fetch(json_file,cve_id,json_file_path,cve_status,cve_status_value)

    for cve_id in update_cve_list:
        cve_year = cve_id[4:8]
        cve_status = "updated"
        cve_status_value = 0
        # years_path = os.path.join(local_repo_path, 'cves')
        year_folder_path = os.path.join(cve_path, cve_year)

        if os.path.isdir(year_folder_path):
            for series in os.listdir(year_folder_path):
                json_file = os.path.join(year_folder_path, series, cve_id + '.json')
                if os.path.exists(json_file):
                    data_fetch(json_file,cve_id,json_file_path,cve_status,cve_status_value)


if __name__=='__main__':
    
    # Create all folders
    logs_folder_path = """logs\\"""
    files_folder_path = """SysFiles\\files""" 
    transferred_logs = """transferred_logs\\"""
    FileHandler.createSysFolders(logs_folder_path)
    FileHandler.createSysFolders(files_folder_path)
    FileHandler.createSysFolders(transferred_logs)

    current_path=os.getcwd()
    dir_list = os.listdir(current_path)

    username = "shruti.dadhich@izoologic.com"
    # Initialize logger
    global logger
    logger = CustomLogger(storageName="StorageA", appId=APP_ID, runTimeArgument=None, appVersion=APP_VERSION,
                    projectId=1, serverId= None, isServerEnvironment=True, userName = username)
    # LoggerInstance(logger, CodeTrigger, LogType)
    if 'delta_log.json' not in dir_list:
        open('delta_log.json', 'w').close()
        
    # fetch all required paths and store in a variable 
    dir_path=os.path.join(current_path, "cvelistV5") 
    delta_json_path=os.path.join(current_path, "cvelistV5","cves","delta.json") 
    cve_path=os.path.join(current_path, "cvelistV5","cves") 
    json_file_path = os.path.join(current_path,"SysFiles\\files")
    new_Log_File = os.path.join(current_path,'delta_log.json')

    if "cvelistV5" in dir_list:
        # new pull required
        clone_pull_status=update_repo(dir_path)
    else:
        # running first time , clone of repo required
        clone_pull_status=clone_repo(dir_path)

    # check point to get the status of pull request
    if clone_pull_status:
        check_new_updation_status = check_new_updation(new_Log_File,delta_json_path)
        if check_new_updation_status:
            # deltajson_file_path=dir_path=os.path.join(current_path, "cvelistV5","cves","delta.json")
    
            new_cve_list , update_cve_list = process_deltajson_file(delta_json_path)
            if new_cve_list  or update_cve_list  :
                json=process_cve_list(new_cve_list , update_cve_list ,cve_path,json_file_path)
        else :
            logger.write(CodeTrigger.Property, LogType.Error,"Delta file is not updated")
    else:
        logger.write(CodeTrigger.Property, LogType.Error,f"Error fetching CVE repository")
logger.write(CodeTrigger.Property, LogType.Info,"Process Completed")