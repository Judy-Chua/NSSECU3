"""
Volatility 2.6.1 Python Script
---------------------------------
1) Runs 'hivelist' to find registry hive offsets
2) Dumps those hives with 'dumpregistry'
3) Processes dumped hives with RECmd
4) Searches for and dumps .evtx files with 'dumpfiles'
5) Processes dumped .evtx files with EvtxECmd

Author: CHUA, HA, MISAGAL, TELOSA
Date: 2025-02-20
"""

import os
import re
import sys
import subprocess
from pathlib import Path
import pandas as pd

def run_volatility_hivelist(volatility_path, memory_file):
    """    
    volatility_path: path to vol.py
    memory_file: path to mem dump
    profile: volatility profile
    """
    
    # python vol.py -f memory.dmp --profile=Win7SP1x64 hivelist
    cmd = [
        "py",  "-2", volatility_path,
        "-f", memory_file, 
        "imageinfo"
    ]
    profile = ""
    print(f"[INFO] Running Volatility imageinfo:\n      {' '.join(cmd)}\n")

    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=False)
        output_list = output.decode('utf-8').split('\n')
        for item in output_list:
            if "Suggested Profile(s)" in item:
                profile = item.split(":")[1].split(",")[0].strip()
                split = item.split(":")[1]
                print(f"**** Suggested Profile(s) found: {split}\n")
                
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Volatility imageinfo failed:\n{e.output}")
        sys.exit(1)
    
    cmd = [
        "py", "-2", volatility_path,
        "-f", memory_file,
        "--profile={}".format(profile),
        "hivelist"
    ]
    
    print(f"[INFO] Running Volatility hivelist:\n      {' '.join(cmd)}\n")
    
    # command run, capture
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=False)
        return [profile, output.decode("utf-8")]
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Volatility hivelist failed:\n{e.output}")
        sys.exit(1)
        

def dump_registry_hives(volatility_path, memory_file, profile, output_folder):
    """
    volatility_path: path to vol.py
    memory_file: path to the mem dump
    profile: vol profile
    offsets: extracted offsets sa hivelist
    output_folder: kung san sstore ung hive files
    """
    
    #output folder, if wala magccreate siya
    os.makedirs(output_folder, exist_ok=True)
    
    cmd = [
        "py", "-2", volatility_path,
        "-f", memory_file,
        "--profile={}".format(profile),
        "dumpregistry",
        "-D", output_folder
    ]
    
    print(f"[INFO] Dumping registry hive:\n      {' '.join(cmd)}\n")
    
    try: #run to dump registry hive
        output = subprocess.run(cmd, check=True, text=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        to_filter = output.stdout.decode("utf-8")
        filtered = []
        for line in to_filter.splitlines():
            if line.startswith("Writing out registry:"):
                filtered.append(line)
        display = "\n".join(filtered)
        print(display)
        print()
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to dump hive:\n{e}")


def process_hives_with_recmd(hive_directory, recmd_path, recmd_output_folder):
    """
    hive_directory: path to folder with dumped hive files
    recmd_path: path to recmed
    recmd_output_folder: csv logs folder
    """
    os.makedirs(recmd_output_folder, exist_ok=True)
    
    for fname in os.listdir(hive_directory):
        lower_fname = fname.lower()
        if (lower_fname.endswith(".hive") or
            lower_fname.endswith(".reg") or
            "system" in lower_fname or
            "sam" in lower_fname or
            "software" in lower_fname or
            "security" in lower_fname or
            "ntuser" in lower_fname):
            
            hive_path = os.path.join(hive_directory, fname)
            
            # .\RECmd.exe -f ".\trial_dir\registry.0xfffff8a0012bc410.ntuserdat.reg" --bn .\BatchExamples\Kroll_Batch.reb --csv out.csv
            cmd = [
                recmd_path, "-f",
                hive_path, "--bn",
                ".\BatchExamples\Kroll_Batch.reb",
                "--csv", recmd_output_folder
            ]
            
            print(f"[INFO] Processing hive '{fname}' with RECmd:\n      {' '.join(cmd)}\n")
            
            try:
                subprocess.run(cmd, check=True, text=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] RECmd failed for '{fname}':\n{e}")


def dump_evtx_files(volatility_path, memory_file, profile, evtx_dump_folder):
    """
    
    volatility_path: path to vol.py
    memory_file:     path  to the memory dump.
    profile:         volatility profile
    evtx_dump_folder: store folder for files
    """
    os.makedirs(evtx_dump_folder, exist_ok=True)
    
    # -R pwede raw to match patterns, 
    cmd = [
        "py", "-2", volatility_path,
        "-f", memory_file,
        "--profile={}".format(profile),
        "dumpfiles",
        "--r=.evtx", #regex need lagay kung nasan man ung logs
        "-D", evtx_dump_folder
    ]
    
    print(f"[INFO] Dumping .evtx files from memory:\n      {' '.join(cmd)}\n")
    
    try:
        subprocess.run(cmd, check=True, text=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        #convert all to .evtx files
        for fname in os.listdir(evtx_dump_folder):
            deconstructed_name = fname.split(".")
            deconstructed_name[-1] = "evtx"
            newname = ".".join(deconstructed_name)
            os.rename(os.path.join(evtx_dump_folder, fname), os.path.join(evtx_dump_folder, newname))
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to dump .evtx files:\n{e}")


def process_evtx_with_evtxecmd(evtx_directory, evtxecmd_path, evtx_output_folder):
    """
    evtx_directory:     folder with .evtx files.
    evtxecmd_path:      tath to evtx
    evtx_output_folder: csv / evtx files folder
    """
    os.makedirs(evtx_output_folder, exist_ok=True)
    
    #builds command
    cmd = [
        evtxecmd_path,
        "-d", evtx_directory,
        "--csv", evtx_output_folder
    ]
    
    print(f"[INFO] Processing event logs in '{evtx_directory}' with EvtxECmd:\n      {' '.join(cmd)}\n")
    
    try:
        subprocess.run(cmd, check=True, text=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] EvtxECmd failed for files in '{evtx_directory}':\n{e}")


def read_csv(folder_path):
    all_data = []
    for file in os.listdir(folder_path):
        if file.endswith(".csv"):
            file_path = os.path.join(folder_path, file)
            df = pd.read_csv(file_path)
            all_data.append(df)

    if all_data:
        return pd.concat(all_data, ignore_index=True)
    return None


def combining_files(folder1, folder2, output_file):
    df1 = read_csv(folder1)
    df2 = read_csv(folder2)

    with pd.ExcelWriter(output_file) as writer:
        if df1 is not None:
            df1.to_excel(writer, sheet_name="RECmd Output", index=False)
        if df2 is not None:
            df2.to_excel(writer, sheet_name="EvtxECmd Output", index=False)
            
    print(f"Successfully combined file saved as {output_file}")


def filter_lines(output):
	filtered = []
	for line in output.splitlines():
		if not line.startswith("*** Failed to import") and not line.startswith("Progress: "):
			filtered.append(line)
	return "\n".join(filtered)


def run_tools(memory_file, hive_dump_folder, evtx_dump_folder, recmd_output_folder, evtx_output_folder, output_filename,
              volatility_path, recmd_path, evtxecmd_path):
    # ==============================================================================
    # 1) HIVELIST
    # ==============================================================================
    print("[STEP 1] Running Volatility hivelist...")
    volatility_profile, hivelist_txt = run_volatility_hivelist(
        volatility_path=volatility_path,
        memory_file=memory_file
    )
    
    filtered = filter_lines(hivelist_txt)
    print(filtered)
    print()
    
    # ==============================================================================
    # 2) DUMP REGISTRY HIVES
    # ==============================================================================
    print("[STEP 2] Dumping registry hives...")
    dump_registry_hives(
        volatility_path=volatility_path,
        memory_file=memory_file,
        profile=volatility_profile,
        output_folder=hive_dump_folder
    )

    # ==============================================================================
    # 3) PROCESS HIVES WITH RECmd
    # ==============================================================================
    print("[STEP 3] Processing dumped hives with RECmd...")
    process_hives_with_recmd(
        hive_directory=hive_dump_folder,
        recmd_path=recmd_path,
        recmd_output_folder=recmd_output_folder
    )

    # ==============================================================================
    # 4) DUMP .EVTX FILES FROM MEMORY
    # ==============================================================================
    print("[STEP 4] Dumping .evtx files from memory with Volatility dumpfiles plugin...")
    dump_evtx_files(
        volatility_path=volatility_path,
        memory_file=memory_file,
        profile=volatility_profile,
        evtx_dump_folder=evtx_dump_folder
    )

    # ==============================================================================
    # 5) PROCESS EVTX WITH EvtxECmd
    # ==============================================================================
    print("[STEP 5] Processing extracted .evtx files with EvtxECmd...")
    process_evtx_with_evtxecmd(
        evtx_directory=evtx_dump_folder,
        evtxecmd_path=evtxecmd_path,
        evtx_output_folder=evtx_output_folder
    )
    
    # ==============================================================================
    # 6) COMBINE ALL CSV FILES INTO A SINGLE CSV FILE
    # ==============================================================================
    print("[STEP 6] Combining all CSV files into a single CSV file...")
    combining_files(
        folder1=recmd_output_folder,
        folder2=evtx_output_folder,
        output_file=output_filename
    )

    print("[INFO] All steps completed successfully!")


def call_print():
    print("****************************************************")
    print("*              ___         ___   ___          ___  *")
    print("*  \        / |     |     |     |   | |\  /| |     *")
    print("*   \  /\  /  |---  |     |     |   | | \/ | |---  *")
    print("*    \/  \/   |___  |___  |___  |___| |    | |___  *")
    print("*                                                  *")
    print("****************************************************")
    print()
    
    
def show_settings(memory_file, output_filename):
    print("====================================================")
    print("                 USER CONFIGURATION                 ")
    print("----------------------------------------------------")
    print()
    print(f"Memory File Name          = {memory_file}")
    print(f"CSV File Name             = {output_filename}")
    print("====================================================")
    print()
    
    
def show_help():
    print("====================================================")
    print("                     USER HELP                     ")
    print("----------------------------------------------------")
    print()
    print(" change Memory <filename>  = Changes current memory file name to <filename>")
    print("    *** Kindly include file type")
    print(" change CSV <filename>     = Changes current csv file name to <filename>")
    print("    *** Kindly DO NOT include .xlsx")
    print(" help                      = Displays User Help")
    print(" quit                      = Exit program")
    print(" run                       = Executes Volatility, RECmd and EvtxECmd to provide a single csv output")
    print(" settings                  = Shows current user settings")
    print("====================================================")
    print()
    
    
def main():
    """
    Main function orchestrating the entire workflow:
      1) List registry hives (hivelist).
      2) Parse offsets.
      3) Dump hives (dumpregistry).
      4) Process hives (RECmd).
      5) Dump .evtx files (dumpfiles).
      6) Process .evtx files (EvtxECmd).

    Update paths and profile to suit your environment.
    """

    # ==============================================================================
    # DEFAULT CONFIGURATION 
    # ==============================================================================
    
    # 1) Memory & Volatility
    memory_file       = "memdump.raw"
    volatility_path   = "vol.py"
    
    # # 2) Output folders
    hive_dump_folder  = "./registry_dir/"
    evtx_dump_folder  = "./evtx_dir/"
    
    # # 3) Paths to Eric Zimmerman's Tools
    recmd_path        = "./RECmd.exe"
    recmd_output_folder = "./recmd_out/"
    
    evtxecmd_path     = "./EvtxECmd.exe"
    evtx_output_folder= "./evtx_out/"
    
    # # 4) File Name
    output_filename = "Grp5s4n6Tool.xlsx"
    
    call_print()
    show_settings(memory_file, output_filename)
    show_help()
    user_input = ""
    
    while not user_input == "quit":
        user_input = input("Command: ")
        if user_input == "run":
            print()
            run_tools(memory_file, hive_dump_folder, evtx_dump_folder, recmd_output_folder, evtx_output_folder, output_filename,
                  volatility_path, recmd_path, evtxecmd_path)
            print()
        elif user_input.startswith("change Memory "):
            change = user_input.split(" ")
            memory_file = change[2]
            print("**Successfully changed memory filename to " + memory_file + "\n")
        elif user_input.startswith("change CSV "):
            change = user_input.split(" ")
            output_filename = change[2] + ".xlsx"
            print("**Successfully changed CSV filename to " + output_filename + "\n")
        elif user_input == "help":
            show_help()
        elif user_input == "quit":
            print("Thank you!\n")
        elif user_input == "settings":
            show_settings(memory_file, output_filename)
        else:
            print(">>Command does not exist!\n")

if __name__ == "__main__":
    main()
