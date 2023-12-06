import os
import yara
import argparse as agp
from typing import List, Dict, Union
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from itertools import chain
from collections import defaultdict
from pprint import pprint

def compile_rules(rulefile_to_use: str, rules_directory: str) -> yara.Rules:
    """
    Compiles the rules using the Yara library.

    Args:
        rulefile_to_use: The name of the rule file to be compiled.
        rules_directory: The path to the directory containing the rule files.

    Returns:
        The compiled Yara rules.
    """
    rules_file_path = os.path.abspath(os.path.join(rules_directory, rulefile_to_use))
    rules = yara.compile(rules_file_path)
    return rules

def scan_file(file_to_scan, rules) -> List[Union[yara.Match, None]]:
    """
    This function scans a given file against a set of rules using the YARA library. It returns a list of matches which consists of instances of the "yara.Match" class or "None" if no matches were found.

    Parameters:
        - file_to_scan (str): The file path or file-like object to be scanned.
        - rules (yara.Rules): The rules to be used for scanning.
    
    Returns:
        - List[Union[yara.Match, None]]: A list of matches found in the file, or an empty list if no matches were found.
    
    Exceptions:
        - Exception: If an error occurs during the scanning process, an error message will be printed with the specific error details.
    """
    try:
        any_match = rules.match(file_to_scan)
        if any_match:
            return any_match
        return []
    except Exception as e:
        print(f"Error occured: {e}")

def scan_directory(directory, rules: List[yara.Rules], threads: int = 2) -> Dict[str, List[Union[str, None]]]:
    """
    This function scans a directory and its subdirectories for files that match a given set of rules. It utilizes multithreading to increase the scanning efficiency. The function returns a dictionary that maps the names of files and directories to the matches found within them.

    Parameters:
        - directory (str): The path of the directory to be scanned.
        - rules (List[Rules]): A list of rules to be used for scanning.
        - threads (int, optional): The number of threads to be used for scanning. Default is 2.

    Returns:
        - Dict[str, List[Union[str, None]]]: A dictionary mapping the names of files and directories to the matches found within them. The matches are represented by a list of strings that contain the match details, or "None" if no matches were found.

    Exceptions:
        - Exception: If an error occurs during the scanning process, an error message will be printed with the specific error details."""
    try:
        contents = os.listdir(directory)
        if not contents:
            return {}

        result_map = defaultdict(list)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for content_name in contents:
                content_absolute_path = os.path.join(os.path.abspath(directory), content_name)
                if os.path.isfile(content_absolute_path):
                    for rule_chunk in rules:
                        futures.extend(executor.submit(scan_file, content_absolute_path, rule) for rule in rule_chunk)
                else:
                    dir_result = scan_directory(content_absolute_path, rules, threads)
                    result_map[content_name].append(dir_result)

            for future in tqdm(as_completed(futures), colour="green", total=len(futures), desc=f"Scanning [{content_name}]"):
                match = future.result()
                if match:
                    result_map[content_name].extend(match)

        return dict(result_map)
    except Exception as e:
        print(f"Something Went Wrong: {e}")

def main():
    parser = agp.ArgumentParser(description="Malicious File Scanner using Yara Rules")
    parser.add_argument('-rdp', '--rules_directory_path', required=True)
    parser.add_argument('-d', '--directory')
    parser.add_argument('-f', '--file')
    parser.add_argument('-T', '--threads', type=int, default=5)
    options = parser.parse_args()

    rules_dir = options.rules_directory_path
    rules = os.listdir(rules_dir)

    rule_objects = [compile_rules(rule, rules_dir) for rule in rules]
    rules_chunks = np.array_split(rule_objects, options.threads)

    if options.file:
        matched_rules = []
        with ThreadPoolExecutor(max_workers=options.threads) as executor:

            futures = []
            for rule_chunk in tqdm(rules_chunks, desc="Processing rules", colour="cyan", smoothing=0.2):
                futures.extend(executor.submit(scan_file, options.file, rule) for rule in rule_chunk)

            for future in tqdm(as_completed(futures), colour="green", total=len(futures), desc="Collecting results"):
                result = future.result()
                if result:
                    matched_rules.append(result)

    # Print or use the matched rules
        pprint([x.rule for x in chain(*matched_rules)])
    
    elif options.directory:
        pprint(scan_directory(options.directory, rules_chunks, options.threads), indent=2)


if __name__ == '__main__':
    main()