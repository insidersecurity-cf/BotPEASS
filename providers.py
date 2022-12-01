# File for proviers of data used in this application

import csv
import datetime
import json
import logging
import os
import sys
import time
from pathlib import Path

import pandas as pd
import requests
import yaml
from bs4 import BeautifulSoup as BS

import bopteas



APP_DIR = Path(__file__).resolve(strict=True).parent
SAVE_DIR = APP_DIR / "output"

LAST_NEW_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
LAST_MODIFIED_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"



class CVERetrieverNVD(object):
    def __init__(self):
        self.base_url_nvd = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        # NOTE: NVD API rate limit w/o an API key: 5 requests in a rolling 30-second window (with key: 50 in 30s)
        self.url_nvd_latest = ''
        self.keywords_config_path = APP_DIR / 'config' / 'bopteas.yaml'
        self.cve_settings_file = SAVE_DIR / 'bopteas.json'
        self.mitre_exploit_file = SAVE_DIR / 'mitre_exploit_map.csv'
        #self.keywords_config_path = KEYWORDS_CONFIG_PATH
        self.cve_new_dataset = []
        self.search_scope = 'all_keywords'          # can be one of: "products", "all_keywords", "all_cves"
        self.include_high_severity = True           # Include High Severity CVE's regardless of keywords
        self.high_severity_threshold = 8.0          # Min CVSS score threshold for "high severity" scope
        self.enable_score_filtering = False         # Enable min. score for matching keywords also
        self.min_score_threshold = 6.0              # Min. score threshold for inclusion in results
        self.product_keywords = set()
        self.product_keywords_i = set()
        self.description_keywords = set()
        self.description_keywords_i = set()
        self.excluded_keywords = set()
        self.last_new_cve = datetime.datetime.now() - datetime.timedelta(days=1)
        self.last_modified_cve = datetime.datetime.now() - datetime.timedelta(days=1)
        self.time_format = "%Y-%m-%dT%H:%M:%S"

        if not os.path.exists(SAVE_DIR):
            os.makedirs(SAVE_DIR)

        # NOTE: param "hasKev" is present in CVE's that appear in CISA's Known Exploited Vulns catalog

        self.api_data_params = ['cveId', 'cvssV3Severity', 'cvssV2Severity', 'cvssV3Metrics',
            'cweId', 'hasKev', 'lastModStartDate', 'lastModEndDate', 'pubStartDate', 'pubEndDate',
            'resultsPerPage', 'startIndex', 'sourceIdentifier', 
        ]
        self.first_run()
        self.load_keywords()
        self.load_cve_settings_file()
        return
    
    def first_run(self):
        pass
        return
        
    def load_keywords(self):
        with open(self.keywords_config_path, 'r') as yaml_file:
            keywords_config = yaml.safe_load(yaml_file)
            self.search_scope = keywords_config["SEARCH_SCOPE"]
            self.include_high_severity = keywords_config["INCLUDE_HIGH_SEVERITY"]
            self.high_severity_threshold = float(keywords_config["HIGH_SEVERITY_THRESHOLD"])
            self.enable_score_filtering = keywords_config['ENABLE_SCORE_FILTERING']
            self.min_score_threshold = keywords_config['MIN_SCORE_THRESHOLD']
            self.product_keywords = keywords_config["PRODUCT_KEYWORDS"]
            self.product_keywords_i = keywords_config["PRODUCT_KEYWORDS_I"]
            self.description_keywords = keywords_config["DESCRIPTION_KEYWORDS"]
            self.description_keywords_i = keywords_config["DESCRIPTION_KEYWORDS_I"]
            self.excluded_keywords = keywords_config["EXCLUDED_KEYWORDS"]
            print("[*] Loaded search keywords from config")
        
        # Load MITRE Exploit Mapping Data
        if not os.path.exists(self.mitre_exploit_file):
            self.download_exploit_mapping()
        self.exploit_map = []
        fieldnames = ["ExploitId", "CveId"]     # The original headers of the MITRE Exploit map file
        with open(self.mitre_exploit_file, 'r') as mitre_file:
            rdr = csv.DictReader(mitre_file)
            for row in rdr:
                # Creating a list of dicts we'll use later to see if an Exploit is listed for a CVE in our results
                self.exploit_map.append({'CVE_ID': row['CveId'], 'ExploitDB_ID': row['ExploitId']})
            print("[*] MITRE Exploit-DB ID Mapping has been loaded")
        return

    def load_cve_settings_file(self):
        if not os.path.exists(self.cve_settings_file):
            print("[!] CVE Data JSON file doesn't exist yet!")
            return
        try:
            with open(self.cve_settings_file, 'r') as json_file:
                self.cve_data_fromfile = json.load(json_file)
                self.last_new_cve = datetime.datetime.strptime(self.cve_data_fromfile["LAST_NEW_CVE"],
                                                               self.time_format)
                self.last_modified_cve = datetime.datetime.strptime(self.cve_data_fromfile["LAST_MODIFIED_CVE"], 
                                                                    self.time_format)
        except Exception as e:
            print("[*] Error opening CVE Data JSON file, keeping default timestamps for search")
            pass
        return

    def update_cve_settings_file(self):
        """ Save this cycle's collection metadata for next run. """
        if not os.path.exists(self.cve_settings_file):
            print("[!] CVE Data JSON file doesn't exist, failed to save updated timestamps!")
            return
        with open(self.cve_settings_file, 'w') as json_file:
            # Update our timestamp values with the updated timestamp created via self._build_query()
            json.dump({
                "LAST_NEW_CVE": self.updated_cve_timestamp,
                "LAST_MODIFIED_CVE": self.updated_cve_timestamp,
            }, json_file)
        # with open(self.keywords_config_path, 'w') as yaml_file:
        #     yaml.dump({
        #         "LAST_NEW_CVE": self.last_new_cve.strftime(self.time_format),
        #         "LAST_MODIFIED_CVE": self.last_modified_cve.strftime(self.time_format),
        #     }, yaml_file)
        return

    def _build_query(self):
        # Query syntax for a typical grab of latest CVE's from NVD API 2.0
        # ?lastModStartDate=2022-08-04T13:00:00
        now = datetime.datetime.now()
        self.updated_cve_timestamp = now.strftime(self.time_format)
        self.last_modified_cve = self.last_modified_cve.strftime(self.time_format)
        print(f"[DBG] Query URL we are using: {self.base_url_nvd}?lastModStartDate={self.last_modified_cve}&lastModEndDate={now.strftime(self.time_format)}")
        return f"{self.base_url_nvd}?lastModStartDate={self.last_modified_cve}&lastModEndDate={self.updated_cve_timestamp}"
        return

    def get_new_cves(self):
        """ Get latest CVE's from NVD's API service and store into dict. """
        response = requests.get(self._build_query())
        #time.sleep(6)   # NVD recommends sleeping 6 secs between requests
        if response.status_code != 200:
            print("[!] Error contacting NVD API for CVEs")
            return
        nvd_json = json.loads(response.text)
        print("[DBG] API json response has been loaded into a json object")
        results_total = nvd_json["totalResults"]
        print(f"[*] {results_total} CVE's pulled from NVD for processing, please wait...")
        for v in nvd_json["vulnerabilities"]:
            #print("\n\n[DBG] Enum v: {}".format(v))
            cve_id = v["cve"]['id']
            try:
                cve_description = v['cve']['descriptions'][0]['value']
            except KeyError:
                cve_description = ''
                print("[DBG] KeyError with cve_description, raw data: {}".format(v['cve']['descriptions']))
            try:
                cvssv3_score = v['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                cvssv3_severity = v['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                cvssv3_exploitability = v['cve']['metrics']['cvssMetricV31'][0]['exploitabilityScore']
                cvssv3_impact = v['cve']['metrics']['cvssMetricV31'][0]['impactScore']
            except KeyError:
                cvssv3_score = ''
                cvssv3_severity = ''
                cvssv3_exploitability = ''
                cvssv3_impact = ''
            
            published = v['cve']['published']
            last_modified = v['cve']['lastModified']
            vuln_status = v['cve']['vulnStatus']

            try:
                cwe = v['cve']['weaknesses'][0]['description'][0]['value']
                if cwe == "NVD-CWE-noinfo":
                    cwe = ''
            except KeyError:
                cwe = ''
            # -- Fine tune our references
            exploit_references = []
            normal_references = []
            try:
                for entry in v['cve']['references']:
                    # Scrutinize what types of references we wish to include
                    if entry.get('tags') is not None:
                        if "Exploit" in entry['tags']:
                            exploit_references.append(entry['url'])
                        #if "Advisory" in entry['tags'] or "Patch" in entry['tags']:
                        if any(w in ["Third Party Advisory", "Vendor Advisory"] for w in entry['tags']):
                            normal_references.append(entry['url'])
            except KeyError:
                print("[DBG] KeyError searching references - {}".format(entry))
                pass
            record = {
                "CVE_ID": cve_id,
                "Description": cve_description,
                "CVSSv3_Score": cvssv3_score,
                "CVSSv3_Severity": cvssv3_severity,
                "CVSSv3_Exploitability": cvssv3_exploitability,
                "CVSSv3_Impact": cvssv3_impact,
                "Published": published,
                "Last_Modified": last_modified,
                "Vuln_Status": vuln_status,
                "CWE": cwe,
                "Exploit_References": exploit_references,
                "Normal_References": normal_references,
            }
            self.cve_new_dataset.append(record)
            #print("[DBG] CVE entry appended to dataset: {}".format(record))
        
        # With new dataset, run it through filtering function
        self.filter_cves()
        self.check_cve_has_exploit()
        self.update_cve_settings_file()
        return self.cve_new_dataset

    def filter_cves(self):
        filtered_cves = []
        for item in self.cve_new_dataset:
            # Which method(s) are we filtering by
            if self.search_scope == 'products':
                if self._is_prod_keyword_present(item['Description']):
                    filtered_cves.append(item)
            elif self.search_scope == 'all_keywords':
                if self._is_prod_keyword_present(item['Description']) or \
                    self._is_summ_keyword_present(item['Description']):
                    filtered_cves.append(item)
            elif self.search_scope == 'all_cves':
                return self.cve_new_dataset

            if self.include_high_severity:
                # TODO: Don't think the 2nd part of this conditional is valid, will always be True bc I'm not checking for CVE_ID in keys
                if self._cvss_score_at_above(item['CVE_ID'], item['CVSSv3_Score']) and item['CVE_ID'] not in filtered_cves:
                    print(f"[DBG] High Severity CVE ({item['CVE_ID']}) identified and including in results")
                    filtered_cves.append(item)
            
        self.cve_new_dataset = filtered_cves
        return

    def _cvss_score_at_above(self, cve, cvss_score: float):
        val = False
        if not cvss_score: 
            print(f"[DBG] {cve} has no CVSS Score")
            return val
        try:
            val = float(cvss_score) >= float(self.high_severity_threshold)
        except ValueError:
            print("[DBG] ValueError evaluating CVSS Score to threshold, CVSS Score is: {}".format(cvss_score))
        return val

    def _is_summ_keyword_present(self, summary: str):
        """ Given the summary check if any keyword is present """
        return any(w in summary for w in self.description_keywords) or \
            any(w.lower() in summary.lower() for w in self.description_keywords_i)

    def _is_prod_keyword_present(self, products: str):
        """ Given the summary check if any keyword is present """
        return any(w in products for w in self.product_keywords) or \
            any(w.lower() in products.lower() for w in self.product_keywords_i)
    
    def _is_excluded_keyword_present(self, summary: str):
        """ return True if an excluded keyword is in the summary/description. """
        return any(w in summary for w in self.excluded_keywords)

    def check_cve_has_exploit(self):
        """ Search CVE's from our results to the exploit mapping to see if an Exploit-DB ID is listed. If so, add this to the dataset. """
        if not self.cve_new_dataset or not self.exploit_map:
            print("[!] Either your new CVEs dataset or the Exploit mapping data is not loaded, skipping exploit ID search")
            return
        
        for item in self.cve_new_dataset:
            if item['CVE_ID'] in [w['CVE_ID'] for w in self.exploit_map]:
                print(f"[DBG] CVE ({item['CVE_ID']} matches an exploit ID mapping")
                for node in self.exploit_map:
                    if node['CVE_ID'] == item['CVE_ID']:
                        # TODO: Would a CVE have more than one exploit id mapping in this file?
                        item['ExploitDB_ID'] = node['ExploitDB_ID']
        
        return

    def download_exploit_mapping(self):
        """ Retrieve the current Exploit mapping from MITRE """
        url_mitre = "https://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html"
        csv_file = open(self.mitre_exploit_file, 'w')
        csv_writer = csv.writer(csv_file)
        response = requests.get(url_mitre, allow_redirects=True)
        #if response.status_code == 200:
        print(f"[*] Response: {response.status_code} - Successfully requested MITRE exploit db mapping resource")
        
        # Parse the html and extract the tables we need
        soup = BS(response.text, "html.parser")
        table = soup.find_all("table", attrs={"cellpadding": "2", "cellspacing": "2", "border": "2"})[1]
        headings = ["ExploitId", "CveId"]
        datasets = []
        for row in table.find_all("tr")[0:]:
            row = list(td.get_text() for td in row.find_all("td"))
            datasets.append(row)
        
        # Create Pandas dataframe to hold this data
        df = pd.DataFrame(datasets, columns=headings)   # Create dataframe with headings and the datasets
        df = df.astype('string')    # Convert padas objects (the default) to strings
        df.drop(df.tail(2).index, inplace=True) # Drop last two rows because they don't contain Exploit-db ID's
        df[headings[0]] = df[headings[0]].str.replace(r'\D', '') # removing the prefix "EXPLOIT-DB" from the ExploitDBId column
        df[headings[1]] = df[headings[1]].str.rstrip("\n") # removing the trailing newline from the CVEId column
        df[headings[1]] = df[headings[1]].str.lstrip(' ') # removing the leading white space from the CVEId column
        df[headings[1]] = df[headings[1]].str.split(' ') # splitting the column based on white space within the entries
        df = df.set_index([headings[0]])[headings[1]].apply(pd.Series).stack().reset_index().drop('level_1',axis = 1).rename(columns = {0: headings[1]}) # creating multiple rows for exploits that correspond to multiple CVE #'s
        print(df)
        n = len(df[headings[1]])
        csv_writer.writerow(headings)
        for i in range(n-1):
            csv_writer.writerow(df.loc[i])  # Write dataframe row to CSV file
        csv_file.close()

        df.to_json("mitre_exploit_data.json", indent=2, orient='records') # Finally, write entire dataset to json
        return

    



# NVD API Notes:
        # E.g. requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev", headers=headers)
        #kev_query = "hasKev"

        # param "keywordSearch" returns any CVE where a word or phrase is found in the description
        # param "keywordExactMatch" is a toggle, that when present in the query, finds only exact matches
        #   E.g. https://api/2.0?keywordSearch=Microsoft Outlook&keywordExactMatch

        # date values must be in ISO-8061 date/time format:
        # [YYYY]["-"][MM]["-"][DD]["T"][HH][":"][SS][Z]     ?lastModStartDate=2022-08-04T13:00:00

        # page limit / resultsPerPage - default value and max page limit is 2,000 results



if __name__ == '__main__':
    retriever = CVERetrieverNVD()
    retriever.get_new_cves()
