#!/usr/bin/env python

import argparse
import os

import requests

from core.epss import EPSSGopher
from notifiers import generate_new_cve_message, send_slack_mesage, send_telegram_message
from providers import CVERetrieverNVD

DEBUG = False


# def enrich_with_epss(dataset):
#     """
#     From provided dataset of new CVE's pulled down from NVD, see if each has an EPSS score
#     and add it as a key to the dataset.
    
#     dataset:

#     """
#     gopher = EPSSGopher()

#     for id,record in enumerate(dataset):





#     return dataset




def main():
    parser = argparse.ArgumentParser(description="BOT to monitor new CVE's and send notifications as a customized vulnerability feed")
    parser.add_argument('-t', '--testing', action='store_true',
                        help='Run bot in console for testing, skipping writes to file')
    args = parser.parse_args()


    retriever = CVERetrieverNVD(testing=args.testing)
    data = retriever.get_new_cves()
    github_query_addendum = retriever.gitdork_excluded_repos_string
    if data:
        if DEBUG: print("[DBG] data keys: {}".format(data[0].keys()))
        for item in data:
            # item is dict with keys: CVE_ID, CVSSv3_Score, Published, Description, ExploitDB_ID
            #  Exploit_References, Normal_References
            public_exploits = ''
            cve_message = generate_new_cve_message(item, github_addendum=github_query_addendum)
            if item.get('ExploitDB_ID') is not None:
                print(f"[*] CVE *with Exploit-db ID* Message:\n{cve_message}")
            else:
                print(f"[*] CVE Message:\n{cve_message}")
            send_slack_mesage(cve_message)
        
        print(f"[*] {len(data):,d} new CVE's to report this collection cycle")
    else:
        print("[-] No new CVE's matching your search scope for this collection cycle")
    
    #if retriever.cve_new_dataset:
        #print("[*] Can also leverage this class attribute of the dataset. Pulled {} CVE's".format(len(retriever.cve_new_dataset)))
        #pass
    return


if __name__ == '__main__':
    main()
