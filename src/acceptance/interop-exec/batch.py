#!/usr/bin/env python3
"""Run the two distinct owned legacy CLI scenarios once; stop on first failure."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ["prepared","styx","signed-host","publisher-key","evidence"]:parser.add_argument("--"+name,required=True,type=Path)
    parser.add_argument("--tls-style",choices=["legacy-selfsigned","standard-chain"],default="legacy-selfsigned")
    args=parser.parse_args();os.umask(0o077)
    output=args.evidence.absolute();output.mkdir(parents=True,exist_ok=False)
    checks=[];start=time.monotonic()
    for case in ["graceful","disconnect"]:
        command=[sys.executable,"-B",str(Path(__file__).with_name("run.py")),"--case",case,"--tls-style",args.tls_style,"--evidence",str(output/case)]
        for key in ["prepared","styx","signed_host","publisher_key"]:command.extend(["--"+key.replace("_","-"),str(getattr(args,key).resolve(strict=True))])
        with (output/f"{case}.stdout.log").open("wb") as stdout,(output/f"{case}.stderr.log").open("wb") as stderr:
            result=subprocess.run(command,stdout=stdout,stderr=stderr)
        receipt=output/case/"receipt.json"
        checks.append({"case":case,"command":command,"exit":result.returncode,"receipt_sha256":hashlib.sha256(receipt.read_bytes()).hexdigest() if receipt.exists() else None})
        if result.returncode:break
    summary={"schema":1,"status":"PASS" if len(checks)==2 and all(item["exit"]==0 and json.loads((output/item["case"]/"receipt.json").read_text())["status"]=="PASS" for item in checks) else "FAIL","checks":checks,"elapsed_seconds":time.monotonic()-start,"scope":"actual owned Linux Rust CLI and original legacy Gateway interoperability; not package, onboarding, account or cross-platform acceptance"}
    (output/"receipt.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps(summary));raise SystemExit(0 if summary["status"]=="PASS" else 1)
if __name__=="__main__":main()
