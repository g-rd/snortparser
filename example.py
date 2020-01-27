from snortparser import *

rules = [
'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Metushy forumclubs C2 format1 20141217"; flow:to_server,established; content:"/index.htm?id="; http_uri; pcre:"/\/index\.htm\?id=\d{5}\&content=[a-zA-Z0-9]{34}"; reference:md5,801854f83a2d2855387074072d645886; sid:9173306; rev:20170131; reference:url,cti.cert.europa.eu/index.php/mnuthreatobject/indicatorslist/details/83/4965;)',
'alert tcp "86.188.201.96/28" any -> $EXTERNAL_NET [80, 443, 8080, 9090] (msg:"NCSC-FI Possible Havex custom C2 protocol - DCBA"; flow:established,to_server; dsize:<10; content:"DCBA DCBA "; depth:8; rawbytes; fast_pattern; classtype:trojan-activity; sid:9873447; rev:20170131; reference:url,cti.cert.europa.eu/index.php/mnuthreatobject/indicatorslist/details/83/3026; gid:1; )',
'alert tcp ![86.188.201.96/28, !67.226.140.64/27,67.226.143.16/29,213.81.68.176/28,149.99.251.200/29,98.129.117.104/29,64.15.137.168/29,184.107.89.160/29,209.53.113.0/24,92.198.36.46] $HTTP_PORTS -> $HOME_NET any (msg:"CrowdStrike Computrace LoJack Handshake Response"; flow:established,to_client; pcre: "/TAGID: [0-9]{1,10}/H"; content: "Content-Length: 15|0d0a|"; http_raw_header; file_data; content: "|7E FF FF FF FF 04 00|"; depth: 7; classtype: trojan-activity; metadata: service http; sid: 15170029; rev: 20170608;)',
'alert tcp !["$HOME_NET", "!127.0.0.1", ![ !$HOME_NET, 192.168.2.2  ]] any -> !$EXTERNAL_NET any (msg:\"MALWARE-BACKDOOR - Dagger_1.4.0\"; flow:to_client,established; content:\"2|00 00 00 06 00 00 00|Drives|24 00|\"; depth:16; metadata:ruleset community; classtype:misc-activity; sid:105; rev:14;)',
'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"CrowdStrike PUTTERPANDA HTTPCLIENT Request 6"; flow:to_server, established; content:"/MicrosoftUpdate/WWRONG/KB"; modifier:http_uri; content:"/default.asp?tmp="; within:35; modifier:http_raw_uri; classtype:trojan-activity; metadata:service http; sid:7226429; rev:20170606;)',
'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Metushy forumclubs C2 format1 20141217"; flow:to_server,established; content:"/index.htm?id="; http_uri; pcre:"\/index\.htm\?id=\d{5}\&content=[a-zA-Z0-9]{34}"; reference:md5,801854f83a2d2855387074072d645886; sid:9173306; rev:20170131; reference:url,cti.cert.europa.eu/index.php/mnuthreatobject/indicatorslist/details/83/4965;)',
'alert tcp any any -> any any (msg:"Non-Std TCP Client Traffic contains "HX1|3a|" "HX2|3a|" "HX3|3a|" "HX4|3a|" (PLUGX Variant)"; sid:7238331; rev:20170428; flow:established,to_server; content:"Accept|3a 20 2a 2f 2a|"; nocase; content:"HX1|3a|"; distance:0; within:6; fast_pattern; content:"HX2|3a|"; nocase; distance:0; content:"HX3|3a|"; nocase; distance:0; content:"HX4|3a|"; nocase; distance:0; classtype:nonstd-tcp; threshold:type limit, track by_src, count 1 , seconds 60;priority:X; reference:url,cti.cert.europa.eu/index.php/mnuthreatobject/indicatorslist/details/83/12844; gid:1;)',
'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg: "CrowdStrike Possible Empire Powershell C2 Request"; flow: to_server,established; content: "GET /login/process.php HTTP/1.1|0d 0a|Cookie: session="; depth:49; content: "=|0d 0a|User-Agent: Mozilla/5.0 (Windows NT 6.1\\; WOW64\\; Trident/7.0\\; rv:11.0) like Gecko|0d 0a|Host: "; offset:76; depth:91; content: "Connection: Keep-Alive|0d 0a 0d 0a|"; classtype: trojan-activity; sid:8001380; rev:20190308;)',
'alert tcp $HOME_NET ANY -> $EXTERNAL_NET $HTTP_PORTS (msg: "CrowdStrike VOODOO BEAR VBS Backdoor [CSIT-18082]"; flow: established, to_server; content: "POST"; http_method; content: "Content-Type:|20|application/x-www-form-urlencoded"; http_header; content: "ui=en-US&"; http_client_body; depth: 9; content: "_LinkId="; http_client_body; within: 13; classtype: trojan-activity; metadata: service http; sid:8001209; rev:20180523; reference:url,falcon.crowdstrike.com/intelligence/reports/CSIT-18082;)'
]


def filter_out(rules):
    sanitize = Sanitizer().sanitize
    for rule in rules:
        parsed = Parser(rule).all
        sanitize(parsed)

        # for index, option in parsed["options"].items():
            # remove gid from rule
            # if "gid" in option:
            #         parsed["options"].pop(index)
            # if "threshold" in option:
            #     print(parsed["options"][index])

        serialized = SerializeRule(parsed)
        orig = "***: {}".format(rule)
        serial = "+++: {}".format(str(serialized))

        # print(orig)
        # print(serial)


filter_out(rules)


