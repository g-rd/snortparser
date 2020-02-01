from snortparser import *

rules = [
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


