from snortparser import Parser, FlattenRule, Sanitizer
#rule = ('alert tcp !["$HOME_NET", "!127.0.0.1", ![ !$HOME_NET, 192.168.2.2  ]] any -> !$EXTERNAL_NET any (msg:\"MALWARE-BACKDOOR - Dagger_1.4.0\"; flow:to_client,established; content:\"2|00 00 00 06 00 00 00|Drives|24 00|\"; depth:16; metadata:ruleset community; classtype:misc-activity; sid:105; rev:14;)')
#rule = ('alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"CrowdStrike PUTTERPANDA HTTPCLIENT Request 6"; flow:to_server, established; content:"/MicrosoftUpdate/WWRONG/KB"; modifier:http_uri; content:"/default.asp?tmp="; within:35; modifier:http_raw_uri; classtype:trojan-activity; metadata:service http; sid:7226429; rev:20170606;)')
#rule = ('alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Metushy forumclubs C2 format1 20141217"; flow:to_server,established; content:"/index.htm?id="; http_uri; pcre:"\/index\.htm\?id=\d{5}\&content=[a-zA-Z0-9]{34}"; reference:md5,801854f83a2d2855387074072d645886; sid:9173306; rev:20170131; reference:url,cti.cert.europa.eu/index.php/mnuthreatobject/indicatorslist/details/83/4965;)')
rule = ('alert tcp any any -> any any (msg:"Non-Std TCP Client Traffic contains "HX1|3a|" "HX2|3a|" "HX3|3a|" "HX4|3a|" (PLUGX Variant)"; sid:7238331; rev:20170428; flow:established,to_server; content:"Accept|3a 20 2a 2f 2a|"; nocase; content:"HX1|3a|"; distance:0; within:6; fast_pattern; content:"HX2|3a|"; nocase; distance:0; content:"HX3|3a|"; nocase; distance:0; content:"HX4|3a|"; nocase; distance:0; classtype:nonstd-tcp; threshold:type limit, track by_src, count 1 , seconds 60;priority:X; reference:url,cti.cert.europa.eu/index.php/mnuthreatobject/indicatorslist/details/83/12844; gid:1;)')
#rule = ('alert tcp ![86.188.201.96/28,67.226.140.64/27,67.226.143.16/29,213.81.68.176/28,149.99.251.200/29,98.129.117.104/29,64.15.137.168/29,184.107.89.160/29,209.53.113.0/24,92.198.36.46] $HTTP_PORTS -> $HOME_NET any (msg:"CrowdStrike Computrace LoJack Handshake Response"; flow:established,to_client; pcre: "/TAGID: [0-9]{1,10}/H"; content: "Content-Length: 15|0d0a|"; http_raw_header; file_data; content: "|7E FF FF FF FF 04 00|"; depth: 7; classtype: trojan-activity; metadata: service http; sid: 15170029; rev: 20170608;)')
#parsed = Parser(rule).all
##print parsed.options
#for index, option in parsed['options'].iteritems():
#    if "gid" in option:
#        parsed['options'].pop(index)
#flatten = FlattenRule(parsed)
#print rule
#print flatten.get_rule()

rule = ('alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Metushy forumclubs C2 format1 20141217"; flow:to_server,established; content:"/index.htm?id="; http_uri; pcre:"/\/index\.htm\?id=\d{5}\&content=[a-zA-Z0-9]{34}"; reference:md5,801854f83a2d2855387074072d645886; sid:9173306; rev:20170131; reference:url,cti.cert.europa.eu/index.php/mnuthreatobject/indicatorslist/details/83/4965;)')

#rule = ('alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"NCSC-FI Possible Havex custom C2 protocol - DCBA"; flow:established,to_server; dsize:<10; content:"DCBA DCBA "; depth:8; rawbytes; fast_pattern; classtype:trojan-activity; sid:9873447; rev:20170131; reference:url,cti.cert.europa.eu/index.php/mnuthreatobject/indicatorslist/details/83/3026; gid:1; )')

def filter_out(rule):
    sanitize = Sanitizer().sanitize
    parsed = Parser(rule).all
    sanitize(parsed)
    for index, option in parsed["options"].iteritems():
        # remove gid from rule
        if "gid" in option:
                parsed["options"].pop(index)
        if "threshold" in option:
            parsed["options"][index]["threshold"] = "new"
    flatten = FlattenRule(parsed) 
    return flatten.get_rule()
filter_out(rule)
