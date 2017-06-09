from snortparser import Parser, FlattenRule
#rule = ('alert tcp !["$HOME_NET", "!127.0.0.1", ![ !$HOME_NET, 192.168.2.2  ]] any -> !$EXTERNAL_NET any (msg:\"MALWARE-BACKDOOR - Dagger_1.4.0\"; flow:to_client,established; content:\"2|00 00 00 06 00 00 00|Drives|24 00|\"; depth:16; metadata:ruleset community; classtype:misc-activity; sid:105; rev:14;)')
rule = ('alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"CrowdStrike PUTTERPANDA HTTPCLIENT Request 6"; flow:to_server, established; content:"/MicrosoftUpdate/WWRONG/KB"; modifier:http_uri; content:"/default.asp?tmp="; within:35; modifier:http_raw_uri; classtype:trojan-activity; metadata:service http; sid:7226429; rev:20170606;)')
parsed = Parser(rule)
print parsed.options

flatten = FlattenRule(parsed)
print flatten.get_rule()

