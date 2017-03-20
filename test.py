from snortparser import Parser
rule = ('alert tcp !["$HOME_NET", "!127.0.0.1", ![ !$HOME_NET, 192.168.2.2  ]] any -> !$EXTERNAL_NET any (msg:\"MALWARE-BACKDOOR - Dagger_1.4.0\"; flow:to_client,established; content:\"2|00 00 00 06 00 00 00|Drives|24 00|\"; depth:16; metadata:ruleset community; classtype:misc-activity; sid:105; rev:14;)')
parsed = Parser(rule)
print parsed.header
