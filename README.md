# snortparser
Snort rule parser written in python, a work in progress. The main goal for this code is to validate snort rules and have them parsed into a workable dictionary object.

The parser class accepts a snort rule as input and returnes a dictionary that containes the parsed output.

>>> from snortparser import Parser
>>> rule = ('alert tcp $HOME_NET any -> !$EXTERNAL_NET any (msg:\"MALWARE-BACKDOOR - Dagger_1.4.0\"; flow:to_client,established; content:\"2|00 00 00 06 00 00 00|Drives|24 00|\"; depth:16; metadata:ruleset community; classtype:misc-activity; sid:105; rev:14;)')
>>> parsed = Parser(rule)
"Header"
>>> parsed.header
OrderedDict([('action', 'alert'), ('proto', 'tcp'), ('source', (True, '$HOME_NET')), ('src_port', (True, 'any')), ('arrow', '->'), ('destination', (False, '$EXTERNAL_NET')), ('dst_port', (True, 'any'))])
"Options"
>>> parsed.options
OrderedDict([(0, {'msg': ['"MALWARE-BACKDOOR - Dagger_1.4.0"']}), (1, {'flow': ['to_client', 'established']}), (2, {'content': ['"2|00 00 00 06 00 00 00|Drives|24 00|"']}), (3, {'depth': ['16']}), (4, {'metadata': ['ruleset community']}), (5, {'classtype': ['misc-activity']}), (6, {'sid': ['105']}), (7, {'rev': ['14']})])

NOTE: if the parser is unable to parse the rule, it will return a ValueError with the invalid rule item. Additionally, it does not care about misplaced spaces in the headers ip and port definitions like: "  alert tcp ![ 127.0.0.1, !8.8.8.8 ]  any --> ". This i by design, since I am not sure if snort cares about header syntax that much.

Also, keep in mind, that I have never used snort myself, nor do I know what the best practices are, this tool is written for a project and entierly based on snort documentatin.

I will update the code with few more features in the future, for example there is no code for snort preprocessor checks and I also want to write some checks to go over the rule efficiency and if it makes sense or not, basically, to go over the Notes: for every option in the snort documentation.

I hope this code is useful for someone.

Cheers!
