# snortparser

> This is a fork of snortparser by g-rd. The original repo can be found at https://github.com/g-rd/snortparser.

Snort rule parser written in python. The main goal for this library is to validate snort rules and have them parsed into a workable dictionary object. A interactive python notebook can be found [here](example.ipynb).

The parser class accepts a snort rule as input and returns a dictionary that contains the parsed output.

```python
from snortparser import Parser

# define a snort rule
rule = ('alert tcp $HOME_NET any -> !$EXTERNAL_NET any (msg:\"MALWARE-BACKDOOR - Dagger_1.4.0\"; flow:to_client,established; content:\"2|00 00 00 06 00 00 00|Drives|24 00|\"; depth:16; metadata:ruleset community; classtype:misc-activity; sid:105; rev:14;)')

# parse the rule
parsed = Parser(rule)

# print the parsed rule
print(parsed.header)
print(parsed.options)
```

**NOTE**: If the parser is unable to parse the rule, it will return a `ValueError` with the invalid rule item. Additionally, it does not care about misplaced spaces in the headers ip and port definitions like: " alert tcp ![ 127.0.0.1, !8.8.8.8 ] any --> ". This is by design, since I am not sure if snort cares about header syntax that much.
