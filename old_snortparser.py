#!/bin/pythionast.literal_eval

# Nothing to configure - Check out usage()
# ----------------------------------------------
import re
import collections
from dicts import Dicts
from utils import Utils


class Parser(object):
    '''
    this will take an array of lines and parse it and hand
    back a dictionary
    NOTE: if you pass an invalid rule to the parser,
    it will a raise ValueError.
    '''

    def __init__(self, rule=None):
        if rule:
            self.dicts = Dicts()
            self.rule = rule
            self.utils = Utils()
            self.header = self.parse_header()
            self.options = self.parse_options()
            self.validate_options(self.options)
            self.data = {"header": self.header, "options": self.options}
            self.all = self.data

    def __iter__(self):
        yield self.data

    def __getitem__(self, key):
        if key is 'all':
            return self.data
        else:
            return self.data[key]

    def actions(self, action):

        actions = {"alert": "alert",
                   "log": "log",
                   "pass": "pass",
                   "activate": "activate",
                   "dynamic": "dynamic",
                   "drop": "drop",
                   "reject": "reject",
                   "sdrop": "sdrop"
                   }

        if action in actions:
            return actions[action]
        else:
            msg = "Invalid action specified %s" % action
            raise ValueError(msg)

    def proto(self, proto):

        protos = {"tcp": "tcp",
                  "udp": "udp",
                  "icmp": "icmp",
                  "ip": "ip"
                  }

        if proto in protos:
            return protos[proto]
        else:
            msg = "Unsupported Protocol %s " % proto
            raise ValueError(msg)

    def _ip_list(self, iplist):
        # returns a list of tuples with
        # correct truth table mark
        if isinstance(iplist, list):
            ip_tested = []
            ip_not = None
            for ip in iplist:

                if re.match("^!", ip):
                    ip_not = False
                    ip = ip.strip("!")
                else:
                    ip_not = True

                if isinstance(ip, list):
                    continue

                if not self.dicts.ip_variables(ip):
                    test_ip = self.utils.valid_ip(ip)
                    if test_ip:
                        ip = (ip_not, ip)
                        ip_tested.append(ip)
                elif self.dicts.ip_variables(ip):
                    ip_tested.append(ip)
                else:
                    msg = "Invalid ip %s" % ip
                    raise ValueError(msg)

            ip = ip_tested
            return ip
        else:
            return False

    def ip(self, ip):
        print "got input %s" % ip
        ifnot = None
        variables = {"$EXTERNAL_NET": "$EXTERNAL_NET",
                     "$HTTP_SERVERS": "$HTTP_SERVERS",
                     "$INTERNAL_NET": "$INTERNAL_NET",
                     "$SQL_SERVERS": "$SQL_SERVERS",
                     "$SMTP_SERVERS": "$SMTP_SERVERS",
                     "$DNS_SERVERS": "$DNS_SERVERS",
                     "$HOME_NET": "$HOME_NET",
                     "HOME_NET": "HOME_NET",
                     "any": "any"}

        # notip is the source marked as not
        if re.match("^!", ip):
            ifnot = False
            ip = ip.strip("!")
        else:
            ifnot = True

        # is the source described as a list of ips
        # if it is, then make it a list from the string

        ip_list = False
        if re.match("^\[", ip):
            ip_list = True
            print "list %s" % ip

        # Snort allows for nesting of lists
        # oh snap, will this horror not end ?!!!
        # customer: "Can I have 3 lists in one snort ip list?"
        # Rick: "Best I can do is 2"
        # Not to forget! these are actually strings!

        # nested and true
        if ip_list:
            ip = re.sub(r'^\[|\]$', '', ip)
            ip = re.sub(r'"', '', ip)
            ips = []
            print "1: %s" % ip
            _nest_list = False
            if re.search(",\[", ip):
                _nest_list = True
            else:
                snort_ip_list = ip.split(',')
                for sip in snort_ip_list:
                    print "sip: %s" % sip
                    ip = self.ip(sip)
                    print "returned sip: %s" % str(ip)
                    ips.append(ip)
            if _nest_list:
                ip = re.sub(r',\[', ';[', ip)
                nests = ip.split(";")
                for li in nests:
                    li = li.lstrip("[").rstrip("]")
                    li = li.split(",")
                    ip = self._ip_list(li)
                    if re.match("^\[", li):
                        li = li.lstrip("[").rstrip("]")
                        li = li.split(",")
                        ip = self._ip_list(li)
                        ips.append((True, ip))
                    else:
                        li = li.split(",")
                        ip = self._ip_list(li)
                        for item in ip:
                            ips.append(item)

            # nested and denied
            print "bumbumbun %s" % str(ip)
            if re.search(",!\[", ip):
                ip = re.sub(r',\!\[', ';![', ip)
                nests = ip.split(";")
                for li in nests:
                    li_not = True
                    if re.match("^!\[", li):
                        li = li.lstrip("!")
                        li_not = False
                    if re.match("^\[", li):
                        li = li.lstrip("[").rstrip("]")
                        li = li.split(",")
                        ip = self._ip_list(li)
                        ips.append((li_not, ip))
                    else:
                        li = li.split(",")
                        ip = self._ip_list(li)
                        for item in ip:
                            ips.append(item)

            # list of ips, but not nested, both denied and true
            if isinstance(ip, basestring) and re.search("^\d.*|^!\d.*", ip):
                print "basestring numbered %s" % ip
                ip = ip.split(",")
                ip = self._ip_list(ip)
                for item in ip:
                    ips.append(item)

            return (ifnot, ips)

        # ip as a string
        ip_test = self.utils.valid_ip(ip)
        if ip_test:
            return (ifnot, ip)

        print "is variable? %s" % repr(ip)
        print [ord(c) for c in ip]
        print [ord(c) for c in variables["$HOME_NET"]]
        print variables.keys()
        if ip in variables.keys():
            print "yes it is"
            return (ifnot, ip)
        else:
            msg = "Invalid ip or variable %s" % ip
            raise ValueError(msg)

    def port(self, port):
        ifnot = None
        # Possibly needs more variables

        variables = {"any": "any",
                     "$HTTP_PORTS": "$HTTP_PORTS"
                     }

        # is the source marked as not
        if re.search("^!.*", port):
            ifnot = False
            port = port.strip("!")
        else:
            ifnot = True
        # is it a list ?
        # if it is, then make it a list from the string
        """
        Snort allows for ports marked between
        square prackets and are used to define lists
        correct:
        >> [80:443,!90,8080]
        >> ![80:443]
        >> [!80:443]
        """
        if re.match("^\[", port):
            port = re.sub(r'\[|\]', '', port)
            port = port.split(",")

        if isinstance(port, list):
            ports = []
            for item in port:
                not_range = True
                if re.search(r"\:", item):
                    # Checking later on if port is [prt:] or [:prt]
                    open_range = False
                    items = item.split(":", 1)
                    for prt in items:
                        message = "Port range is malformed %s" % item
                        prt = prt.lstrip("!")
                        if not prt:
                            open_range = True
                            continue
                        try:
                            prt = int(prt)
                        except:
                            raise ValueError(message)
                        if prt < 0 or prt > 65535:
                            raise ValueError(message)
                    for index, value in enumerate(items):
                        value = value.lstrip("!")
                        items[index] = value
                    if not open_range:
                        try:
                            a = int(items[-1])
                            b = int(items[0])
                        except:
                            raise ValueError(message)
                        if a - b < 0:
                            raise ValueError(message)
                    not_range = False

                port_not = True
                if re.search("^!", item):
                    port_not = False
                    item = item.strip("!")
                if not_range:
                    message1 = "Port is out of range %s" % item
                    message2 = "Unknown port %s" % item
                    if item in variables:
                        ports.append((port_not, item))
                        continue
                    try:
                        prt = int(item)
                        if prt < 0 or prt > 65535:
                            raise ValueError(message1)
                    except:
                        raise ValueError(message2)
                ports.append((port_not, item))
            return (ifnot, ports)

        if isinstance(port, basestring):
            """
            Parsing ports like: :8080, 80:, 80:443
            and passes all variables ex: $HTTP
            ranges do not accept denial (!)
            """
            if port in variables or re.search(r"^\$+", port):
                return (ifnot, port)
            if re.search(":", port):
                message = "Port is out of range %s" % port
                ports = port.split(":")
                for portl in ports:
                    portl.lstrip("!")
                    if not portl:
                        continue
                    if portl in variables:
                        continue
                    try:
                        portl = int(portl)
                    except:
                        raise ValueError(message)
                    if portl < 0 or portl > 65535:
                        raise ValueError(message)
                return (ifnot, port)

            """
            Parsing a single port
            single port accepts denial.
            """
            try:
                if not int(port) > 65535 or int[port] < 0:
                    return (ifnot, port)
                if int(port) > 65535 or int[port] < 0:
                    raise ValueError(message)
            except:
                msg = "Unknown port: \"%s\" " % port
                raise ValueError(msg)
        else:
            message = "Unknown port \"%s\"" % port
            raise ValueError(message)

    def destination(self, dst):
        destinations = {"->": "to_dst",
                        "<>": "bi_direct"}

        if dst in destinations:
            return dst
        else:
            msg = "Invalid destination variable %s" % dst
            raise ValueError(msg)

    def get_header(self):
        if re.match(r"(^[a-z|A-Z].+?)?(\(.+;\)|;\s\))", self.rule):
            header = self.rule.split('(', 1)
            return header[0]
        else:
            msg = 'Error in syntax, check if rule'\
                  'has been closed properly %s ' % self.rule
            raise SyntaxError(msg)

    def get_options(self):
        options = self.rule.split('(', 1)
        return options[1]

    def parse_header(self):
        """
        >>> from snortparser import Parser
        >>> rule = ('alert tcp $HOME_NET any -> !$EXTERNAL_NET  \
any (msg:\"MALWARE-BACKDOOR - Dagger_1.4.0\"; \
flow:to_client,established; \
content:\"2|00 00 00 06 00 00 00|Drives|24 00|\"; \
depth:16; metadata:ruleset community; \
classtype:misc-activity; sid:105; rev:14;)')
        >>> parsed = Parser(rule)
        >>> parsed.header
        OrderedDict([('action', 'alert'), ('proto', 'tcp'), ('source', \
(True, '$HOME_NET')), ('src_port', (True, 'any')), ('arrow', '->'), \
('destination', (False, '$EXTERNAL_NET')), ('dst_port', (True, 'any'))])

    """

        if self.get_header():
            header = self.get_header()
            if re.search(r"[,\[\]]\s", header):
                header = re.sub(r",\s+", ",", header)
                header = re.sub(r"\s+,", ",", header)
                header = re.sub(r"\[\s+", "[", header)
                header = re.sub(r"\s+\]", "]", header)
            header = header.split()
        else:
            raise ValueError("Header is missing, or unparsable")
        # get rid of empty list elements
        header = filter(None, header)
        header_dict = collections.OrderedDict()
        size = len(header)
        if not size == 7 and not size == 1:
            msg = "Snort rule header is malformed %s" % header
            raise ValueError(msg)

        for item in header:
                if "action" not in header_dict:
                    action = self.actions(item)
                    header_dict["action"] = action
                    continue

                if "proto" not in header_dict:
                    try:
                        proto = self.proto(item)
                        header_dict["proto"] = proto
                        continue
                    except Exception as perror:
                        raise ValueError(perror)

                if "source" not in header_dict:
                    src_ip = self.ip(item)
                    header_dict["source"] = src_ip

                if "src_port" not in header_dict:
                    src_port = self.port(item)
                    header_dict["src_port"] = src_port
                    continue

                if "arrow" not in header_dict:
                    dst = self.destination(item)
                    header_dict["arrow"] = dst
                    continue

                if "destination" not in header_dict:
                    dst_ip = self.ip(item)
                    header_dict["destination"] = dst_ip
                    continue

                if "dst_port" not in header_dict:
                    dst_port = self.port(item)
                    header_dict["dst_port"] = dst_port
                    continue

        return header_dict

    def parse_options(self, rule=None):
        # TODO:
        # 1. preprocesor checks
        # 2. output modules checks
        if rule:
            self.rule = rule
        options_dict = collections.OrderedDict()
        opts = self.get_options()
        _pcre_opt = False
        if re.search(r'(;\s+pcre:\s+".*";)', opts):
            _pcre_opt = True

        if _pcre_opt:
            _pcre = re.split(r';(\s+pcre:\s+".*");', opts)
            options_l = _pcre[0].split(';')
            options_l.append(_pcre[1])
            options_r = _pcre[2].split(';')
            options = options_l + options_r
        else:
            options = opts.split(';')
        options = filter(None, options)
        if options[-1].lstrip().rstrip() == ")":
            options.pop()
        else:
            raise ValueError("Snort rule options is not closed properly, "
                             "you have a syntax error")

        for index, option in enumerate(options):
            try:
                split_option = option.split(":", 1)
                for place, item in enumerate(split_option):
                    item = item.lstrip().rstrip()
                    split_option[place] = item
                option_dict = {}
                if isinstance(split_option, list):
                    key = split_option[0]
                    split_option_values = split_option[-1].split(",")
                    option_dict[key] = split_option_values
                else:
                    option_dict[split_option[0]] = None
                options_dict[index] = option_dict
            except:
                option = option.lstrip().rstrip()
        return options_dict

    def validate_options(self, options):
        for key, value in options.iteritems():
            option_dict = value
            opt = False
            for key, value in option_dict.iteritems():
                option = key
                content_mod = self.dicts.content_modifiers(option)
                if content_mod:
                    # An unfinished feature
                    pass
                gen_option = self.dicts.options(option)
                if gen_option:
                    opt = True
                    continue
                pay_option = self.dicts.options(option)
                if pay_option:
                    opt = True
                    continue
                non_pay_option = self.dicts.options(option)
                if non_pay_option:
                    opt = True
                    continue
                post_detect = self.dicts.options(option)
                if post_detect:
                    opt = True
                    continue
                threshold = self.dicts.options(option)
                if threshold:
                    opt = True
                    continue
                if not opt:
                    message = "unrecognized option: %s" % option
                    raise ValueError(message)
        return options


if __name__ == "__main__":

    import doctest

    doctest.testmod()
