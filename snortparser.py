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

    def __ip_to_tuple(self, ip):
        if re.match(r"!", ip):
            ip = ip.lstrip("!")
            return (False, ip)
        else:
            return (True, ip)

    def __form_ip_list(self, ip_list):
        ip_list = ip_list.split(",")
        ips = []
        for ip in ip_list:
            ips.append(self.__ip_to_tuple(ip))
        return ips

    def __flatten_ip(self, ip):
        list_deny = True
        if re.match("^!", ip):
            list_deny = False
            ip = ip.strip("!")
        _ip_list = []
        _not_nest = True
        ip = re.sub(r'^\[|\]$', '', ip)
        ip = re.sub(r'"', '', ip)
        if re.search(r"(\[.*\])", ip):
            _not_nest = False
            nest = re.split(r",(!?\[.*\])", ip)
            nest = filter(None, nest)
            # unnest from _ip_list
            _return_ips = []
            for item in nest:
                if re.match(r"^\[|^!\[", item):
                    nested = self.__flatten_ip(item)
                    _return_ips.append(nested)
                    continue
                else:
                    _ip_list = self. __form_ip_list(item)
                    for _ip in _ip_list:
                        _return_ips.append(_ip)
            return (list_deny, _return_ips)
        if _not_nest:
            _ip_list = self. __form_ip_list(ip)
            return (list_deny, _ip_list)

    def __validate_ip(self, ips):
        utils = Utils()
        variables = {"$EXTERNAL_NET": "$EXTERNAL_NET",
                     "$HTTP_SERVERS": "$HTTP_SERVERS",
                     "$INTERNAL_NET": "$INTERNAL_NET",
                     "$SQL_SERVERS": "$SQL_SERVERS",
                     "$SMTP_SERVERS": "$SMTP_SERVERS",
                     "$DNS_SERVERS": "$DNS_SERVERS",
                     "$HOME_NET": "$HOME_NET",
                     "HOME_NET": "HOME_NET",
                     "any": "any"}

        # deny_flag = None
        for item in ips:
            if isinstance(item, bool):
                pass
                # deny_flag = item
            if isinstance(item, list):
                for ip in item:
                    ip = self.__validate_ip(ip)
                    if isinstance(ip, list):
                        ip = self.__validate_ip(ip)
            if isinstance(item, basestring):
                    if item in variables:
                        pass
                    elif utils.valid_ip(item):
                        pass
                    else:
                        raise ValueError("Unknown ip or variable %s" % item)
        return True

    def ip(self, ip):

        if isinstance(ip, basestring):
            ip = ip.strip('"')
            if re.search(r",", ip):
                item = self.__flatten_ip(ip)
                ip = item
            else:
                ip = self.__ip_to_tuple(ip)
            valid = self.__validate_ip(ip)
            if valid:
                return ip
            else:
                raise ValueError("Unvalid ip or variable: %s" % ip)

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
                    try:
                        src_ip = self.ip(item)
                        header_dict["source"] = src_ip
                        continue
                    except Exception as serror:
                        raise ValueError(serror)

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
        opts = self.get_options()
        _pcre_opt = False
        #if re.search(r'(;\s+pcre:\s+".*";)', opts):
        if re.search(r'(;\s+pcre:\s+".*";|;\s+pcre:".*";)', opts):
            _pcre_opt = True

        if _pcre_opt:
            #_pcre = re.split(r';(\s+pcre:\s+".*");', opts)
            _pcre = re.split(r';(\s+pcre:\s+".*"|\s+pcre:".*");', opts)
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

        options_dict = collections.OrderedDict()
        for index, option in enumerate(options):
            if ':' in option:
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

            else:
                options_dict[index] = {"modifier":[option.lstrip().rstrip()]}
        return options_dict

    def validate_options(self, options):
        for key, value in options.iteritems():
            option_dict = value
            opt = False
            for key, value in option_dict.iteritems():
                content_mod = self.dicts.content_modifiers(value[0])
                if content_mod:
                    # An unfinished feature
                    continue
                gen_option = self.dicts.options(key)
                if gen_option:
                    opt = True
                    continue
                pay_option = self.dicts.options(key)
                if pay_option:
                    opt = True
                    continue
                non_pay_option = self.dicts.options(key)
                if non_pay_option:
                    opt = True
                    continue
                post_detect = self.dicts.options(key)
                if post_detect:
                    opt = True
                    continue
                threshold = self.dicts.options(key)
                if threshold:
                    opt = True
                    continue
                if not opt:
                    message = "unrecognized option: %s" % key
                    raise ValueError(message)
        return options

class Sanitizer(object):
    def __init__(self):
        self.methods = {
                "pcre": self.pcre,
                "depth": self.depth
                }

    def pcre(self, options):
        pcre_idx = [idx for idx in options if options[idx].has_key("pcre")][0]
        value = options[pcre_idx]["pcre"]
        if isinstance(value, list):
            value = value[0]
        if re.match(r'^"/.*/"$', value):
            print True
        else:
            if not re.match(r'^("\/)', value):
                start = re.split(r'^"', value)
                start[0] = '"/'
                value = ''.join(start)
            if not re.search(r'(\/")$', value):
                end = re.split(r'"$', value)
                end[-1] = '/"'
                value = ''.join(end)
            return value

    def depth(self, options):
        depth_idx = [idx for idx in options if options[idx].has_key("depth")][0]
        dsize_idx = [idx for idx in options if options[idx].has_key("dsize")][0]
        depth = options[depth_idx].get("depth")[0]
        dsize = options[dsize_idx].get("dsize")[0]
        full_dsize = re.split(r'[0-9]+', dsize)
        operand = [x for x in full_dsize if x]
        dsize = dsize.strip(operand[0])
        if int(depth) < int(dsize):
            print dsize
            return dsize
        else:
            return depth


    def sanitize(self, rule):
        options = rule['options']
        for idx in options:
            key = options[idx].keys()[0]
            opt = options[idx]
            if key in self.methods:
               value = self.methods[key](options)
               options[idx][key] = [value]
        return options


class FlattenRule(object):

    def __init__(self, rule):
        self.rule = rule

    def __getitem__(self):
        return self.flatten_rule()

    # (True, [(True, 80), (False, 443)])
    def flatten_header_item(self, item):
        item_str = ''
        in_list = False
        if isinstance(item[1], list):
            item_str = '['
            in_list = True
            for tup in item[1]:
                tup = self.flatten_header_item(tup)
                item_str = item_str + tup + ','
            item_str = item_str.rstrip(',') + ']'
            if not item[0]:
                item_str = '!' + item_str
        if isinstance(item, tuple) and not in_list:
            if item[0]:
                item_str = item_str + item[1]
            else:
                item_str = '!' + item_str + item[1]
        if isinstance(item, basestring):
            item_str = item_str + str(item)
        return item_str

    def flatten_header(self, header):
        header_raw = ''
        for key, value in header.iteritems():
            flat = self.flatten_header_item(value)
            header_raw = header_raw + flat + ' '
        return header_raw

    def flatten_options(self, options):
        options_list = []
        for index, value in options.iteritems():
            key = value.keys()[0]
            if 'modifier' not in key:
                value = key, ','.join(str(e) for e in value[key])
                value = ':'.join(str(e) for e in value)
            else:
                value = value[key][0]
            options_list.append(value)

        options_flat = '; '.join(str(e) for e in options_list)
        options_raw = '(' + options_flat + ';)'
        return options_raw

    def get_rule(self):
        header = self.rule['header']
        options = self.rule['options']
        flat_header = self.flatten_header(header)
        flat_options = self.flatten_options(options)
        flat_rule = flat_header + flat_options

        return flat_rule  


if __name__ == "__main__":

    import doctest

    doctest.testmod()
