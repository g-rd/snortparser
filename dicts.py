class Dicts():

    def ip_variables(self, variable):
        variables = {"$EXTERNAL_NET": "$EXTERNAL_NET",
                     "$HTTP_SERVERS": "$HTTP_SERVERS",
                     "$INTERNAL_NET": "$INTERNAL_NET",
                     "$SQL_SERVERS": "$SQL_SERVERS",
                     "$SMTP_SERVERS": "$SMTP_SERVERS",
                     "$DNS_SERVERS": "$DNS_SERVERS",
                     "$HOME_NET": "$HOME_NET",
                     "any": "any"
                     }

        if variable in variables:
            return variables[variable]
        else:
            return False

    def general_options(self, option):
        # TODO: maybe add Snort Default Classifications
        general_options = {"msg": "msg",
                           # The msg keyword tells the
                           # logging and alerting engine
                           # the message to print with the packet
                           # dump or alert.
                           "reference": "reference",
                           # The reference keyword allows rules to include
                           # references to external attack identification
                           # systems.
                           "gid": "gid",
                           # The gid keyword (generator id) is used to
                           # identify  what part of Snort generates the event
                           # when a particular rule fires.
                           "sid": "sid",
                           # The sid keyword is used to uniquely identify
                           # Snort rules.
                           "rev": "rev",
                           # The rev keyword is used to uniquely identify
                           # revisions of Snort rules.
                           "classtype": "classtype",
                           # The classtype keyword is used to categorize
                           # a rule as detecting  an attack that is part
                           # of a more general type of attack class.
                           # The priority keyword assigns a severity level to
                           # rules. "priority": "priority",
                           "metadata": "metadata"
                           # The metadata keyword allows a rule writer
                           # to embed additional  information about the rule,
                           # typically in a key-value format.  Keys: engine
                           # ( Indicate a Shared Library Rule ) ex: "shared",
                           # soid ( Shared Library Rule Generator and
                           # SID ) ex: "gid|sid", service ( Target-Based
                           # Service Identifier ) ex: "http"
                           }

        if option in general_options:
            return general_options[option]
        else:
            return False

    def payload_options(self, option):

        payload_detection = {"content": "content",
                             # The content keyword allows
                             # the user to set rules that search for specific
                             # content in the packet payload and trigger
                             # response based on that data.
                             "protected_content": "protected_content",
                             # As with the content keyword,
                             # its primary purpose is to match strings of
                             # specific bytes. The search is performed by
                             # hashing portions of incoming packets and
                             # comparing the results against the hash provided,
                             # and as such, it is computationally expensive.
                             "hash": "hash",
                             # The hash keyword is used to specify the hashing
                             # algorithm to use when matching a
                             # protected_content rule.
                             "length": "length",
                             # The length keyword is used to specify the
                             # original length of the content specified
                             # in a protected_content rule digest.
                             # The value provided must be greater than 0 and
                             # less than 65536.
                             "nocase": "nocase",
                             # The nocase keyword allows the rule writer to
                             # specify that the Snort should look for the
                             # specific pattern, ignoring case. nocase
                             # modifies the previous content keyword
                             # in the rule.
                             "rawbytes": "rawbytes",
                             # The rawbytes keyword allows rules to look at
                             # the raw packet data, ignoring any decoding
                             # that was done by preprocessors.
                             "depth": "depth",
                             # The depth keyword allows the rule writer to
                             # specify how far into a packet Snort should
                             # search for the specified pattern.
                             "offset": "offset",
                             # The offset keyword allows the rule writer to
                             # specify where to start searching for a pattern
                             # within a packet.
                             "distance": "distance",
                             # The distance keyword allows the rule writer to
                             # specify how far into a packet Snort should
                             # ignore before starting to search for the
                             # specified pattern relative to the end of the
                             # previous pattern match.
                             "within": "within",
                             # The within keyword is a content modifier that
                             # makes sure that at most N bytes are between
                             # pattern matches using the content keyword.
                             # NOTE: The http_client_body modifier is not
                             # allowed to be used with the rawbytes modifier
                             # for the same content.
                             "http_client_body": "http_client_body",
                             # The http_client_body keyword is a content
                             # modifier that restricts the search to the body
                             # of an HTTP client request.
                             # NOTE: The http_cookie modifier is not
                             # allowed to be used with the
                             # rawbytes or fast_pattern modifiers for the same
                             # content
                             "http_cookie": "http_cookie",
                             # The http_cookie keyword is a content modifier
                             # that restricts the search to the extracted
                             # Cookie Header field As this keyword
                             # is a modifier to the previous content
                             # keyword, there must be a content in the rule
                             # before http_cookie is specified.
                             # This keyword is dependent
                             # on the enable_cookie config option.
                             # NOTE: The http_raw_cookie modifier
                             # is not allowed to be used with the rawbytes,
                             # http_cookie or fast_pattern modifiers for the
                             # same content
                             "http_raw_cookie": "http_raw_cookie",
                             # The http_raw_cookie keyword is a content
                             # modifier that restricts the search to the
                             # extracted UNNORMALIZED Cookie Header field
                             # NOTE: The http_header modifier is not allowed
                             # to be used with the rawbytes modifier for the
                             # same content.
                             "http_header": "http_header",
                             # The http_header keyword is a content modifier
                             # that restricts the search to the extracted
                             # Header fields.
                             # NOTE:The http_raw_header modifier
                             # is not allowed to be used with the rawbytes,
                             # http_header or fast_pattern modifiers for the
                             # same content.
                             "http_raw_header": "http_raw_header",
                             # The http_raw_header keyword is a content
                             # modifier that restricts the search to the
                             # extracted UNNORMALIZED Header fields
                             # NOTE: The http_method modifier
                             # is not allowed to be used with the rawbytes
                             # or fast_pattern
                             # modifiers for the same content.
                             "http_method": "http_method",
                             # The http_method keyword is a content modifier
                             # that restricts the search to the extracted
                             # Method from a HTTP client request.
                             # NOTE: The http_uri modifier is not allowed
                             # to be used with the rawbytes modifier for
                             # the same content.
                             "http_uri": "http_uri",
                             # The http_uri keyword is a content modifier
                             # that restricts the search to the NORMALIZED
                             # request URI field. NOTE: The http_raw_uri
                             # modifier is not allowed to be used with the
                             # rawbytes, http_uri or fast_pattern modifiers
                             # for the same content.
                             "http_raw_uri": "http_raw_uri",
                             # The http_raw_uri keyword is a content modifie
                             # that restricts the search to the UNNORMALIZED
                             # request URI field. NOTE: The http_stat_code
                             # modifier is not allowedi to be used with the
                             # rawbytes or fast_pattern modifiers for the
                             # same content.
                             "http_stat_code": "http_stat_code",
                             # The http_stat_code keyword is a content
                             # modifier that restricts the search
                             # to the extracted Status code field
                             # from a HTTP server response.
                             # NOTE: The http_stat_msg modifier is not allowed
                             # to be used with the rawbytes or fast_pattern
                             # modifiers for the same content.
                             "http_stat_msg": "http_stat_msg",
                             # The http_stat_msg keyword is a content modifier
                             # that restricts the search to the extracted
                             # Status Message field from a
                             # HTTP server response.
                             # NOTE: Negation(!) and OR(|) operations cannot
                             # be used in conjunction with each other for the
                             # http_encode keyword. The OR and negation
                             # operations work only on the encoding type
                             # field and not on http buffer type field.
                             # TODO: check for http_encode options
                             "http_encode": "http_encode",
                             # The http_encode keyword will enable alerting
                             # based on encoding type present in a HTTP client
                             # request or a HTTP server response
                             # NOTE: The fast_pattern modifier cannot be used
                             # with the following http content modifiers:
                             # 1. http_cookie,
                             # 2. http_raw_uri,
                             # 3. http_raw_header,
                             # 4. http_raw_cookie,
                             # 5. http_method,
                             # 6. http_stat_code,
                             # 7. http_stat_msg
                             # NOTE: The fast_pattern modifier can be used
                             # with negated contents onlyi if those contents
                             # are not modified with:
                             # 1. offset,
                             # 2. depth,
                             # 3. distance or
                             # 4.  within.
                             # NOTE: The fast pattern matcher is always case
                             # insensitive. TODO: check for fast_pattern
                             # format
                             "fast_pattern": "fast_pattern",
                             # The fast_pattern keyword is a content modifier
                             # that sets the content within a rule to be used
                             # with the fast pattern matcher.
                             # NOTE: uricontent cannot be modified by
                             # a rawbytes modifier or any of the other
                             # HTTP modifiers. If you wish to search the
                             # UNNORMALIZED request URI field, use the
                             # http_raw_uri modifier with a content option.
                             "uricontent": "uricontent",
                             # The uricontent keyword in the Snort
                             # rule language searches the normalized request
                             # URI field.
                             "urilen": "urilen",
                             # The urilen keyword in the Snort rule
                             # language specifies the exact length,
                             # the minimum length, the maximum length,
                             # or range of URI lengths to match.
                             "isdataat": "isdataat",
                             # The isdataat keyword verifies that the
                             # payload has data at a specified location.
                             # TODO: check for Perl compatible modifiers
                             # for pcre. NOTE: Since this is an advanced
                             # option, check the manual for pitfalls.
                             "pcre": "pcre",
                             # The pcre keyword allows rules to
                             # be written using perl compatible regular
                             # expressions.
                             "pkt_data": "pkt_data",
                             # This option sets the cursor used for detection
                             # to the raw transport payload.
                             # NOTE: The argument mime to file_data is
                             # deprecated. The rule options file_data will
                             # itself point to the decoded MIME attachment.
                             "file_data": "file_data",
                             # This option sets the cursor used for detection
                             # to one of the following buffers:
                             # 1. HTTP response body
                             # 2. HTTP de-chunked response body
                             # 3. HTTP decompressed response
                             # 4. HTTP normalized response body
                             # 5. HTTP UTF normalized response body
                             # 6. All of the above
                             # 7. SMTP/POP/IMAP data body
                             # 8. Base64 decoded MIME attachment
                             # 9. Non-Encoded MIME attachment
                             # 10. Quoted-Printable decoded MIME attachment
                             # 11. Unix-to-Unix decoded attachment
                             # TODO: check for base64_decode options and
                             # format
                             "base64_decode": "base64_decode",
                             # This option is used to decode the
                             # base64 encoded data. This option is
                             # particularly useful in
                             # case of HTTP headers such as HTTP authorization
                             # headers. NOTE: Fast pattern content matches
                             # are not allowed with this buffer.
                             "base64_data": "base64_data",
                             # This option is similar to the rule option
                             # file_data and is used to set the
                             # cursor used for detection to the beginning
                             # of the base64 decoded
                             # buffer if present.
                             # TODO: check for options.
                             "byte_test": "byte_test",
                             # The byte_test keyword tests a byte
                             # field against a specific value
                             # (with operatori). TODO: check
                             # for options
                             "byte_jump": "byte_jump",
                             # The byte_jump keyword allows rules to read the
                             # length of a portion of data, then skip that
                             # far forward in the packet. NOTE: Only two
                             # byte_extract variables may be created per rule.
                             # They can be re-used in the same rule any number
                             # of times. TODO. check for options.
                             "byte_extract": "byte_extract",
                             # It reads in some number of bytes from the
                             # packet payload and saves it to a variable.
                             # TODO: check for byte_math syntax and options
                             "byte_math": "byte_math",
                             # Perform a mathematical
                             # operation on an extracted
                             # value and a specified value or
                             # existing variable,
                             # and store the outcome in a new resulting
                             # variable
                             "ftpbounce": "ftpbounce",
                             # The ftpbounce keyword detects FTP bounce
                             # attacks. TODO. check for options and syntax
                             # for asn1
                             "asn1": "asn1",
                             # The asn1 detection plugin decodes a packet or a
                             # portion of a packet, and looks for variou
                             #  malicious encodings.
                             # NOTE: This plugin cannot do detection over
                             # encrypted sessions, e.g. SSH (usually port 22).
                             # TODO: find a way to check if the rule uses
                             # encrypted sessions
                             "cvs": "cvs",
                             # The cvs keyword detects invalid entry strings.
                             "dce_iface": "dce_iface",
                             # For DCE/RPC based rules it has been necessary
                             # to set flow-bits based on a client bind to a
                             # service to avoid false positives.
                             "dce_opnum": "dce_opnum",
                             # The opnum represents a specific function
                             # call to an interface.
                             "dce_stub_data": "dce_stub_data",
                             # This option is used to place the cursor
                             # (used to walk the packet payload in rules
                             # processing) at the beginning of the DCE/RPC
                             # stub data SIP Preprocessor provides ways to
                             # tackle Common Vulnerabilities and Exposures
                             # (CVEs) related with SIP found over the past
                             # few years.
                             "sip_method": "sip_method",
                             # The sip_method keyword is used to check for
                             # specific SIP request methods.
                             "sip_stat_code": "sip_stat_code",
                             # The sip_stat_code is used to check the SIP
                             # response status code.
                             # This option matches if any one of the state
                             # codes specified matches the status codes of
                             # the SIP response.
                             "sip_header": "sip_header",
                             # The sip_header keyword restricts the search
                             # to the extracted Header fields of a SIP message
                             # request or a response. This works similar to
                             # file_data.
                             "sip_body": "sip_body",
                             # The sip_body keyword places the cursor at the
                             # beginning of the Body fields of a SIP message.
                             # This works similar to file_data and
                             # dce_stub_data. The message body includes
                             # channel information using SDP protocol
                             # (Session Description Protocol).
                             # GTP (GPRS Tunneling Protocol) is used in core
                             # communication networks to establish a channel
                             # between GSNs (GPRS Serving Node). GTP decoding
                             # preprocessor provides ways to tackle
                             # intrusion attempts to those networks through
                             # GTP. It also makes detecting new attacks easier.
                             # TODO: identify also gtp message types, but for
                             # now keyword check has to cut it.
                             "gtp_type": "gtp_type",
                             # The gtp_type keyword is used to check for
                             # specific GTP types. User can input message type
                             # value, an integer in [0, 255], or a string
                             # defined in the Table below.
                             # TODO: gtp_info table check.
                             "gtp_info": "gtp_info",
                             # The gtp_info keyword is used to check for
                             # specific GTP information element.
                             # This keyword restricts the search to the
                             # information element field. User can input
                             # information element value,
                             # an integer in $[0, 255]$,
                             "gtp_version": "gtp_version",
                             # The gtp_version keyword is used to check for
                             # specific GTP version. Relates to gtp_info
                             # and gtp_type tables.
                             }

        if option in payload_detection:
            return payload_detection[option]
        else:
            return False

    def non_payload_options(self, option):

        non_payload_detect = {"fragoffset": "fragoffset",
                              # The fragoffset keyword allows one to compare
                              # the IP fragment offset field against a
                              # decimal value.
                              "ttl": "ttl",
                              # The ttl keyword is used to check the IP
                              # time-to-live value.
                              "tos": "tos",
                              # The tos keyword is used to check the IP
                              # TOS field for a specific value.
                              "id": "id",
                              # The id keyword is used to check the IP ID
                              # field for a specific value.
                              "ipopts": "ipopts",
                              # The ipopts keyword is used to check if a
                              # specific IP option is present.
                              "fragbits": "fragbits",
                              # The fragbits keyword is used to check if
                              # fragmentation and reserved bits are set
                              # in the IP header.
                              "dsize": "dsize",
                              # The dsize keyword is used to test the
                              # packet payload isize NOTE: The reserved bits
                              # '1' and '2' have been replaced with
                              # 'C' and 'E',respectively, to match
                              # RFC 3168, "The Addition of Explicit
                              # Congestion Notification (ECN) to IP".
                              # The old values of '1' and '2' are still
                              # valid for the flag keyword, but are now
                              # deprecated.
                              "flags": "flags",
                              # The flags keyword is used to check if
                              # specific TCP flag bits are present.
                              # TODO: check for syntax and options
                              "flow": "flow",
                              # The flow keyword allows rules to only
                              # apply to certain directions of the traffic
                              # flow. TODO. check for options and syntax
                              "flowbits": "flowbits",
                              # The flowbits keyword allows rules to
                              # track states during a transport protocol
                              # session.
                              "seq": "seq",
                              # The seq keyword is used to check for a
                              # specific TCP sequence number
                              "ack": "ack",
                              # The ack keyword is used to check for a
                              # specific TCP acknowledge number
                              "window": "window",
                              # The window keyword is used to check for
                              # a specific TCP window size
                              "itype": "itype",
                              # The itype keyword is used to check for a
                              # specific ICMP type value
                              "icode": "icode",
                              # The icode keyword is used to check for
                              # a specific ICMP code value
                              "icmp_id": "icmp_id",
                              # The icmp id keyword is used to check
                              # for a specific ICMP ID value.
                              "icmp_seq": "icmp_seq",
                              # The icmp seq keyword is used to check
                              # for a specific ICMP sequence value.
                              "rpc": "rpc",
                              # The rpc keyword is used to check
                              # for a RPC application, version, and
                              # procedure numbers in SUNRPC CALL requests
                              "ip_proto": "ip_proto",
                              # The ip proto keyword allows checks against
                              # the IP protocol header
                              "sameip": "sameip",
                              # The sameip keyword allows rules to check
                              # if the source ip is the same as the
                              # destination IP.
                              # NOTE: The stream_reassemble option is
                              # only available when the Stream preprocessor
                              # is enabled.
                              "stream_reassemble": "stream_reassemble",
                              # The stream_reassemble keyword allows a rule
                              # to enable or disable TCP stream
                              # reassembly on matching traffic.
                              # NOTE: The stream_size option is only
                              # available when the Stream preprocessor
                              # is enabled.
                              "stream_size": "stream_size"
                              # The stream_size keyword allows a rule
                              # to match traffic
                              # according to the number of bytes observed,
                              # as determined by the TCP sequence numbers.
                              }

        if option in non_payload_detect:
            return non_payload_detect[option]
        else:
            return False

    def post_detect_options(self, option):

        post_detect = {"logto": "logto",
                       # The logto keyword tells Snort to log all packets
                       # that trigger this rule to a special output log file.
                       "session": "session",
                       # The session keyword is built to extract user data
                       # from TCP Sessions
                       "resp": "resp",
                       # The resp keyword is used attempt to close sessions
                       # when an alert is triggered.
                       "react": "react",
                       # This keyword implements an ability for users to
                       # react to traffic that matches a Snort rule by
                       # closing connection and sending a noticei.
                       # NOTE: also check for options
                       "tag": "tag",
                       # The tag keyword allow rules to log more than
                       # just the single packet that triggered the rule
                       "activates": "activates",
                       # This keyword allows the rule writer to specify
                       # a rule to add when a specific network event occurs.
                       "activated_by": "activated_by",
                       # This keyword allows the rule writer to dynamically
                       # enable a rule when a specific activate rule is
                       # triggered.
                       "count": "count",
                       # This keyword must be used in combination with the
                       # activated by keyword. It
                       # allows the rule writer to specify how many packets
                       # to leave the rule enabled for
                       # after it is activated
                       "replace": "replace",
                       # Replace the prior matching content with the given
                       # string of the same length. Available in inline
                       # mode only. NOTE: As mentioned above, Snort evaluates
                       #  detection_filter as the last step of the detection
                       # and not in post-detection.
                       "detection_filter": "detection_filter",
                       # Replace the prior matching content with the given
                       # string of the same length. Available
                       # in inline mode only.
                       "detection_filter": "detection_filter"
                       # Track by source or destination IP address and if
                       # the rule otherwise matches more
                       # than the configured rate it will fire.
                       }

        if option in post_detect:
            return post_detect[option]
        else:
            return False

    def content_modifiers(self, option):

        content_modifiers = {"nocase": "nocase",
                             "rawbytes": "rawbytes",
                             "depth": "depth",
                             "offset": "offset",
                             "distance": "distance",
                             "within": "within",
                             "http_client_body": "http_client_body",
                             "http_cookie": "http_cookie",
                             "http_raw_cookie": "http_raw_cookie",
                             "http_header": "http_header",
                             "http_raw_header": "http_raw_header",
                             "http_method": "http_method",
                             "http_uri": "http_uri",
                             "http_raw_uri": "http_raw_uri",
                             "http_stat_code": "http_stat_code",
                             "http_stat_msg": "http_stat_msg",
                             "http_encode": "http_encode",
                             "fast_pattern": "fast_pattern",
                             "uricontent": "uricontent",
                             "urilen": "urilen",
                             "isdataat": "isdataat",
                             "pcre": "pcre",
                             "pkt_data": "pkt_data",
                             "file_data": "file_data",
                             "base64_decode": "base64_decode",
                             "base64_data": "base64_data",
                             "byte_test": "byte_test",
                             "byte_jump": "byte_jump",
                             "byte_extract": "byte_extract",
                             "byte_math": "byte_math",
                             "ftpbounce": "ftpbounce",
                             "asn1": "asn1",
                             "cvs": "cvs",
                             "dce_iface": "dce_iface",
                             "dce_opnum": "dce_opnum",
                             "dce_stub_data": "dce_stub_data",
                             "sip_method": "sip_method",
                             "sip_stat_code": "sip_stat_code",
                             "sip_header": "sip_header",
                             "sip_body": "sip_body",
                             "gtp_type": "gtp_type",
                             "gtp_info": "gtp_info",
                             "gtp_version": "gtp_version",
                             "ssl_version": "ssl_version",
                             "ssl_state": "ssl_state"
                             }

        if option in content_modifiers:
            return content_modifiers[option]
        else:
            return False

    def rule_tresholds(self, option):

        rule_tresholds = {"threshold": "threshold"}

        if option in rule_tresholds:
            return rule_tresholds[option]
        else:
            return False

    def options(self, option):

        # TODO: maybe add Snort Default Classifications
        general_options = {"msg": "msg",
                           # The msg keyword tells the logging and
                           # alerting engine the message to print with the
                           # packet dump or alert.
                           "reference": "reference",
                           # The reference keyword allows rules to include
                           # references to external attack identification
                           # systems.
                           "gid": "gid",
                           # The gid keyword (generator id) is used to
                           # identify what part of Snort generates the event
                           # when a particular rule fires.
                           "sid": "sid",
                           # The sid keyword is used to uniquely identify
                           # Snort rules.
                           "rev": "rev",
                           # The rev keyword is used to uniquely identify
                           # revisions of Snort rules.
                           "classtype": "classtype",
                           # The classtype keyword is used to categorize a
                           # rule as detecting an attack that is part of a
                           # more general type of attack class.
                           "priority": "priority",
                           # The priority keyword assigns a severity level
                           # to rules.
                           "metadata": "metadata"
                           # The metadata keyword allows a rule writer
                           # to embed additional information about the rule,
                           # typically in a key-value format.
                           # Keys: engine ( Indicate a Shared Library Rule )
                           # ex: "shared", soid ( Shared Library
                           # Rule Generator and SID ) ex: "gid|sid",
                           # service ( Target-Based Service Identifier )
                           # ex: "http"
                           }

        payload_detection = {"content": "content",
                             # The content keyword allows the user
                             # to set rules that search for specific
                             # content in the packet payload and trigger
                             # response based on that data.
                             "protected_content": "protected_content",
                             # As with the content keyword, its primary purpose
                             # is to match strings of specific bytes. The
                             # search is performed by hashing portions of
                             # incoming packets and comparing the results
                             # against the hash provided, and as such, it is
                             # computationally expensive.
                             "hash": "hash",
                             # The hash keyword is used to specify
                             # the hashing algorithm to use when
                             # matching a protected_content rule.
                             "length": "length",
                             # The length keyword is used to specify the
                             # original length of the content specified
                             # in a protected_content rule digest.
                             # The value provided must be greater than 0 and
                             # less than 65536.
                             "nocase": "nocase",
                             # The nocase keyword allows the rule writer
                             # to specify that the Snort should look for
                             # the specific pattern, ignoring case. nocase
                             # modifies the previous content keyword in the
                             # rule.
                             "rawbytes": "rawbytes",
                             # The rawbytes keyword allows rules to look at
                             # the raw packet data, ignoring any decoding
                             # that was done by preprocessors.
                             "depth": "depth",
                             # The depth keyword allows the rule writer
                             # to specify how far into a packet Snort should
                             # search for the specified pattern.
                             "offset": "offset",
                             # The offset keyword allows the rule writer
                             # to specify where to start searching for a
                             # pattern within a packet.
                             "distance": "distance",
                             # The distance keyword allows the rule writer
                             # to specify how far into a packet Snort should
                             # ignore before starting to search for the
                             # specified pattern relative to the end of the
                             # previous pattern match.
                             "within": "within",
                             # The within keyword is a content modifier
                             # that makes sure that at most N bytes are
                             # between pattern matches using the content
                             # keyword. NOTE: The http_client_body modifier
                             # is not allowed to be used with the rawbytes
                             # modifier for the same content.
                             "http_client_body": "http_client_body",
                             # The http_client_body keyword is a content
                             # modifier that restricts the search
                             # to the body of an HTTP client request.
                             # NOTE: The http_cookie modifier is not allowed
                             # to be used with the rawbytes
                             # or fast_pattern modifiers for the same content
                             "http_cookie": "http_cookie",
                             # The http_cookie keyword is a content modifier
                             # that restricts the search to the extracted
                             # Cookie Header field As this keyword is a
                             # modifier to the previous content keyword,
                             # there must be a content in the rule before
                             # http_cookie is specified.
                             # This keyword is dependent on the enable_cookie
                             # config option. NOTE: The http_raw_cookie
                             # modifier is not allowed to be used with the
                             # rawbytes, http_cookie or fast_pattern modifiers
                             # for the same content
                             "http_raw_cookie": "http_raw_cookie",
                             # The http_raw_cookie keyword is a content
                             # modifier that restricts the search to the
                             # extracted UNNORMALIZED Cookie Header field
                             # NOTE: The http_header modifier is not allowed
                             # to be used with the rawbytes modifier for the
                             # same content.
                             "http_header": "http_header",
                             # The http_header keyword is a content modifier
                             # that restricts the search to the extracted
                             # Header fields NOTE: The http_raw_header
                             # modifier is not allowed to be used with the
                             # rawbytes, http_header or fast_pattern modifiers
                             # for the same content.
                             "http_raw_header": "http_raw_header",
                             # The http_raw_header keyword is a content
                             # modifier that restricts the search to the
                             # extracted UNNORMALIZED Header fields
                             # NOTE: The http_method modifier is not allowed
                             # to be used with the rawbytes or fast_pattern
                             # modifiers for the same content.
                             "http_method": "http_method",
                             # The http_method keyword is a content modifier
                             # that restricts the search to the extracted
                             # Method from a HTTP client request.
                             # NOTE: The http_uri modifier is not allowed
                             # to be used with the rawbytes modifier for the
                             # same content.
                             "http_uri": "http_uri",
                             # The http_uri keyword is a content modifier
                             # that restricts the search to the NORMALIZED
                             # request URI field. NOTE: The http_raw_uri
                             # modifier is not allowed to be used with the
                             # rawbytes, http_uri or fast_pattern modifiers
                             # for the same content.
                             "http_raw_uri": "http_raw_uri",
                             # The http_raw_uri keyword is a content modifie
                             # that restricts the search to the UNNORMALIZED
                             # request URI field.
                             # NOTE: The http_stat_code modifier is not allowed
                             # to be used with the rawbytes or fast_pattern
                             # modifiers for the same content.
                             "http_stat_code": "http_stat_code",
                             # The http_stat_code keyword is a content
                             # modifier that restricts the search to the
                             # extracted Status code field from a HTTP server
                             # response.
                             # NOTE: The http_stat_msg modifier is not allowed
                             # to be used with the rawbytes or fast_pattern
                             # modifiers for the same content.
                             "http_stat_msg": "http_stat_msg",
                             # The http_stat_msg keyword is a content modifier
                             # that restricts the search to the extracted
                             # status Message field from
                             # a HTTP server response.
                             # NOTE: Negation(!) and OR(|) operations cannot
                             # be used in conjunction
                             # with each other for the http_encode keyword.
                             # The OR and negation operations work only on the
                             # encoding type
                             #  field and not on http buffer type field.
                             # TODO: check for http_encode options
                             "http_encode": "http_encode",
                             # The http_encode keyword will enable alerting
                             # based on encoding type present in a HTTP client
                             # request or a HTTP server response
                             # NOTE: The fast_pattern modifier cannot be used
                             # with the following http content modifiers:
                             # 1. http_cookie,
                             # 2. http_raw_uri,
                             # 3. http_raw_header,
                             # 4. http_raw_cookie,
                             # 5. http_method,
                             # 6. http_stat_code,
                             # 7. http_stat_msg
                             # NOTE: The fast_pattern modifier can be used
                             # with negated contents only
                             # if those contents are not modified with
                             # 1. offset,
                             # 2. depth,
                             # 3. distance or
                             # 4.  within.
                             # NOTE: The fast pattern matcher is always case
                             # insensitive.
                             # TODO: check for fast_pattern format
                             "fast_pattern": "fast_pattern",
                             # The fast_pattern keyword is a content modifier
                             # that sets the content within a rule
                             # to be used with the fast pattern matcher.
                             # NOTE: uricontent cannot be modified by a
                             # rawbytes modifier or any of the other HTTP
                             # modifiers. If you wish to search the
                             # UNNORMALIZED request URI field,
                             # use the http_raw_uri modifier with a content
                             # option.
                             "uricontent": "uricontent",
                             # The uricontent keyword in the Snort
                             # rule language searches the normalized request
                             # URI field.
                             "urilen": "urilen",
                             # The urilen keyword in the Snort rule
                             # language specifies the exact length,
                             # the minimum length, the maximum length,
                             # or range of URI lengths to match.
                             "isdataat": "isdataat",
                             # The isdataat keyword verifies that the payload
                             # has data at a specified location.
                             # TODO: check for Perl compatible modifiers for
                             # pcre. NOTE: Since this is an advanced option,
                             # check the manual for pitfalls.
                             "pcre": "pcre",
                             # The pcre keyword allows rules to be written
                             # using perl compatible regular expressions.
                             "pkt_data": "pkt_data",
                             # This option sets the cursor used for detection
                             # to the raw transport payload. NOTE: The
                             # argument mime to file_data is deprecated.
                             # The rule options file_data will itself point
                             # to the decoded MIME attachment.
                             "file_data": "file_data",
                             # This option sets the cursor used for detection
                             # to one of the following buffers:
                             # 1. HTTP response body
                             # 2. HTTP de-chunked response body
                             # 3. HTTP decompressed response
                             # 4. HTTP normalized response body
                             # 5. HTTP UTF normalized response body
                             # 6. All of the above
                             # 7. SMTP/POP/IMAP data body
                             # 8. Base64 decoded MIME attachment
                             # 9. Non-Encoded MIME attachment
                             # 10. Quoted-Printable decoded MIME attachment
                             # 11. Unix-to-Unix decoded attachment
                             # TODO: check for base64_decode options and format
                             "base64_decode": "base64_decode",
                             # This option is used to decode the base64
                             # encoded data. This option is particularly
                             # useful in case of HTTP headers such as
                             # HTTP authorization headers.
                             # NOTE: Fast pattern content matches are not
                             # allowed with this buffer.
                             "base64_data": "base64_data",
                             # This option is similar to the rule option
                             # file_data and is used to set the cursor used
                             # for detection to the beginning of the base64
                             # decoded buffer if present.
                             # TODO: check for options
                             "byte_test": "byte_test",
                             # The byte_test keyword tests a byte field
                             # against a specific value (with operatori).
                             # TODO: check for options
                             "byte_jump": "byte_jump",
                             # The byte_jump keyword allows rules to read the
                             # length of a portion of data, then skip that
                             # far forward in the packet.
                             # NOTE: Only two byte_extract variables may be
                             # created per rule. They can be re-used in the
                             # same rule any number of times.
                             # TODO. check for options
                             "byte_extract": "byte_extract",
                             # It reads in some number of bytes from the
                             # packet payload and saves it to a variable.
                             # TODO: check for byte_math syntax and options
                             "byte_math": "byte_math",
                             # Perform a mathematical operation on an
                             # extracted value and a specified value or
                             # existing variable, and store the outcome in a
                             # new resulting variable
                             "ftpbounce": "ftpbounce",
                             # The ftpbounce keyword detects FTP bounce
                             # attacks.
                             # TODO. check for options and syntax for asn1
                             "asn1": "asn1",
                             # The asn1 detection plugin decodes a packet
                             # or a portion of a packet, and looks for
                             # various malicious encodings.
                             # NOTE: This plugin cannot do detection over
                             # encrypted sessions, e.g. SSH (usually port 22).
                             # TODO: find a way to check if the rule uses
                             # encrypted sessions
                             "cvs": "cvs",
                             # The cvs keyword detects invalid entry strings.
                             "dce_iface": "dce_iface",
                             # For DCE/RPC based rules it has been necessary
                             # to set flow-bits based on a client bind to a
                             # service to avoid false positives.
                             "dce_opnum": "dce_opnum",
                             # The opnum represents a specific function
                             # call to an interface.
                             "dce_stub_data": "dce_stub_data",
                             # This option is used to place the cursor
                             # (used to walk the packet payload in rule
                             # processing) at the beginning of the DCE/RPC
                             # stub data SIP Preprocessor provides ways
                             # to tackle Common Vulnerabilities and Exposures
                             # (CVEs) related with SIP found over the past
                             # few years.
                             "sip_method": "sip_method",
                             # The sip_method keyword is used to check
                             # for specific SIP request methods.
                             "sip_stat_code": "sip_stat_code",
                             # The sip_stat_code is used to check the
                             # SIP response status code. This option matches
                             # if any one of the state codes
                             # specified matches the status codes of the
                             # SIP response.
                             "sip_header": "sip_header",
                             # The sip_header keyword restricts the search
                             # to the extracted Header fields of a SIP message
                             # request or a response.
                             # This works similar to file_data.
                             "sip_body": "sip_body",
                             # The sip_body keyword places the cursor at the
                             # beginning of the Body fields of a SIP message.
                             # This works similar to file_data and
                             # dce_stub_data. The message body includes
                             # channel information using SDP protocol
                             # (Session Description Protocol).
                             # GTP (GPRS Tunneling Protocol) is used in core
                             # communication networks to establish a channel
                             # between GSNs (GPRS Serving Node). GTP decoding
                             # preprocessor provides ways to tackle
                             # intrusion attempts to those networks through
                             # GTP. It also makes detecting new attacks easier.
                             # TODO: identify also gtp message types, but for
                             # now keyword check has to cut it.
                             "gtp_type": "gtp_type",
                             # The gtp_type keyword is used to check for
                             # specific GTP types. User can input message
                             # type value, an integer in [0, 255], or a
                             # string defined in the Table below.
                             # TODO: gtp_info table check
                             "gtp_info": "gtp_info",
                             # The gtp_info keyword is used to check for
                             # specific GTP information element. This keyword
                             # restricts the search to the information
                             # element field. User can input information
                             # element value, an integer in  $[0, 255]$,
                             "gtp_version": "gtp_version",
                             # The gtp_version keyword is used to check for
                             # specific GTP version. Relates to gtp_info and
                             # gtp_type tables.
                             "ssl_version": "ssl_version",
                             # The ssl_version rule option tracks the version
                             # negotiated between the endpoints of the
                             # SSL encryption.
                             "ssl_state": "ssl_state"
                             # The ssl_state rule option tracks the state
                             # of the SSL encryption during the
                             # process of hello and key exchange.
                             # Encrypted traffic should be ignored by Snort
                             # for both performance reasons and to reduce
                             # false positives. The SSL Dynamic Preprocessor
                             # (SSLPP) decodes SSL and TLS traffic and
                             # optionally determines if and when Snort
                             # should stop inspection of it.
                             }

        content_modifiers = {"nocase": "nocase",
                             "rawbytes": "rawbytes",
                             "depth": "depth",
                             "offset": "offset",
                             "distance": "distance",
                             "within": "within",
                             "http_client_body": "http_client_body",
                             "http_cookie": "http_cookie",
                             "http_raw_cookie": "http_raw_cookie",
                             "http_header": "http_header",
                             "http_raw_header": "http_raw_header",
                             "http_method": "http_method",
                             "http_uri": "http_uri",
                             "http_raw_uri": "http_raw_uri",
                             "http_stat_code": "http_stat_code",
                             "http_stat_msg": "http_stat_msg",
                             "http_encode": "http_encode",
                             "fast_pattern": "fast_pattern",
                             "uricontent": "uricontent",
                             "urilen": "urilen",
                             "isdataat": "isdataat",
                             "pcre": "pcre",
                             "pkt_data": "pkt_data",
                             "file_data": "file_data",
                             "base64_decode": "base64_decode",
                             "base64_data": "base64_data",
                             "byte_test": "byte_test",
                             "byte_jump": "byte_jump",
                             "byte_extract": "byte_extract",
                             "byte_math": "byte_math",
                             "ftpbounce": "ftpbounce",
                             "asn1": "asn1",
                             "cvs": "cvs",
                             "dce_iface": "dce_iface",
                             "dce_opnum": "dce_opnum",
                             "dce_stub_data": "dce_stub_data",
                             "sip_method": "sip_method",
                             "sip_stat_code": "sip_stat_code",
                             "sip_header": "sip_header",
                             "sip_body": "sip_body",
                             "gtp_type": "gtp_type",
                             "gtp_info": "gtp_info",
                             "gtp_version": "gtp_version",
                             "ssl_version": "ssl_version",
                             "ssl_state": "ssl_state"
                             }

        non_payload_detect = {"fragoffset": "fragoffset",
                              # The fragoffset keyword allows one to
                              # compare the IP fragment offset field
                              # against a decimal value.
                              "ttl": "ttl",
                              # The ttl keyword is used to check the
                              # IP time-to-live value.
                              "tos": "tos",
                              # The tos keyword is used to check the IP TOS
                              # field for a specific value.
                              "id": "id",
                              # The id keyword is used to check the IP ID
                              # field for a specific value.
                              "ipopts": "ipopts",
                              # The ipopts keyword is used to check if a
                              # specific IP option is present.
                              "fragbits": "fragbits",
                              # The fragbits keyword is used to check if
                              # fragmentation and reserved bits are set in
                              # the IP header.
                              "dsize": "dsize",
                              # The dsize keyword is used to test the
                              # packet payload isize
                              # NOTE: The reserved bits '1' and '2'
                              # have been replaced with 'C' and 'E',
                              # respectively, to match RFC 3168,
                              # "The Addition of Explicit Congestion
                              # Notification (ECN) to IP".
                              # The old values of '1' and '2' are still
                              # valid for the flag keyword, but are now
                              # deprecated.
                              "flags": "flags",
                              # The flags keyword is used to check if
                              # specific TCP flag bits are present.
                              # TODO: check for syntax and options
                              "flow": "flow",
                              # The flow keyword allows rules to only apply
                              # to certain directions of the traffic flow.
                              # TODO. check for options and syntax
                              "flowbits": "flowbits",
                              # The flowbits keyword allows rules to track
                              # states during a transport protocol session.
                              "seq": "seq",
                              # The seq keyword is used to check for
                              # a specific TCP sequence number
                              "ack": "ack",
                              # The ack keyword is used to check for
                              # a specific TCP acknowledge number
                              "window": "window",
                              # The window keyword is used to check for
                              # a specific TCP window size
                              "itype": "itype",
                              # The itype keyword is used to check for
                              # a specific ICMP type value
                              "icode": "icode",
                              # The icode keyword is used to check for
                              # a specific ICMP code value
                              "icmp_id": "icmp_id",
                              # The icmp id keyword is used to check for
                              # a specific ICMP ID value.
                              "icmp_seq": "icmp_seq",
                              # The icmp seq keyword is used to check for
                              # a specific ICMP sequence value.
                              "rpc": "rpc",
                              # The rpc keyword is used to check for
                              # a RPC application, version, and procedure
                              # numbers in SUNRPC CALL requests
                              "ip_proto": "ip_proto",
                              # The ip proto keyword allows checks against
                              # the IP protocol header
                              "sameip": "sameip",
                              # The sameip keyword allows rules to check
                              # if the source ip is the same as the
                              # destination IP.
                              # NOTE: The stream_reassemble option is only
                              # available when the Stream preprocessor
                              # is enabled.
                              "stream_reassemble": "stream_reassemble",
                              # The stream_reassemble keyword allows a rule
                              # to enable or disable TCP stream
                              # reassembly on matching traffic.
                              # NOTE: The stream_size option is only
                              # available when the Stream preprocessor
                              # is enabled.
                              "stream_size": "stream_size"
                              # The stream_size keyword allows a rule to
                              # match traffic according to the number of
                              # bytes observed, as determined by the TCP
                              # sequence numbers.
                              }

        post_detect = {"logto": "logto",
                       # The logto keyword tells Snort to log all packets
                       # that trigger this rule to a special output log file.
                       "session": "session",
                       # The session keyword is built to extract user data
                       # from TCP Sessions
                       "resp": "resp",
                       # The resp keyword is used attempt to close
                       # sessions when an alert is triggered.
                       "react": "react",
                       # This keyword implements an ability for users to
                       # react to traffic that matches a Snort rule by
                       # closing connection and sending a noticei.
                       # NOTE: also check for options
                       "tag": "tag",
                       # The tag keyword allow rules to log
                       # more than just the single packet that triggered
                       # the rule
                       "activates": "activates",
                       # This keyword allows the rule writer to specify
                       # a rule to add when a specific network event occurs.
                       "activated_by": "activated_by",
                       # This keyword allows the rule writer to dynamically
                       # enable a rule when a specific activate rule is
                       # triggered.
                       "count": "count",
                       # This keyword must be used in combination with the
                       # activated by keyword. It allows the rule writer
                       # to specify how many packets to leave the rule
                       # enabled for after it is activated
                       "replace": "replace",
                       # Replace the prior matching content with the given
                       # string of the same length. Available in inline mode
                       # only. NOTE: As mentioned above, Snort evaluates
                       # detection_filter as the last step of the detection
                       # and not in post-detection.
                       "detection_filter": "detection_filter",
                       # Replace the prior matching content with the given
                       # string of the same length. Available in inline mode
                       # only.
                       "detection_filter": "detection_filter"
                       # Track by source or destination IP address and
                       # if the rule otherwise matches more than the
                       # configured rate it will fire.
                       }

        # TODO: add threshold types ex: threshold:
        # type limit <<, but for now, this will have to suffice
        rule_tresholds = {"threshold": "threshold"}

        # check if rule is of payload detect type
        if option in payload_detection:
            return "payload", payload_detection[option]
        if option in non_payload_detect:
            return "non-payload", non_payload_detect[option]
        if option in general_options:
            return "general", general_options[option]
        if option in rule_tresholds:
            return "threshold", rule_tresholds[option]
        if option in content_modifiers:
            return "content_modifier", content_modifiers[option]
        if option in post_detect:
            return "post_detect", post_detect[option]
