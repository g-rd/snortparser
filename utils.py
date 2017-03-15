import re
import socket
from uuid import UUID


class Utils():

    def __ipv4(self, ip):
        rex = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}){1}$|'
                         '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})$')
        if not re.match(rex, ip):
            return ValueError("Not an ipv4 IP")
        if "/" in ip:
            iprange = ip.split("/")
            ip = iprange[0]
            subnet_start = ip.split(".")
            size = iprange[-1]
            if int(subnet_start[-1]) > 0 and int(size) < 32:
                return ValueError("subnet start is not correct")
            try:
                int(size)
            except:
                return ValueError("not int")
            if int(size) > 32 or int(size) < 0:
                return ValueError("out of range")

        try:
            socket.inet_pton(socket.AF_INET, ip)
        except socket.error as e:
            return ValueError(e)
        else:
            return True

    def __ipv6(self, ip):
        spechial_ipv6 = {"unspecfified": "::/128",
                         "default route": "::/0",
                         "loopback": "::1/128"
                         }

        if ip in spechial_ipv6.values():
            return True

        if "/" in ip:
            iprange = ip.split("/")
            ip = iprange[0]
            size = iprange[-1]
            try:
                int(size)
            except:
                return ValueError("not int")
            if int(size) == 127:
                return True
            if int(size) > 64 or int(size) < 0:
                return ValueError("out of range")

        try:
            socket.inet_pton(socket.AF_INET6, ip)
        except socket.error:
            return False
        else:
            return True

    def valid_ip(self, ip):
        tests = {}
        tests["ipv4"] = self.__ipv4(ip)
        tests["ipv6"] = self.__ipv6(ip)
        if True not in tests.values():
            return False
        else:
            return True
