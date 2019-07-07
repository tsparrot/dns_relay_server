# -*- coding: utf-8 -*-

import struct, sys, socket, getopt, time
from socketserver import BaseRequestHandler, ThreadingUDPServer


def bitslice(byte, offset, length):
    return (byte >> (7 - (offset + length - 1))) & ~(0xff << length)


class myserver(BaseRequestHandler):
    def handle(self):
        config = 'E:\query1.txt'
        nsip = '8.8.8.8'
        dlevel = 0
        recvData = self.request[0]
        qRecv = question()
        hRecv = header()
        hRecv.parse(recvData)
        qRecv.parse(recvData)
        domain = self.domainHandler(qRecv.qname)
        aRes = answer()

        try:
            opts, args = getopt.getopt(sys.argv[1:], 'd:n:c:', ["dd=", "ns=", "config="])
        except getopt.GetoptError:
            print('Wrong Arguments')
            sys.exit(1)

        for o, a in opts:
            if o == "-d":
                dlevel = a
            elif o == "-n":
                nsip = a
            elif o == "-c":
                config = a

        if self.localquery(domain, config):
            hRecv.rcode = 3
            aRes.response(qRecv.qname, self.localquery(domain, config))
            resData = self.response(recvData, aRes)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(recvData, (nsip, 53))
            resData = sock.recv(4096)
        output =""

        if dlevel == '1':
            #output = ""
            output += "当前时间为：%s\n" % time.asctime(time.localtime(time.time()))
            output += "Connected from: (%s,%s)\n" % self.client_address
            output += "查询的域名为：%s\n" % domain
            output += "ID=%s\n" % struct.unpack('>H', hRecv.id)
        elif dlevel == '2':
            #output = ""
            output += "当前时间为：%s\n" % time.asctime(time.localtime(time.time()))
            output += "Connected from: (%s,%s)\n" % self.client_address
            output += "查询的域名为：%s\n" % domain
            output += "--请求报文--\n"
            output += "--Header--\n"
            output += "ID=%s\nQR=%d " % (struct.unpack('>H', hRecv.id)[0], hRecv.qr)
            output += "OPCODE=%d " % hRecv.opcode
            output += "AA=%d TC=%d RD=%d\nRA=%d Z=%d " % (hRecv.aa, hRecv.tc, hRecv.rd, hRecv.ra, hRecv.z)
            output += "RCODE=%d\n" % hRecv.rcode
            output += "QDCOUNT=%s ANCOUNT=%s " % (
            struct.unpack('>H', hRecv.qdcount)[0], struct.unpack('>H', hRecv.ancount)[0])
            output += "NSCOUNT=%s ARCOUNT=%s\n" % (
            struct.unpack('>H', hRecv.nscount)[0], struct.unpack('>H', hRecv.arcount)[0])
            output += "--Question--\n"
            output += "QNAME=%s QTYPE=%s " % (domain, struct.unpack('>H', qRecv.qtype)[0])
            output += "QCLASS=%s\n" % struct.unpack('>H', qRecv.qclass)[0]
            '''
            output += "--响应报文--\n"
            output += "--Header--\n"
            output += "ID=%s\nQR=1" % struct.unpack('>H', hRecv.id)[0]
            output += "OPCODE=%d " % hRecv.opcode
            output += "AA=%d TC=%d RD=%d\nRA=%d Z=%d" % (hRecv.aa, hRecv.tc, hRecv.rd, hRecv.ra, hRecv.z)
            output += "RCODE=%d\n" % hRecv.rcode
            output += "QDCOUNT=%s ANCOUNT=%s" % (
                struct.unpack('>H', hRecv.qdcount)[0], struct.unpack('>H', hRecv.ancount)[0])
            output += "NSCOUNT=%s ARCOUNT=%s\n" % (
                struct.unpack('>H', hRecv.nscount)[0], struct.unpack('>H', hRecv.arcount)[0])
            output += "--Question--\n"
            output += "QNAME=%s QTYPE=%s " % (domain, struct.unpack('>H', qRecv.qtype)[0])
            output += "QCLASS=%s\n" % struct.unpack('>H', qRecv.qclass)[0]
            output += "--Answer--\n"
            output += "NAME     TYPE    CLASS   TTL\n"
            output += "%s       %s      %s      %s\n" %(domain, aRes.type, aRes.aclass, aRes.ttl)
        '''
        sys.stdout.write(output + '\n')
        self.request[1].sendto(resData, self.client_address)


        #把qname段转化为域名
    def domainHandler(self, qname):
        qtemp = ''
        i = 0
        while i < len(qname) - 1:
            seclength = qname[i]
            offset = i + 1
            qtemp = ('%s%s.' % (qtemp, str(qname[offset:offset+seclength], encoding='utf-8')))
            i = offset + seclength
        return qtemp[:-1]

    def localquery(self, domain, config):
        with open(config, 'r') as f:
            for line in f.readlines():
                line = line.strip()
                if not line:
                    break
                linelist = line.split(' ', 1)
                localdomain = linelist[1]
                localip = linelist[0]
                print(domain)
                print(localdomain)

                if domain == localdomain:
                    return localip
            return 0

    def response(self, recvData, answer):
        byte1 = struct.unpack('>B', recvData[2:3])[0]
        newbyte1 = 1 << 7 | bitslice(byte1, 1, 7)
        byte2 = struct.unpack('>B', recvData[3:4])[0]
        newbyte2 = bitslice(byte2, 0, 4) + 3
        responseData = recvData[0:2] + struct.pack('>2B', newbyte1, newbyte2) + recvData[4:]\
            + answer.name + struct.pack('>2HLHL', answer.type, answer.aclass, answer.ttl, answer.rdlength, answer.rdata)
        return responseData



class header(object):
    def parse(self, recvData):
        self.id = recvData[0:2]
        byte1 = struct.unpack('<B', recvData[2:3])[0]
        self.qr = bitslice(byte1, 0, 1)
        self.opcode = bitslice(byte1, 1, 4)
        self.aa = bitslice(byte1, 5, 1)
        self.tc = bitslice(byte1, 6, 1)
        self.rd = bitslice(byte1, 7, 1)
        byte2 = struct.unpack('<B', recvData[3:4])[0]
        self.ra = bitslice(byte2, 0, 1)
        self.z = bitslice(byte2, 1, 3)
        self.rcode = bitslice(byte2, 4, 4)
        self.qdcount = recvData[4:6]
        self.ancount = recvData[6:8]
        self.nscount = recvData[8:10]
        self.arcount = recvData[10:12]


class question(object):
    def parse(self, recvData):
        length = len(recvData)
        self.qname = recvData[12:length - 4]
        self.qtype = recvData[length - 4:length - 2]
        self.qclass = recvData[length - 2:]


class answer(object):
    def response(self, qname, ip):
        self.name = qname
        self.type = 1
        self.aclass = 1
        self.ttl = 600
        self.rdlength = 4
        ip = ip.split('.', 3)
        self.rdata = int(ip[0])*(1 << 24) + int(ip[1])*(1 << 16) + int(ip[2])*(1 << 8) + int(ip[3])


if __name__ == '__main__':
    serv = ThreadingUDPServer(('127.0.0.1', 53), myserver)
    serv.serve_forever()
