#!/usr/bin/python
import socket

def _get_question_section(query):
    # Query format is as follows: 12 byte header, question section (comprised
    # of arbitrary-length name, 2 byte type, 2 byte class), followed by an
    # additional section sometimes. (e.g. OPT record for DNSSEC)
    start_idx = 12
    end_idx = start_idx

    num_questions = (ord(query.data[4]) << 8) | ord(query.data[5])

    while num_questions > 0:
        while query.data[end_idx] != '\0':
            end_idx += ord(query.data[end_idx]) + 1
        # Include the null byte, type, and class
        end_idx += 5
        num_questions -= 1

    return query.data[start_idx:end_idx]

class DNSResponse(object):
    def __init__(self, query):
        self.id = query.data[:2]  # Use the ID from the request.
        self.flags = "\x81\x80"  # No errors, we never have those.
        self.questions = query.data[4:6]  # Number of questions asked...
        # Answer RRs (Answer resource records contained in response) 1 for now.
        self.rranswers = "\x00\x01"
        self.rrauthority = "\x00\x00"  # Same but for authority
        self.rradditional = "\x00\x00"  # Same but for additionals.
        # Include the question section
        self.query = _get_question_section(query)
        # The pointer to the resource record - seems to always be this value.
        self.pointer = "\xc0\x0c"
        # This value is set by the subclass and is defined in TYPE dict.
        self.type = None
        self.dnsclass = "\x00\x01"  # "IN" class.
        # TODO: Make this adjustable - 1 is good for noobs/testers
        self.ttl = "\x00\x00\x00\x01"
        # Set by subclass because is variable except in A/AAAA records.
        self.length = None
        self.data = None  # Same as above.

    def answer(self):
        try:
            return self.id + self.flags + self.questions + self.rranswers + \
                self.rrauthority + self.rradditional + self.query + \
                self.pointer + self.type + self.dnsclass + self.ttl + \
                self.length + self.data
        except (TypeError, ValueError):
            pass

class A(DNSResponse):
    def __init__(self, query, ip):
        super(A, self).__init__(query)
        self.type = "\x00\x01"
        self.length = "\x00\x04"
        self.data = ''.join(chr(int(x)) for x in ip.split('.'))

class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.domain = ''

        tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
        if tipo == 0:                     # Standard query
            ini = 12
            lon = ord(data[ini])
            while lon != 0:
                self.domain += data[ini+1:ini+lon+1]+'.'
                ini += lon+1
                lon = ord(data[ini])

if __name__ == '__main__':
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('',53))
  
    try:
        while 1:
            data, addr = udps.recvfrom(1024)
            q = DNSQuery(data)
            r = A(q, addr[0])
            udps.sendto(r.answer(), addr)
            print '%s -> %s' % (p.domain, addr[0])
    except KeyboardInterrupt:
      print 'Closing'
      udps.close()
