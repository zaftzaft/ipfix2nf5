import struct

class IPFIXDecoder(object):

    def __init__(self):
        self.template = {}
        #self.raw = raw
        #self.counter = 0


    def import_template(self, template):
        self.template = template


    def set_raw(self, raw):
        #print("[***] set_raw")
        self.raw = raw
        self.counter = 0


    def decode(self):
        self.flows = []

        version, length, timestamp, seqnum, obid = struct.unpack(">HHIII", self.raw[0:16])
        self.counter += 16

        while True:
            if len(self.raw) < self.counter + 4:
                break

            setid, setlen = struct.unpack(">HH", self.raw[self.counter:self.counter + 4])
            self.counter += 4

            #print("> Set", setid, setlen)

            if setid == 2:
                base = self.counter - 4
                #print(base, base + setlen)
                while self.counter < base + setlen:
                    #print(self.counter, base + setlen)
                    tempid, fldcount = struct.unpack(">HH", self.raw[self.counter:self.counter + 4])
                    self.counter += 4
                    #print(">> Template:", tempid, fldcount)
                    print(">> Template:", tempid)

                    self.template[tempid] = []

                    self.decode_template(tempid, fldcount)

            elif setid == 3:
                base = self.counter - 4
                #print(base, base + setlen)

                while self.counter < base + setlen:
                    tempid, fldcount, scopecount = struct.unpack(">HHH", self.raw[self.counter:self.counter + 6])
                    self.counter += 6
                    #print(">> Opt Template", tempid, fldcount, scopecount)
                    self.template[tempid] = []
                    self.decode_template(tempid, fldcount)

            elif setid > 255:
                base = self.counter - 4
                print(">> data")
                while self.counter - base < setlen:
                    #print(self.counter, base ,setlen, len(self.raw))
                    if not self.decode_data(setid, {}, 0):
                        self.counter = base + setlen
                        print(">> data skip")

                       # break


            else:
                n = self.counter - 100
                if n < 0:
                    n = 0

                #hexdump(self.raw[n:self.counter ])
                #print("[*] undefined setid")
                #hexdump(self.raw[self.counter - 4:self.counter + 200])
                break

        return self.flows


    def decode_template(self, tempid, fldcount):
        for i in range(0, fldcount):
            elmid,fldlen = struct.unpack(">HH", self.raw[self.counter:self.counter + 4])
            self.counter += 4

            if elmid & 0x8000:
                enterprise = struct.unpack(">I", self.raw[self.counter:self.counter + 4])
                self.counter += 4

                #if not enterprise[0] in pen:
                #    hexdump(raw[counter - 12:counter + 12])
                #    return

                #print(">>> Enterprise", elmid, fldlen, pen[enterprise[0]])
                self.template[tempid].append([elmid, fldlen, enterprise[0]])
            else:
                #if elmid in element_id:
                #    #print(">>>", element_id[elmid], fldlen)
                #    pass
                #else:
                #    print("--", counter, elmid)
                #    continue
                self.template[tempid].append([elmid, fldlen])


    def decode_data(self, template_id, flow={}, depth=0):
        broken = False

        if not template_id in self.template:
            #print(">> template is not exists")
            print("[*] template {0} is not exists".format(template_id))
            return False

        #print(">> template exists")


        for temp in self.template[template_id]:
            #name = element_id[temp[0]] if temp[0] in element_id else temp[0]
            name = temp[0]

            if temp[0] in (291, 292, 293):
                try:
                    #print(">>+ list", temp[0])

                    # sub template Header
                    if self.raw[self.counter:self.counter + 1] is not b"\xff":
                        print(">>@ broken sub template header;", temp[0])
                        broken = True
                        break
                        #return False
    #                    print(1)
    #                    print(self.counter, len(self.raw))
    #                    print(self.raw[self.counter:self.counter + 4])
                    #print(self.counter, len(self.raw))

                    self.counter += 1 # skip fixed field 0xff
                    attrLen = struct.unpack(">H", self.raw[self.counter:self.counter + 2])[0]
                    self.counter += 2
                    semantic = struct.unpack(">B", self.raw[self.counter:self.counter + 1])[0]
                    self.counter += 1

                    #print(">>@", "attrLen", attrLen, "semantic", semantic)

                    sub_temp_id = struct.unpack(">H", self.raw[self.counter:self.counter + 2])[0]
                    self.counter += 2
                    sub_temp_len = struct.unpack(">H", self.raw[self.counter:self.counter + 2])[0]
                    self.counter += 2

                    #print("sub_temp_id", sub_temp_id, "sub_temp_len", sub_temp_len)

                    if sub_temp_id in self.template:
                        #print(">>@ sub template exists")
                        self.decode_data(sub_temp_id, flow, 1)
                        #print(">>@ sub template exists]")
                    else:
                        #print(">>@ sub template not exists")
                        break

                except:
                    print("err")
                    return False



            else:
                #print(">>+", name, "[", temp[0], "]", temp[1], self.raw[self.counter:self.counter + temp[1]])
                flow[temp[0]] = self.raw[self.counter:self.counter + temp[1]]
                self.counter += temp[1]
                #print(self.counter, setlen, base)
        #print(">> data END")

        if depth == 0:
            self.flows.append(flow)

        if broken:
            return False

        return True

