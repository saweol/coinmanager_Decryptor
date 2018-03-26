#-*- coding: utf-8 -*-
import idaapi
import idautils


def DbgPrint(self, expandTable):
    for index, x in enumerate(expandTable):
      print hex(x),
      if index % 16 == 15:
        print '' # newline
    print "=================== END ==================="

def byte(data):
        return data & 0x000000FF

class dec:
    expandTable = []
    key = [0x85,0xc0,0x7C,0x17, 0x8B,0x4D,0xF4,0x8B,0x76,0x20,0x33,0xc0,0x3b,0xc8,0x77,0x0b]
    #encStr =  [0x10, 0x82, 0xDF, 0x19, 0xC8, 0x59, 0xAE, 0x4D, 0xED, 0xDB, 0xF9, 0x3F, 0x65, 0x9C, 0xF2, 0x77]
    encStr = []
    keySize = len(key)
    
    def SetEncStr(self,addr,size):
        data = GetManyBytes(addr,size)
        #print data.encode('hex')
        
        for ch in data:
            self.encStr.append(int('%02x' % ord(ch),16))
        
        print "Encrypted Str : ",self.encStr        
    
    def ExpandKey(self):
        keyIndex    = 0
        tableIndex  = 0
        index       = 0
        result      = 0


        # Generate 256 Table
        for x in range(0,256):
            self.expandTable.append(x)

        #Mixing Table Based Key
        #key = [0x85,0xc0,0x7C,0x17, 0x8B,0x4D,0xF4,0x8B,0x76,0x20,0x33,0xc0,0x3b,0xc8,0x77,0x0b]
        while index < 0x100:
            keyIndex = index % self.keySize
            index = index + 1
            tableIndex += ( self.expandTable[index - 1] + self.key[keyIndex] )
            tableIndex = byte(tableIndex)
            self.expandTable[index - 1], self.expandTable[tableIndex] = self.expandTable[tableIndex], self.expandTable[index - 1]

    def Decrypt(self):
        count    = 0     #self.expandTable + 0x100
        swpAdd = 0     #self.expandTable + 0x101
        swp      = 0
        size     = len(self.encStr) - 1
        print "DECRYPT : ",self.encStr
        
        #self.encStr = [63, 193, 153, 167, 38, 68, 126, 88, 54, 154, 171, 242, 147, 156]
        #size = len(self.encStr)
        
        while size > 0:
            count = count + 1
            swpAdd = byte(swpAdd + self.expandTable[count])
            swp = self.expandTable[count]
            self.expandTable[count] = self.expandTable[swpAdd]
            self.expandTable[swpAdd] = swp
            self.encStr[count] = self.encStr[count] ^ self.expandTable[byte(self.expandTable[swpAdd] + self.expandTable[count])]
            size = size - 1
        del(self.encStr[0])

        decStr = ""
        #print "DECRYPT : ",self.encStr
        #print "Encrypted Str : ", self.encStr 
        print "Decrypted Str : ","".join([chr(x) for x in self.encStr if x != 0])
        



    #key = [0x85,0xc0,0x7C,0x17, 0x8B,0x4D,0xF4,0x8B,0x76,0x20,0x33,0xc0,0x3b,0xc8,0x77,0x0b]
    #encStr = [0x08, 0x92, 0xD3, 0x03, 0xDD, 0x53, 0xA4, 0x4D, 0x88]

'''
if __name__ == "__main__":
    expandTable = []
    key = [0x85,0xc0,0x7C,0x17, 0x8B,0x4D,0xF4,0x8B,0x76,0x20,0x33,0xc0,0x3b,0xc8,0x77,0x0b]
    encStr =  [0x10, 0x82, 0xDF, 0x19, 0xC8, 0x59, 0xAE, 0x4D, 0xED, 0xDB, 0xF9, 0x3F, 0x65, 0x9C, 0xF2, 0x77]
    keySize = len(key)
    ExpandKey(expandTable,key,keySize)
    Decrypt(expandTable,encStr)


dtt = dec()
dtt.SetEncStr(0x4B1014,17)
dtt.ExpandKey()
dtt.Decrypt()
'''