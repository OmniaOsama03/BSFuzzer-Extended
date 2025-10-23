from BSFuzz.libs.scapy.all import *
from BSFuzz.libs.scapy.layers.bluetooth4LE import *
from BSFuzz.libs.boofuzz.primitives import *


class RawData():
    def __init__(self, pkt:Packet, remove = True, add = True):
        self.pkt = pkt
        self.remove = remove
        self.add = add

    def get_raw_value(self,min_length=0, max_length=3):
        mutations = RandomData(min_length=min_length, max_length=max_length).get_mutations()
        value = random.choice(list(itertools.chain.from_iterable(mutations))).value
        return value

    def remove_data(self):
        pkt = self.pkt.copy()
        raw_pkt = raw(pkt)
        origin_len = len(raw_pkt)
        current_layer = pkt
        while current_layer.payload:
            if not current_layer.payload.payload:
                current_layer.remove_payload()
                break
            current_layer = current_layer.payload   
        max_len = origin_len - len(raw(pkt))   
        mutations = self.get_raw_value(min_length=0, max_length=max_len)
        raw_pkt = raw_pkt[:len(pkt)-3] + mutations + b"\x00\x00\x00"
        pkt = BTLE(raw_pkt)
        pkt["BTLE"].crc = None
        return pkt

        
        
    
    def add_data(self):
        pkt = self.pkt / Raw(self.get_raw_value())
        return pkt
    
    def orignal_pkt(self):
        pkt = self.pkt
        return pkt
    


    
    def random_choice(self):
        function_list = []
        weights = []
        if self.remove:
            function_list.append(self.remove_data)
            weights.append(0.1)
        if self.add:
            function_list.append(self.add_data)
            weights.append(0.1)

        if not function_list:
            return self.pkt
        else:
            function_list.append(self.orignal_pkt)
            weights.append(0.8)
            func = random.choices(function_list,weights,k=1)[0]
            return func()
    
