from networkx import DiGraph
from colorama import Fore
import random
import itertools
from scapy.packet import Packet, NoPayload, PacketListField, MultipleTypeField, ConditionalField
from scapy.compat import cast, raw
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.fields import StrField
from scapy.fields import Field, FlagValue

import struct
import logging
from BSFuzz.srcs.Packet_Fuzz.LayerRemove import RawData
from BSFuzz.srcs.parse_xml_test import SemanticParser
from langchain_openai import ChatOpenAI
import json
import os
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from BSFuzz.srcs.prompt.SemFieldRspPrompt import get_prompt
from BSFuzz.srcs.Send_Packet.Bluetooth_SUL import Bluetooth_SUL
from BSFuzz.srcs.llm_model.ModConf import ModelConfig

class Fuzz_Session:
    def __init__(self, sul:Bluetooth_SUL, graph:DiGraph,path_list, fuzz_layer, fuzz_session_filename, fuzz_sleep_time, logger_handle = None, fuzz_times = 200, untested_layer = [], unadd_layer = [], block_packet = [],data_add = False, data_remove = True, unremove_layer = [], config_file = None):   
        self.sul = sul
        self.graph = graph
        self.fuzz_session_filename = fuzz_session_filename
        self.fuzz_sleep_time = fuzz_sleep_time
        self.path_list = path_list
        self.exclude_list = ["UNKNOWN", "REJECT"]
        self.visited_state = set()
        self.visited_packet = set()
        self.same_state_request = {}
        self.diff_state_request = {}
        self.untested_field = ["ScanA","AdvA","InitA"]
        self.data_add = data_add
        self.data_remove = data_remove
        # fuzz_layer: list, for example: [BTLE_CTRL, BTLE_DATA]
        self.fuzz_layer = fuzz_layer
        self.fuzz_times = fuzz_times

        # 解析config.json
        if config_file != None:
            with open(config_file, "r") as file:
                config = json.load(file)
                self.model_provider = config.get("llm", {}).get("model_provider")
                self.model = config.get("llm", {}).get("model")
    
                self.semfuzz_xml_path = config.get("semfuzz", {}).get("xml_file_path")
            
        llm_config = ModelConfig(model_provider=self.model_provider)

        # self.untested_layer = [LL_CONNECTION_UPDATE_IND,LL_START_ENC_RSP]
        if len(untested_layer) > 0:
            self.untested_layer = [globals()[name] for name in untested_layer]  
        else:
            self.untested_layer = []
        # unadd_raw
        if len(unadd_layer) > 0:
            self.unadd_layer = [globals()[name] for name in unadd_layer]
        else:
            self.unadd_layer = [] 
        if len(unremove_layer) > 0:
            self.unremove_layer = [globals()[name] for name in unremove_layer]
        else:
            self.unremove_layer = []
        
      
        self.all_state_request = []

        self.block_packet = block_packet  
        print(f"Block Packet: {self.block_packet}")  
        self.logger = logging.getLogger(logger_handle)
        if self.semfuzz_xml_path != None:
            self.semantic_parser = SemanticParser(self.semfuzz_xml_path)
        else:
            self.semantic_parser = None
        if self.model != None:
            self.openai_client = ChatOpenAI(model=self.model, api_key=self.api_key)
        else:
            self.openai_client = None

        # 初始化提示模板
        self.prompt = get_prompt()
        # 初始化LLM Chain
        if self.model != None:
            llm=ChatOpenAI(model=self.model, api_key=self.api_key) 
            prompt = self.prompt
            self.chain =  prompt | llm
        
        else:
            self.chain = None

    # def get_raw_value(self):
    #     mutations = RandomData(min_length=0, max_length=3).get_mutations()
    #     value = random.choice(list(itertools.chain.from_iterable(mutations))).value
    #     return value

      

    def get_field_value(self, packet, field:Field):
        # 获取字段的语义和种子值
        semantic, defined_values,  seeds = self.semantic_parser.get_field_semantic(
            type(packet).__name__, 
            field.name
        )
        
        if seeds:
            # 如果有预定义的种子值，优先使用
            value = random.choice(seeds)
            return self.convert_value_type(value, field)
            
        if isinstance(field, StrField):

            print(f"{Fore.GREEN}Field Name: {field.name},{field.fmt},{field.i2m(packet, field.default)}, Field Default: {field.default}{Fore.RESET}")

            mutations = String(name=field.name,default_value=field.default).get_mutations()
            value = random.choice(list(itertools.chain.from_iterable(mutations))).value
            return value.encode('utf-8')



        if isinstance(field.default, FlagValue):
            field.default = int(field.default.value)
        else :
            pass
            # print(f"{Fore.YELLOW}Field Name: {field.name}, Field Default: {field.default}{Fore.RESET}")
        if field.sz < 1:
            mutations = Bit_Field(field.name, field.default, int(field.sz*8)).get_mutations()
            value = random.choice(list(itertools.chain.from_iterable(mutations))).value
            return int(value)
        elif field.sz == 1:
            mutations = Byte(field.name, field.default).get_mutations()
            value = random.choice(list(itertools.chain.from_iterable(mutations))).value
            return value
        elif field.sz > 1:
            if isinstance(field.i2m(packet, field.default), bytes):
                field_default_bytes = field.i2m(packet, field.default)
            else:
                field_default_bytes = struct.pack(field.fmt, field.i2m(packet, field.default))
                
            mutations = Bytes(field.name, field_default_bytes, field.sz).get_mutations()

            mutations_random= random.choice(list(itertools.chain.from_iterable(mutations)))
            if callable(mutations_random.value):
                value = mutations_random.value(field_default_bytes)
                return value
            else:
                return mutations_random.value

    # def convert_value_type(self, value, field):
    #     """将种子值转换为正确的数据类型"""
    #     try:
    #         if isinstance(field, StrField):
    #             return value.encode('utf-8')
    #         elif field.sz == 1:
    #             return int(value)
    #         elif field.sz > 1:
    #             return struct.pack(field.fmt, int(value))
    #     except Exception as e:
    #         self.logger.error(f"值转换失败: {e}")
    #         return None
        

    def load_semantic_parser(self, packet_name,field_name):
        data = self.semantic_parser.get_field_semantic(packet_name, field_name)
        return data

    def pre_field_selection(self, packet_name,path):
        
        packet = self.sul.packet_construction.get_pkt(packet_name)
        p = packet.copy()
        while not isinstance(p, NoPayload):
            if not isinstance(p, tuple(self.untested_layer)):
                for f in p.fields_desc:
                    semantic = self.load_semantic_parser(type(p).__name__, f.name)
                    print(f"Packet Name: {type(p).__name__}, Field Name: {f.name}")
                    print(f"Semantic: {semantic}")
                    if semantic == None:
                        print(f"Can't find semantic for {type(p).__name__} {f.name}")
                        self.logger.error(f"Can't find semantic for {type(p).__name__} {f.name}")
                        continue
                    else:
                        seeds = semantic[2]
                        for seed in seeds:
                            self.sul.pre()
                            self.sul.step(path)
                            p.setfieldval(f.name,seed)
                            response = self.sul.packet_send_received_control(p)
                            packet_description = []
                            for pkt in response:
                                packet_description.append(self.packet_to_description(pkt))
                
                    
                            # # 使用LLMChain分析语义
                            try:
                                result = self.chain.invoke(PACKET_NAME=packet_name, FIELD_NAME=f.name, FIELD_SEMANTIC=semantic[0], DEFAULT_VALUE=semantic[1], RESPONSE_PACKET_DESC=packet_description)
                                print("Analysis: "+result["result"])
                                
                                # 解析结果中的拒绝信息
                                is_rejected = "true" in result.lower() or "拒绝" in result
                                
                                    
                            except Exception as e:
                                self.logger.error(f"语义分析失败: {e}")

                            self.sul.post()

                p = p.payload
        
    # def packet_mutation(self, p:Packet,_inplace =0):

    #     if not _inplace:
    #         p = p.copy()
    #     q = p    

    #     if self.fuzz_layer is None:
    #         print("fuzz_layer should not None")
    #         return
    #     while not isinstance(q, tuple(self.fuzz_layer)):  

    #         q = q.payload
    #         if isinstance(q, NoPayload):
    #             print("Please check the fuzz_layer")
    #             return 
        
    #     while not isinstance(q, NoPayload):
    #         if isinstance(q, tuple(self.untested_layer)):
    #             print(f"{Fore.GREEN}Untested Layer Name: {q}{Fore.RESET}")
    #             q = q.payload
    #             continue  
    #         if isinstance(q, tuple(self.unadd_layer)):
    #             self.data_add = False 
    #         if isinstance(q, tuple(self.unremove_layer)):
    #             self.data_remove = False
    #         new_default_fields = {}
    #         multiple_type_fields = [] 
    #         # if isinstance(q, tuple(self.fuzz_layer)):    
    #         for f in q.fields_desc:
    #             #if f.name in q.fields.keys()
    #             # q.fields={}
    #             if (f.name in q.overloaded_fields) or (((f.default is None) and ("len" not in f.name)) and (((f.default is None) and ("Length" not in f.name ) ))) :
    #             # if (f.name in q.overloaded_fields) or (f.default is None) or (f.name in self.untested_field):
    #                 # self.untested_field[type(q).__name__] = f.name
                    
    #                 # print(((f.default is None) and ("len" not in f.name)))
    #                 print(f"{Fore.GREEN}Untested Field Name: {f.name} in layer {type(q).__name__}{Fore.RESET}")
    #                 continue
    #             if isinstance(f, PacketListField):
    #                 for r in getattr(q, f.name):
    #                     self.packet_mutation(r, _inplace=1)
    #             elif isinstance(f, MultipleTypeField):
    #                 # the type of the field will depend on others
    #                 multiple_type_fields.append(f.name)
    #             elif f.default is not None or ("len" in f.name or "Len" in f.name)  :
    #             #elif f.default is not None :
    #                 if not isinstance(f, ConditionalField) or f._evalcond(q):
    #                     rnd = self.get_field_value(q,f)
    #                     if rnd is not None:
    #                         # p.setfieldval(f.name,rnd)
    #                         if isinstance(rnd, bytes):
    #                             new_default_fields[f.name] = rnd
    #                         else:
    #                             new_default_fields[f.name] = f.any2i(p,rnd)
    #             # Process packets with MultipleTypeFields
    #             if multiple_type_fields:
    #                 # freeze the other random values
    #                 new_default_fields = {
    #                     key: (val._fix() if isinstance(val, VolatileValue) else val)
    #                     for key, val in six.iteritems(new_default_fields)
    #                 }
    #                 q.default_fields.update(new_default_fields)
    #                 # add the random values of the MultipleTypeFields
    #                 for name in multiple_type_fields:
    #                     fld = cast(MultipleTypeField, q.get_field(name))
    #                     rnd = self.get_field_value(q,fld._find_fld_pkt(q))
    #                     if rnd is not None:
    #                         new_default_fields[name] = f.any2i(p,rnd)
    #             # for name, val in six.iteritems(new_default_fields):
                    # p.setfieldval(f.name,val)
                    
    #         # else:
    #         #     pass 
          
    #         q.default_fields.update(new_default_fields) 
    #         q = q.payload


    #     rd = RawData(p,remove = self.data_remove,add = self.data_add)
    #     return_pkt = rd.random_choice()  
    #     return return_pkt
    def pre(self, path):
        self.sul.pre()
        # for packet in path:
        print(f"Path: {path}")
        if len(path) != 0:
            self.sul.step(path)
    def post(self):
        self.sul.post()

    def analyze_response_semantic(self, response_packet):
        """分析响应数据包的语义"""
        # 将数据包转换为文本描述



    def packet_to_description(self, packets):
        """将数据包转换为文本描述"""
        if not isinstance(packets, list):
            packets = [packets]
            
        descriptions = []
        for index,packet in enumerate(packets):
            last_layer = packet.lastlayer()
            packet_name = type(last_layer).__name__
            description = [f"The {index+1} packet name: {packet_name}"]
            
            # 只添加最后一层的字段值
            for field_name, field_value in last_layer.fields.items():
                description.append(f"  {field_name}: {field_value}")
                
            descriptions.append("\n".join(description))
            #添加返回数据包的数量
        return "Total response packets number: "+str(len(packets))+"\n\n"+ "\n\n".join(descriptions)

    def fuzz(self):
        self.get_state_request()
        print(self.same_state_request)
        print(self.diff_state_request)
        print(self.all_state_request)
        # 按照顺序fuzz all packets
        for packet_name,path in (self.same_state_request.items() and self.diff_state_request.items()):
            print(f"Packet Name: {packet_name}, Path: {path}")  
            self.pre_field_selection(packet_name,path)
            break


        #     print(f"Packet Name: {packet_name}, Path: {path}")
        #     for i in range(self.fuzz_times):
        #         self.pre(path)
        #         packet = self.sul.packet_construction.get_pkt(packet_name)
        #         mutation_packet = self.packet_mutation(packet)
        #         if self.block_packet:
        #             for block in self.block_packet:

        #                 if block[0] == packet_name:
        #                     mutation_packet.getlayer(block[1]).fields[block[2]] = block[3]
        #                 else:
        #                     pass
                
        #         mutation_packet.show2()
                
        #         # 发送变异数据包并接收响应
        #         response = self.sul.packet_send_received_control(mutation_packet)
        #         for pkt in response:
        #             packet_description = self.packet_to_description(pkt)
      
        
        #         # # 使用LLMChain分析语义
        #         try:
        #             result = self.chain.invoke(PACKET_NAME=packet_name, FIELD_NAME="MaxTxOctets", FIELD_SEMANTIC="The maximum number of octets the sender can transmit in a single Data Channel PDU.", DEFAULT_VALUE="27 (0x001B) to 251 (0x00FB)", RESPONSE_PACKET_DESC="LL_LENGTH_RSP")
        #             print(f"Analysis: {result}")
                    
        #             # 解析结果中的拒绝信息
        #             is_rejected = "true" in result.lower() or "拒绝" in result
                    
                        
        #         except Exception as e:
        #             self.logger.error(f"语义分析失败: {e}")
                   
                        
        #         # 分析响应的语义
                
                
        #         if is_rejected:
        #             self.logger.info(f"变异被拒绝: {analysis}")
        #         else:
        #             self.logger.info(f"变异被接受: {analysis}")
                
        #         self.post()

        # # fuzz 不同状态的所有数据包
        # for request in self.all_state_request:
        #     packet_name = request[0]
        #     for i in range(self.fuzz_times):
        #         self.pre(request[1])
        #         packet = self.sul.packet_construction.get_pkt(packet_name)
        #         packet.show2()
        #         mutation_packet = self.packet_mutation(packet)
        #         if self.block_packet:
        #             for block in self.block_packet:
        #                 print(f"packet_name: {packet_name}, block[0]: {block[0]}")
        #                 if block[0] == packet_name:
        #                     mutation_packet.getlayer(block[1]).fields[block[2]] = block[3]
        #                 else:
        #                     pass
        #         mutation_packet.show2()
        #         if mutation_packet.haslayer("SM_Hdr"):
        #             self.sul.packet_send_received(mutation_packet)
        #         else:
        #             self.sul.packet_send_received_control(mutation_packet)
        #         self.post()
        # # fuzz 状态混淆
        # for request in self.all_state_request:
        #     for i in range(self.fuzz_times):
                    
        #         packet = self.sul.packet_construction.get_pkt(request[0])
        #         mutation_packet = self.packet_mutation(packet)
        #         if self.block_packet:
        #             for block in self.block_packet:
        #                 if block[0] == packet_name:
        #                     mutation_packet.getlayer(block[1]).fields[block[2]] = block[3]
        #                 else:
        #                     pass

        #         request[1].insert(random.randint(0,len(request[1])), mutation_packet)
        #         # print(f"path: {request[1]}, packet: {mutation_packet}")
        #         self.pre(request[1])
        #         self.post()
        #         request[1].remove(mutation_packet)




    def get_state_request(self):
       
        for path in self.path_list:
            for i in reversed(range(len(path))):
                packet_path = []
              
                self.current_node = path[i]
                # 找到相同状态中packet
                edge = self.graph.get_edge_data(self.current_node, self.current_node)
                if edge:

                    for j in range(i-1):
                        current_node_edge = self.graph.get_edge_data(path[j], path[j+1])['lable'].split(", ")

                        random_packet = random.choice(current_node_edge).split("/")[0]
                        packet_path.append(random_packet)

                    for packet in edge['lable'].split(", "):
                        packet = packet.split("/")[0]
                        self.all_state_request.append((packet, packet_path))
                        if packet in self.same_state_request.keys():
                            
                            continue
                        self.same_state_request[packet] = packet_path
                        
                
        for path in self.path_list:
            for i in reversed(range(len(path))):
                packet_path = []

                self.current_node = path[i] 
                # 找到不同状态中packet       
                for j in range(i):
                    current_node_edge = self.graph.get_edge_data(path[j], path[j+1])['lable'].split(", ")

                    random_packet = random.choice(current_node_edge).split("/")[0]
                    packet_path.append(random_packet)                    
                if i == (len(path)-1):
                    continue
                else:
                    for packet in self.graph.get_edge_data(self.current_node,path[i+1])['lable'].split(", "):
                        packet_name = packet.split("/")[0]
                        if any(s in packet.split("/")[1] for s in self.exclude_list):
                            continue
                        self.all_state_request.append((packet_name, packet_path))
                        if packet_name in self.same_state_request.keys() or packet_name in self.diff_state_request.keys() :    
                            continue

                        self.diff_state_request[packet_name] = packet_path
                    
                    print(f"Curren Node: {self.current_node}, Packet: {packet}, Packet Path: {packet_path}")




