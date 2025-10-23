from networkx import DiGraph
from colorama import Fore
import random
import itertools
from scapy.packet import Packet, NoPayload, PacketListField, MultipleTypeField, ConditionalField
from scapy.compat import cast, raw
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from BSFuzz.libs.boofuzz.cli import fuzz
from BSFuzz.libs.boofuzz.primitives import *
import logging
from BSFuzz.srcs.Packet_Fuzz.LayerRemove import RawData


import json
import os
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from BSFuzz.srcs.prompt.SemFieldRspPrompt import get_prompt
from BSFuzz.srcs.prompt.SemDepRspPrompt import get_dep_prompt
from BSFuzz.srcs.Send_Packet.Bluetooth_SUL1 import Bluetooth_SUL
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
from BSFuzz.srcs.prompt.Packet_Description import PacketDescriptionGenerator
import re
from fuzzywuzzy import process
from BSFuzz.srcs.Packet_Fuzz.SeedPacketParse import SeedPacketParser


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
        config_file = "/home/yangting/Documents/Semantic/config/semfuzz_config.json"


        # 解析config.json
        if config_file != None:
            with open(config_file, "r") as file:
                config = json.load(file)
                model_config = ModelConfig(config.get("llm", {}).get("model_provider"))
                model_config.update_config({"model":config.get("llm", {}).get("model"),"temperature":config.get("llm", {}).get("temperature"),})
                print(model_config.get_config())
                self.llm = model_config.get_llm()
                self.semfuzz_xml_path = config.get("semfuzz", {}).get("xml_file_path")
                self.semseed_file_path = config.get("semfuzz", {}).get("semseed_file_path")
                self.semseed_parser = SeedPacketParser(self.semseed_file_path)
                
              
        # self.untested_layer = [LL_CONNECTION_UPDATE_IND,LL_START_ENC_RSP]
        if len(untested_layer) > 0:
            self.untested_layer = [globals()[name] for name in untested_layer]  
        else:
            self.untested_layer = []
        # # unadd_raw
        # if len(unadd_layer) > 0:
        #     self.unadd_layer = [globals()[name] for name in unadd_layer]
        # else:
        #     self.unadd_layer = [] 
        # if len(unremove_layer) > 0:
        #     self.unremove_layer = [globals()[name] for name in unremove_layer]
        # else:
        #     self.unremove_layer = []
        
      
        # self.all_state_request = []

        # self.block_packet = block_packet  
        print(f"Block Packet: {self.block_packet}")  
        self.logger = logging.getLogger(logger_handle)

  
        self.prompt = get_prompt()
  
    def get_mutation_seeds(self,packet_name, field_name):
        """
        从 semseed.json 获取指定字段的测试种子
        """
        try:
            with open(self.semseed_file_path, 'r') as f:
                json_data = json.load(f)
                
            for packet in json_data.get("packets", []):
                if packet["name"] == packet_name:
                    for field in packet.get("fields", []):
                        if field["name"] == field_name:
                            return field.get("mutations", [])
        except Exception as e:
            print(f"读取种子文件失败: {str(e)}")
            return []
    def analyze_mutation_result(self,packet_name, field_name, mutated_value, response_desc):
        packet_desc_gen = PacketDescriptionGenerator(self.semfuzz_xml_path)
        field_desc = packet_desc_gen.get_field_description(packet_name, field_name)
        self.prompt = get_prompt(FIELD_DESC=field_desc, MUTATED_VALUE=mutated_value, RESPONSE_PACKET_DESC=response_desc)
        result = self.llm.invoke(prompt=self.prompt)
        return result.content
    
    def extract_judgment(result):

        try:
            # 使用正则表达式匹配 <Judgment> 标签中的内容
            judgment_match = re.search(r'<Judgment>(.*?)</Judgment>', result, re.DOTALL)
            if judgment_match:
                judgment = judgment_match.group(1).strip()
                return judgment
            return None
        except Exception as e:
            print(f"提取判断结果失败: {str(e)}")
            return None

    def field_mutation(self, packet_name,path):
        
        packet = self.sul.packet_construction.get_pkt(packet_name)
        p = packet.copy()
        while not isinstance(p, NoPayload):
            if not isinstance(p, tuple(self.untested_layer)):
                for f in p.fields_desc:
                    mutations = self.semseed_parser.get_field_mutations(packet_name, f.name)
                    for seed in mutations:
                        test_value = seed.get(f.name)
                        self.sul.pre()
                        self.sul.step(path)
                        p.setfieldval(f.name,test_value)
                        response = self.sul.packet_send_received_control(p)
                        result = self.analyze_mutation_result(packet_name, f.name, test_value, self.packet_to_description(response))
                        print(result)
                        if self.extract_judgment(result) == "Incorrect":
                            self.logger.info(f"Incorrect: {result}")
                        elif self.extract_judgment(result) == "Correct":
                            self.logger.info(f"Correct: {result}")
                        elif self.extract_judgment(result) == "Inconclusive":
                            self.logger.info(f"Inconclusive: {result}")
                        else:
                            self.logger.error(f"Answer Format Error: {result}")
                        self.sul.post()


            p = p.payload

    def field_dependency_mutation(self,packet_name,path):
        packet = self.sul.packet_construction.get_pkt(packet_name)
        p = packet.copy()
        while not isinstance(p, NoPayload):
            if not isinstance(p, tuple(self.untested_layer)):
                for f in p.fields_desc:
                    dependency_mutations = self.semseed_parser.get_field_dependency_mutations(packet_name, f.name)
                    for dependency_mutation in dependency_mutations:
                        send_pkt_list = []
                        received_pkt_list = []

                        items = list(dependency_mutation.items()) 
                        # item[0][1] 是依赖的field name item[1][1] 是依赖的packet name item[2][0]是依赖的field 名称 item[2][1] 是依赖的field value
                        #先判断是依赖的packet name 是否在path中
                        try:
                            for letter in path:
                                pkt = self.sul.packet_construction.get_pkt(letter)
                                list_pkt = pkt.summary().split("/")
                            
                                if items[1][1] in list_pkt:
                                    pkt.getlayer(items[1][1]).setfieldval(items[2][0],items[2][1])
                                if type(p).name in list_pkt:
                                    p.getlayer(type(p).name).setfieldval(items[0][0],items[0][1])

                                send_pkt = self.sul.packet_construction.send_packet_handler(pkt)
                                receive_pkt = self.sul.packet_send_received_control(send_pkt)
                                send_pkt_list.append(letter)
                                received_pkt_list.append(receive_pkt)
                        except Exception as e:
                            print(f"Error: {items}")
                            continue
                        
                        mutinf = f"In the input packets:The {items[0][0]} field of the {type(p).name} is {items[0][1]}. The {items[2][0]} field of the {items[1][1]} is {items[2][1]}. In the output packets:The {items[0][0]} field of the {type(p).name} is {items[0][1]}. The {items[2][0]} field of the {items[1][1]} is {items[2][1]}. "
                        result = self.analyze_response_semantic(send_pkt_list,received_pkt_list,mutinf)
                        print(result)
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

    def analyze_response_semantic(self, inputseq,outputseq,mutation_information):
        self.prompt = get_dep_prompt(INSEQ=inputseq,OUTSEQ=outputseq,MUTINF=mutation_information)
        result = self.llm.invoke(prompt=self.prompt)
        return result.content




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




