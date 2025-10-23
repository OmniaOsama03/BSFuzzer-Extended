
from scapy.compat import cast, raw
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.all import Raw
import os
import time
# from BSFuzz.libs.boofuzz.primitives import *
import logging
import random


import json
# from BSFuzz.srcs.prompt.SemFieldRspPrompt import get_prompt
from BSFuzz.srcs.Send_Packet.Bluetooth_SUL import Bluetooth_SUL
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
from BSFuzz.srcs.prompt.Packet_Description import PacketDescriptionGenerator
import re


class Fuzz_Session:
    def __init__(self, sul:Bluetooth_SUL, logger_handle = None, config_file = None, block_packet = None, block_packet_truncated = None, block_packet_add = None, output_file_path = None, pairing_type = None):   
        self.sul = sul
        self.logger = logging.getLogger(logger_handle)
        config_file = config_file
        self.block_packet = block_packet
        self.block_packet_truncated = block_packet_truncated
        self.block_packet_add = block_packet_add
        self.output_file_path = output_file_path

        # 解析config.json
        if config_file != None:
            with open(config_file, "r") as file:
                config = json.load(file)
                model_config = ModelConfig(config.get("llm", {}).get("model_provider"))
                model_config.update_config({"model":config.get("llm", {}).get("model"),"temperature":config.get("llm", {}).get("temperature"),})
                print(model_config.get_config())
                self.llm = model_config.get_llm()
                self.semfuzz_xml_path = config.get("semfuzz", {}).get("xml_file_path")
                # self.semseed_file_path = config.get("semfuzz", {}).get("semseed_file_path")
                # self.semseed_parser = SeedPacketParser(self.semseed_file_path)

                self.field_semseed_file_path = config.get("semfuzz", {}).get("field_seed_file_path").replace("${model_provider}",config.get("llm", {}).get("model_provider"))
                self.inner_field_semseed_file_path = config.get("semfuzz", {}).get("inner_field_seed_file_path").replace("${model_provider}",config.get("llm", {}).get("model_provider"))
                self.state_semseed_file_path = config.get("semfuzz", {}).get("state_seed_file_path").replace("${model_provider}",config.get("llm", {}).get("model_provider"))
       
        self.base_legency = ["ll_feature_req_pkt","ll_length_req_pkt","ll_version_ind_pkt","smp_pairing_request_pkt","smp_pairing_confirm_pkt","smp_pairing_random_pkt","ll_enc_req_pkt","ll_start_enc_rsp_pkt","smp_encryption_information_pkt","smp_master_identification_pkt","smp_identity_information_pkt","smp_identity_address_information_pkt","ll_pause_enc_req_pkt"] 
        self.base_sc = ["ll_version_ind_pkt","ll_feature_req_pkt","ll_length_req_pkt","smp_pairing_request_pkt","smp_pairing_public_key_pkt","smp_pairing_random_pkt","smp_pairing_dhkey_check_pkt","ll_enc_req_pkt","ll_start_enc_rsp_pkt","smp_encryption_information_pkt","smp_master_identification_pkt","smp_identity_information_pkt","smp_identity_address_information_pkt","ll_pause_enc_req_pkt"] 
        if pairing_type == "legency":
            self.base_path = self.base_legency
        elif pairing_type == "sc":  
    
            self.base_path = self.base_sc
        else:
            raise ValueError("pairing_type must be legency or sc")

    def fuzz(self):
        # 写入output_file_path
        #从后往前 fuzz
        # field mutation

        log =1157
        j = 0
        with open(self.field_semseed_file_path, 'r') as f:
            json_data = json.load(f)
        for i,mutation_packet in enumerate(self.base_path[::-1]):
            if "ll_" in mutation_packet:
                continue
            end = len(self.base_path)-i-1
           
            #读取field_semseed_parse.json 获取mutation 的依赖
            #json_data 获取每一个packet_name 的依赖
            for packet_name in json_data.keys():
                mutation_packet = mutation_packet.replace("smp_","")
             
                if packet_name == mutation_packet:
                    for mutation in json_data[packet_name]:

                        # 获取 megred xml中field_bit_length
                        j += 1
                        if j < log:
                            continue
                        if self.in_block_packet(mutation):
                            # print("in block packet")
                            
                            continue
                        # pkt = self.sul.get_packet(packet_name.replace("smp_",""))
                        packet_desc_gen = PacketDescriptionGenerator(self.semfuzz_xml_path)
                        field_bit_length = packet_desc_gen.get_field_bit_length(mutation[1], mutation[2])
                        byte_mutation = bytes.fromhex(mutation[3])
                        if (int.from_bytes(byte_mutation, byteorder='big') > (2**int(field_bit_length)-1)):
                            continue
                        outputs_pre = self.pre(self.base_path[:end])
                        # print(mutation)
                        pkt = self.sul.get_packet(packet_name.replace("smp_",""))
                        pkt.getlayer(mutation[1]).setfieldval(mutation[2], byte_mutation)
                        result = self.sul.packet_send_received_fuzz(pkt)
                        # if packet_name == "pairing_random_pkt":
                        #     pkt.show2()
                        # length = len(result)
                        # print(length)
                        outputs_pre.append(result[1])
                        if end == len(self.base_path)-1:
                            outputs_post = None
                            self.post()
                        else:
                            for pkt in self.base_path[end+1:]:
                                outputs_post = self.sul.step(pkt.replace("smp_",""))
                                outputs_pre.append(outputs_post)
                            self.post()
                        # 写入output_file_path
                        print("--------------base_path------------------")
                        bath_path = ",".join(f"({item.replace('smp_','')})" for item in self.base_path)
                        print(bath_path)
                        print("--------------outputs------------------")
                        outputs= ",".join(f"({item})" for item in outputs_pre)
                        print(outputs)
                      
                        print("--------------mutation------------------")
                        mutation_str = ",".join(mutation)
                        print(mutation_str)
                        print("--------------fuzz_result------------------")
                        print(result[0])
                     
        
                        with open(self.output_file_path, 'a') as f:
                            json.dump({
                                "base_path": bath_path,
                                "outputs": outputs,
                                "mutation": mutation_str,
                                "fuzz_result": result[0],
                                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                                "log": j
                            }, f)
                            f.write("\n")
                            





                        # result = self.analyze_mutation_result(packet_name, mutation[2], mutation[3], fuzz_result)
                        # print(result)
        # # structure mutation
        # for i,mutation_packet in enumerate(self.base_path[::-1]):
        #     if "ll_" in mutation_packet:
        #         continue
        #     end = len(self.base_path)-i-1
        #     mutation_packet = mutation_packet.replace("smp_","")
        #     base_truncated = self.in_block_packet_truncated(mutation_packet)
        #     pkt = self.sul.get_packet(mutation_packet)
            
        #     for add_length in range(len(raw(pkt))-base_truncated):
        #         # print(range(len(raw(pkt))-base_truncated))
        #         j += 1
        #         if j < log:
                    
        #             continue
                
        #         outputs_pre = self.pre(self.base_path[:end])
        #         sub_pkt = raw(pkt)[0:base_truncated+add_length]
        #         send_pkt = BTLE(sub_pkt)
        #         mutation_str = f"{mutation_packet} truncated to {base_truncated+add_length} bytes"
        #         result = self.sul.packet_send_received_fuzz(send_pkt)
        #         outputs_pre.append(result[1])
        #         if end == len(self.base_path)-1:
        #             outputs_post = None
        #             self.post()
        #         else:
        #             for pkt_name in self.base_path[end+1:]:
        #                 outputs_post = self.sul.step(pkt_name.replace("smp_",""))
        #                 outputs_pre.append(outputs_post)
        #             self.post()
        #         base_path = ",".join(f"({item.replace('smp_','')})" for item in self.base_path)
        #         outputs= ",".join(f"({item})" for item in outputs_pre)
               
        #         with open(self.output_file_path, 'a') as f:
        #             json.dump({
        #                 "base_path": base_path,
        #                 "outputs": outputs,
        #                 "mutation": mutation_str,
        #                 "fuzz_result": result[0],
        #                 "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        #                 "log": j
        #             }, f)
        #             f.write("\n")
                  
        # add length mutation
        # for i,mutation_packet in enumerate(self.base_path[::-1]):
        #     end = len(self.base_path)-i-1
        #     mutation_packet = mutation_packet.replace("smp_","")
        #     pkt = self.sul.get_packet(mutation_packet)
        #     for add_length in range(20):
        #         j += 1
        #         if j < log:
        #             continue
        #         if self.in_block_packet_add(mutation_packet):
        #             continue
        #         outputs_pre = self.pre(self.base_path[:end])
        #         send_pkt = pkt / Raw(os.urandom(random.randint(1,88)))
        #         mutation_str = f"{mutation_packet} add to {len(raw(send_pkt))} bytes"
        #         result = self.sul.packet_send_received_fuzz(send_pkt)
        #         outputs_pre.append(result[1])
        #         if end == len(self.base_path)-1:
        #             outputs_post = None
        #             self.post()
        #         else:
        #             for pkt in self.base_path[end+1:]:
        #                 outputs_post = self.sul.step(pkt.replace("smp_",""))
        #                 outputs_pre.append(outputs_post)
        #             self.post()
        #         base_path = ",".join(f"({item.replace('smp_','')})" for item in self.base_path)
        #         outputs= ",".join(f"({item})" for item in outputs_pre)
        #         with open(self.output_file_path, 'a') as f:
        #             json.dump({
        #                 "base_path": base_path,
        #                 "outputs": outputs,
        #                 "mutation": mutation_str,
        #                 "fuzz_result": result[0],
        #                 "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        #                 "log": j
        #             }, f)
        #             f.write("\n")
                  
        # # inner field mutation
        # with open(self.inner_field_semseed_file_path, "r") as f:
        #     json_data = json.load(f)
        # print("inner_field_semseed_file_path")
        # for i,mutation_packet in enumerate(self.base_path[::-1]):
        #     mutation_packet = mutation_packet.replace("smp_","")
        #     end = len(self.base_path)-i-1
        #     #读取inner_field_semseed_parse.json 获取mutation 
        #     for packet_name in json_data.keys():
        #         if packet_name == mutation_packet:
        #             for mutation in json_data[packet_name]:
        #                 mutations = mutation.values()
        #                 for mutation_fields in mutations:
        #                     for mutation_field in mutation_fields:
        #                         # print(mutation_field)


        #                         pkt = self.sul.get_packet(packet_name.replace("smp_",""))
        #                         packet_desc_gen = PacketDescriptionGenerator(self.semfuzz_xml_path)
        #                         field_bit_length = packet_desc_gen.get_field_bit_length(mutation_field[1], mutation_field[2])
        #                         byte_mutation = bytes.fromhex(mutation_field[3])
        #                         if (int.from_bytes(byte_mutation, byteorder='big') > (2**int(field_bit_length)-1)):
        #                             continue
        #                         pkt.getlayer(mutation_field[1]).setfieldval(mutation_field[2], byte_mutation)
        #                 j += 1
        #                 if j < log:
                                    
        #                     continue       

        #                 outputs_pre = self.pre(self.base_path[:end])
        #                 result = self.sul.packet_send_received_fuzz(pkt)

        #                 outputs_pre.append(result[1])
        #                 if end == len(self.base_path)-1:
        #                     outputs_post = None
        #                     self.post()
        #                 else:
        #                     for pkt_name in self.base_path[end+1:]:
        #                         outputs_post = self.sul.step(pkt_name.replace("smp_",""))
        #                         outputs_pre.append(outputs_post)
        #                     self.post()
        #                 # 写入output_file_path  
        #                 print("--------------base_path------------------")
        #                 bath_path = ",".join(f"({item.replace('smp_','')})" for item in self.base_path)
        #                 print(bath_path)
        #                 print("--------------outputs------------------")
        #                 outputs= ",".join(f"({item})" for item in outputs_pre)
        #                 print(outputs)
                    
        #                 print("--------------mutation------------------")
        #                 mutations_list = list(mutations)
        #                 print(mutations_list)
        #                 mutation_str = ",".join(f"({item})" for item in mutations_list[0])
        #                 print(mutation_str)
                     
        #                 print("--------------fuzz_result------------------")
        #                 print(result[0])

        #                 with open(self.output_file_path, 'a') as f:
        #                     json.dump({
        #                         "base_path": bath_path,
        #                         "outputs": outputs,
        #                         "mutation": mutation_str,
        #                         "fuzz_result": result[0],
        #                         "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        #                         "log": j
        #                     }, f)
        #                     f.write("\n")
                           
        # state mutation
        with open(self.state_semseed_file_path, "r") as f:
            json_data = json.load(f)
        for seqs in json_data:
            for key,value in seqs.items():
                if key == "path":
                    j += 1
                    if j < log:
                        continue
                    mutation_path = value.split(",")
                    # print(self.base_path)
                    outputs_pre = self.pre(mutation_path)
                    if "ll_enc_req_pkt" not in mutation_path:
                        mutation_path.extend(self.base_path[6:])
                        for pkt in self.base_path[6:]:
                            outputs_post = self.sul.step(pkt.replace("smp_",""))
                            outputs_pre.append(outputs_post)
                        self.post()
                    else:
                        outputs_post = None
                        self.post()
                    
                    print("--------------mutations------------------")
                    mutations = ",".join(f"({item.replace('smp_','')})" for item in mutation_path)
                    print(mutations)
                    print("--------------outputs------------------")
                    fuzz_result = ",".join(f"({item})" for item in outputs_pre)
                    print(fuzz_result)
                    with open(self.output_file_path, 'a') as f:
                        json.dump({
                            "base_path": mutations,
                            "outputs": fuzz_result,
                            "mutation": None,
                            "fuzz_result": None,
                            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                            "log": j
                        }, f)
                        f.write("\n")

    def fuzz_connect(self):
        # 写入output_file_path
        #从后往前 fuzz
        # field mutation
        self.base_path = ["scan_req","connect_req"]
        log = 0
        j = 0
        with open(self.field_semseed_file_path, 'r') as f:
            json_data = json.load(f)
        for i,mutation_packet in enumerate(self.base_path[::-1]):
            end = len(self.base_path)-i-1
           
            #读取field_semseed_parse.json 获取mutation 的依赖
            #json_data 获取每一个packet_name 的依赖
            for packet_name in json_data.keys():
             
                if packet_name == mutation_packet:
                    for mutation in json_data[packet_name]:
                        j += 1
                        if j < log:
                            continue
                            
                        if self.in_block_packet(mutation) :
                            continue
                        for i in range(2):
                        # 获取 megred xml中field_bit_length

                                # print("in block packet")
                                
                            
                            pkt = self.sul.get_packet(packet_name.replace("smp_",""))
                            packet_desc_gen = PacketDescriptionGenerator(self.semfuzz_xml_path)
                            field_bit_length = packet_desc_gen.get_field_bit_length(mutation[1], mutation[2])
                            byte_mutation = bytes.fromhex(mutation[3])
                            if (int.from_bytes(byte_mutation, byteorder='big') > (2**int(field_bit_length)-1)):
                                continue
                            outputs_pre = self.pre(self.base_path[:end])
                            print(mutation)
                            pkt.getlayer(mutation[1]).setfieldval(mutation[2], byte_mutation)
                            result = self.sul.packet_send_received_fuzz(pkt)
                            # length = len(result)
                            # print(length)
                            outputs_pre.append(result[1])
                            if end == len(self.base_path)-1:
                                outputs_post = None
                                self.post()
                            else:
                                for pkt in self.base_path[end+1:]:
                                    outputs_post = self.sul.step(pkt.replace("smp_",""))
                                    outputs_pre.append(outputs_post)
                                self.post()
                            
                            # 写入output_file_path
                        print("--------------base_path------------------")
                        bath_path = ",".join(f"({item.replace('smp_','')})" for item in self.base_path)
                        print(bath_path)
                        print("--------------outputs------------------")
                        outputs= ",".join(f"({item})" for item in outputs_pre)
                        print(outputs)
                    
                        print("--------------mutation------------------")
                        mutation_str = ",".join(mutation)
                        print(mutation_str)
                        print("--------------fuzz_result------------------")
                        print(result[0])
                        
                     
        
                        with open(self.output_file_path, 'a') as f:
                            json.dump({
                                "base_path": bath_path,
                                "outputs": outputs,
                                "mutation": mutation_str,
                                "fuzz_result": result[0],
                                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                                "log": j
                            }, f)
                            f.write("\n")
                            





                        # result = self.analyze_mutation_result(packet_name, mutation[2], mutation[3], fuzz_result)
                        # print(result)
        # structure mutation
        for i,mutation_packet in enumerate(self.base_path[::-1]):
            end = len(self.base_path)-i-1
            mutation_packet = mutation_packet.replace("smp_","")
            base_truncated = self.in_block_packet_truncated(mutation_packet)
            pkt = self.sul.get_packet(mutation_packet)
            
            for add_length in range(len(raw(pkt))-base_truncated):
                j += 1
                if j < log:
                    continue

                for i in range(2):
              
                    
                    outputs_pre = self.pre(self.base_path[:end])
                    sub_pkt = raw(pkt)[0:base_truncated+add_length]
                    send_pkt = BTLE(sub_pkt)
                    mutation_str = f"{mutation_packet} truncated to {base_truncated+add_length} bytes"
                    result = self.sul.packet_send_received_fuzz(send_pkt)
                    outputs_pre.append(result[1])
                    if end == len(self.base_path)-1:
                        outputs_post = None
                        self.post()
                    else:
                        for pkt_name in self.base_path[end+1:]:
                            outputs_post = self.sul.step(pkt_name.replace("smp_",""))
                            outputs_pre.append(outputs_post)
                        self.post()
                base_path = ",".join(f"({item.replace('smp_','')})" for item in self.base_path)
                outputs= ",".join(f"({item})" for item in outputs_pre)
               
                with open(self.output_file_path, 'a') as f:
                    json.dump({
                        "base_path": base_path,
                        "outputs": outputs,
                        "mutation": mutation_str,
                        "fuzz_result": result[0],
                        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                        "log": j
                    }, f)
                    f.write("\n")
                        
                    

    # def analyze_mutation_result(self,packet_name, field_name, mutated_value, response_desc):
    #     packet_desc_gen = PacketDescriptionGenerator(self.semfuzz_xml_path)
    #     field_desc = packet_desc_gen.get_field_description(packet_name, field_name)
    #     self.prompt = get_prompt(FIELD_DESC=field_desc, MUTATED_VALUE=mutated_value, RESPONSE_PACKET_DESC=response_desc)
    #     result = self.llm.invoke(prompt=self.prompt)
    #     return result.content
    
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

   

    def pre(self, path):
        self.sul.pre()
        outputs_list = []
        if len(path) != 0:
            for pkt in path:
                
                outputs = self.sul.step(pkt.replace("smp_",""))
                outputs_list.append(outputs)
        return outputs_list
    def post(self):
        self.sul.post()

    def in_block_packet(self,pkt):
        # print(pkt)
        # print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+"-------------block_packet-------------------")
        # print(self.block_packet)
        
        #先检查是否和block_packet中的packet_name 相同,如果都不同返回False，如果相同，检查是否和block_packet中的packet_layer 相同，如果相同，检查是否和block_packet中的field_name 相同，如果相同，返回True
        for block_pkt in self.block_packet:

            # print(block_pkt)
            if block_pkt["packet_name"] == pkt[0].replace("smp_",""):
                if block_pkt["packet_layer"] == pkt[1]:
                    if block_pkt["field_name"] == pkt[2]:
                            print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+"-------------block_packet-------------------")
                            return True
        return False
    
    def in_block_packet_truncated(self,pkt):
        base_truncated = 7
        for block_pkt in self.block_packet_truncated:
            if block_pkt["packet_name"] == pkt:
                if block_pkt["packet_layer"] == "BTLE_DATA":
                    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+"-------------BTLE_DATA_truncated-------------------")
                    base_truncated = 9
                elif block_pkt["packet_layer"] == "BTLE_CTRL":
                    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+"-------------BTLE_CTRL_truncated-------------------")
                    base_truncated = 13
                elif block_pkt["packet_layer"] == "33":
                    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+"-------------33_truncated-------------------")
                    base_truncated = 33
                return base_truncated
        return base_truncated
    

    def in_block_packet_add(self,pkt):
        for block_pkt in self.block_packet_add:
            if block_pkt["packet_name"] == pkt:
                return True
        return False


if __name__ == "__main__":

    semfuzz = Fuzz_Session()
    print(semfuzz.in_block_packet_truncated(("ll_start_enc_rsp_pkt","BTLE_DATA")))