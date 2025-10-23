import os
import sys


sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")


from BSFuzz.srcs.Send_Packet.Bluetooth_SUL1 import Bluetooth_SUL
from BSFuzz.libs.driver.NRF52_dongle import NRF52Dongle

from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Config_File.Cypress import config
from scapy.packet import NoPayload
import json
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
from BSFuzz.srcs.prompt.SemFieldMutation import get_prompt
from BSFuzz.srcs.prompt.IndexPacketPrompt import get_question
from BSFuzz.srcs.Pdf_Sem.PdfDb import load_documents
from BSFuzz.srcs.prompt.Packet_Description import PacketDescriptionGenerator
# from langchain_community.retrievers import BM25Retriever
# from langchain.retrievers import EnsembleRetriever


Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_legency_pkts",6:"test_sc_pkts"}

# sul config
advertiser_address = config.device["advertiser_address"]
iat = config.device["iat"]
rat = config.device["rat"]
role = config.device["role"]
rx_len = config.device["rx_len"]
tx_len = config.device["tx_len"]
test_layer = Layers[config.device["packet_layer"]]
config_file = config.device["config_file"]
logger_handle = config_file.split('/')[-1].split('.')[0]

logger = configure_logger( logger_handle, config.device["log_path"],logging.DEBUG)


return_handle_layer = [Layers[i] for i in config.device["return_handle_layer"]]
send_handle_layer = [Layers[i] for i in config.device["send_handle_layer"]]
port_name = config.device["port_name"]
logs_pcap = config.device["logs_pcap"]
pcap_filename = config.device["pcap_filename"]
key_path = config.device["key_path"]

ble_sul = Bluetooth_SUL(NRF52Dongle(port_name=port_name,logs_pcap=logs_pcap,pcap_filename=pcap_filename), advertiser_address,iat,rat, role,rx_len,tx_len ,logger_handle, key_path,test_layer, config_file, return_handle_layer=return_handle_layer,send_handle_layer=send_handle_layer)
alphabet=[]
alphabet= ['ll_connection_update_ind_pkt', 'll_channel_map_req_pkt', 'll_terminate_ind_pkt', 'll_enc_req_pkt', 'll_enc_rsp_pkt', 'll_start_enc_req_pkt', 'll_start_enc_rsp_pkt', 'll_unknown_rsp_pkt', 'll_feature_req_pkt', 'll_feature_rsp_pkt', 'll_pause_enc_req_pkt', 'll_pause_enc_rsp_pkt', 'll_version_ind_pkt', 'll_reject_ind_pkt', 'll_slave_feature_req_pkt', 'll_connection_param_req_pkt', 'll_connection_param_rsp_pkt', 'll_reject_ind_ext_pkt', 'll_ping_req_pkt', 'll_ping_rsp_pkt', 'll_length_req_pkt', 'll_length_rsp_pkt']
alphabet.extend(["scan_req","connect_req"])
alphabet.extend(['master_identification_pkt','pairing_request_pkt', 'identity_information_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt',  'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt'])
# print(prompt.format(packet_name="pairing request", field="io_cap"))
# alphabet.extend(['ll_connection_update_ind_pkt'])
# alphabet.remove(['pairing_request_pkt'])
# 加载 JSON 配置文件
# print(len(alphabet))

mutations = {}

for packet_name in alphabet:
    pkt = ble_sul.get_packet(packet_name)
    
    mutations[packet_name] = []
    while not isinstance(pkt, NoPayload):
       
        layer_name = type(pkt).__name__
        if layer_name == "BTLE":
            pkt = pkt.payload
            continue
        #查找layer_name 在field_semseed.json 中的数据
        
        with open(f"Semantic/data/sem_seed/grok/field_semseed.json", "r") as f:
            data = json.load(f)
        for item in data["packets"]:
            if item["name"] == layer_name:
                for field in item["fields"]:
                   
                    for mutation in field["mutations"]:
                        # 如果mutation 是字典类型，则取第一个value
                        for key,value in mutation.items():
                            if key != "TestType":
                               #str to 16进制bytes
                            #    print(value)
                               if "0b" in value:
                                   # 将二进制字符串转换为十六进制
                                   value = value.replace("0b","")
                                   value = hex(int(value, 2))[2:]  # 转换为十六进制并移除'0x'前缀
                               elif "0x" in value:
                                   value = value.replace("0x","")
                               # 确保value是偶数长度的十六进制字符串
                               if len(value) % 2 != 0:
                                   value = '0' + value
                               
                               try:
                                   # 转换为bytes
                                   value_bytes = bytes.fromhex(value)
                                   # 将bytes转换为十六进制字符串以便JSON序列化
                                   hex_str = value_bytes.hex()
                                   mutation_packet = [packet_name, layer_name, field["name"], hex_str]
                                   mutations[packet_name].append(mutation_packet)
                               except ValueError as e:
                                   print(f"无法转换的十六进制值: {value}")
                                   continue
        pkt = pkt.payload               
        # # 将mutations 写入到json文件中,如果文件存在则追加，否则创建
with open(f"Semantic/data/sem_seed/grok/field_semseed_parse.json", "a") as f:
    json.dump(mutations, f, indent=4)  # 添加indent参数使输出更易读
    f.write("\n")
    
                   

