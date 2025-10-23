
import os

import sys
# from time import sleep
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../../")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../libs/")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../libs/boofuzz/")
# sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/libs/aalpy/")
# sys.path.append(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/srcs/")

from BSFuzz.libs.driver.NRF52_dongle import NRF52Dongle
from scapy.compat import raw
# from boofuzz.primitives.bit_field import Bit_Field
from scapy.volatile import *
from scapy.utils import hexdump
from scapy.layers.bluetooth4LE import *
from scapy.layers.inet6 import *
from scapy.layers.bluetooth import *
from scapy.fields import *
from scapy.packet import fuzz
from scapy.all import *






from BSFuzz.srcs.Send_Packet.Bluetooth_SUL import Bluetooth_SUL

# from BSFuzz.libs.boofuzz.primitives import *

from BSFuzz.srcs.Log_Config.logger_config import *
import Semantic.srcs.Send_Packet.constant as constant


from BSFuzz.srcs.Config_File.Microchip import config
str = config.device["advertiser_address"]
Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_legency_pkts",6:"test_sc_pkts"}
advertiser_address = config.device["advertiser_address"]
iat = config.device["iat"]
rat = config.device["rat"]
role = config.device["role"]
rx_len = config.device["rx_len"]
tx_len = config.device["tx_len"]
test_layer = Layers[config.device["packet_layer"]]
config_file = config.device["config_file"]
learned_model_path = config.device["learned_model_path"]
return_handle_layer = [Layers[i] for i in config.device["return_handle_layer"]]
send_handle_layer = [Layers[i] for i in config.device["send_handle_layer"]]
port_name = config.device["port_name"]
logs_pcap = config.device["logs_pcap"]
pcap_filename = config.device["pcap_filename"]
if config.device["return_handle_layer"]:
    for i in config.device["return_handle_layer"]:
        return_handle_layer.append(Layers[int(i)])
logger_handle = config_file.split('/')[-1].split('.')[0]

logger = configure_logger( logger_handle, config.device["log_path"],logging.DEBUG)
key_path = config.device["key_path"]

# 获取log配置
ble_sul = Bluetooth_SUL(NRF52Dongle(port_name=port_name,logs_pcap=logs_pcap,pcap_filename=pcap_filename), advertiser_address, iat,rat,role,rx_len,tx_len, logger_handle, key_path,test_layer, config_file, return_handle_layer=return_handle_layer,send_handle_layer=send_handle_layer)

###
ble_sul.data_prepare()
ble_sul.data_processing()
error_count = 0
output = constant.EMPTY
while True:
    error_count += 1
    if error_count < constant.CONNECTION_ERROR_ATTEMPTS:
        ble_sul.driver.send(ble_sul.packet_construction.get_pkt('ll_terminate_ind_pkt'))
        ble_sul.packet_send_received(ble_sul.packet_construction.get_pkt('scan_req'), connect_min_attempts=constant.SCAN_MIN_ATTEMPTS, connect_max_attempts=constant.SCAN_MAX_ATTEMPTS)
        connect_pkt = ble_sul.packet_construction.get_pkt('connect_req')
        # connect_pkt["BTLE_CONNECT_REQ"].win_offset = 0xffff
        output = ble_sul.connection_packet_send_received(connect_pkt, connect_min_attempts=constant.CONNECT_MIN_ATTEMPTS, connect_max_attempts=constant.CONNECT_MAX_ATTEMPTS)
    

    # pkt = ble_sul.get_packet("ll_version_ind_pkt")
    # pkt.show2()
    # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

    # pkt = ble_sul.get_packet("ll_feature_req_pkt")
    # pkt.show2()
    # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

    # pkt = ble_sul.get_packet("ll_length_req_pkt")
    # pkt.show2()
    # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)
    # # pkt = ble_sul.get_packet("ll_length_req_pkt")
    # # pkt.show2()
    # # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)
    # # pkt = ble_sul.get_packet("ll_length_req_pkt")
    # # pkt.show2()
    # # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)
    # # pkt = ble_sul.get_packet("ll_length_req_pkt")
    # # pkt.show2()
    # # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)


    # # pkt = ble_sul.get_packet("pairing_public_key_pkt")
    # # pkt.show2()
    # # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

    # i = i + 1

    # pkt = ble_sul.get_packet("pairing_request_pkt")
    # # # pkt["SM_Pairing_Request"].iocap = 0x03
    # # # pkt["SM_Pairing_Request"].oob = 0x00
    # # # pkt["SM_Pairing_Request"].authentication = 0x28
    # # # pkt["SM_Pairing_Request"].max_key_size = 0x10
    # # # pkt["SM_Pairing_Request"].initiator_key_distribution = 0x0f
    # # # pkt["SM_Pairing_Request"].responder_key_distribution = 0x0f
    # pkt.show2()
    # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)
    # pkt = ble_sul.get_packet("pairing_public_key_pkt")
    # # pkt.show2()
    # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

    # pkt = ble_sul.get_packet("pairing_random_pkt")
    # # pkt.show2()
    # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)   
    # pkt = ble_sul.get_packet("pairing_dhkey_check_pkt")
    # # pkt.show2()
    # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)
    # pkt = ble_sul.get_packet("ll_enc_req_pkt")
    # pkt.show2()
    # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

    # pkt = ble_sul.get_packet("ll_start_enc_rsp_pkt")
    # pkt.show2()
    # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

    # ble_sul.post()
    # i = i + 1
#     print("i = ",i)

# ble_sul.driver.save_pcap()
# ble_sul.packet_construction.save_key()



