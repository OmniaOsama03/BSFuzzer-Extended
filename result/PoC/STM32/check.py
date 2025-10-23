import resource
import os
import sys
import signal
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../../")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../libs/")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../libs/boofuzz/")



from BSFuzz.srcs.Send_Packet.Bluetooth_SUL1 import Bluetooth_SUL
from BSFuzz.libs.driver.NRF52_dongle import NRF52Dongle
from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Packet_Fuzz.SemFuzz import Fuzz_Session
from BSFuzz.srcs.Packet_Fuzz.AutomataSUL_Graph import AutomataSUL_Graph
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from BSFuzz.srcs.Config_File.STM32 import config
import Semantic.srcs.Send_Packet.constant as constant

rsrc = resource.RLIMIT_DATA
soft, hard = resource.getrlimit(rsrc)
resource.setrlimit(rsrc, (1024 * 1024 * 1024 * 12, hard))


# 获取log配置
Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_legency_pkts",6:"test_sc_pkts"}

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

learned_model_path = config.device["learned_model_path"]
return_handle_layer = [Layers[i] for i in config.device["return_handle_layer"]]
send_handle_layer = [Layers[i] for i in config.device["send_handle_layer"]]
port_name = config.device["port_name"]
logs_pcap = config.device["logs_pcap"]
pcap_filename = config.fuzz["fuzz_pcap_filename"]
key_path = config.device["key_path"]
block_packet=config.fuzz["block_packet"]
block_packet_truncated=config.fuzz["block_packet_truncated"]
block_packet_add=config.fuzz["block_packet_add"]
output_file_path = config.fuzz["output_file_path"]
fuzz_config_path = "/home/yangting/Documents/Semantic/config/semfuzz_config.json"

ble_sul = Bluetooth_SUL(NRF52Dongle(port_name=port_name,logs_pcap=logs_pcap,pcap_filename=pcap_filename), advertiser_address,iat,rat, role,rx_len,tx_len ,logger_handle, key_path,test_layer, config_file, return_handle_layer=return_handle_layer,send_handle_layer=send_handle_layer)


ble_sul.data_prepare()
ble_sul.data_processing()
error_count = 0
output = constant.EMPTY
while output == constant.EMPTY:
    error_count += 1
    if error_count < 50:
        ble_sul.driver.send(ble_sul.packet_construction.get_pkt('ll_terminate_ind_pkt'))
        ble_sul.packet_send_received(ble_sul.packet_construction.get_pkt('scan_req'), connect_min_attempts=constant.SCAN_MIN_ATTEMPTS, connect_max_attempts=constant.SCAN_MAX_ATTEMPTS)
        
        connect_pkt = ble_sul.packet_construction.get_pkt('connect_req')
        timeout = connect_pkt["BTLE_CONNECT_REQ"].timeout
        connect_pkt["BTLE_CONNECT_REQ"].timeout = 0xffff
        output = ble_sul.connection_packet_send_received(connect_pkt, connect_min_attempts=constant.CONNECT_MIN_ATTEMPTS, connect_max_attempts=constant.CONNECT_MAX_ATTEMPTS)
        # else:
        #     connect_pkt = ble_sul.packet_construction.get_pkt('connect_req')
        #     connect_pkt["BTLE_CONNECT_REQ"].timeout = timeout
        #     output = ble_sul.connection_packet_send_received(connect_pkt, connect_min_attempts=constant.CONNECT_MIN_ATTEMPTS, connect_max_attempts=constant.CONNECT_MAX_ATTEMPTS)
            



# pkt = ble_sul.get_packet("ll_feature_req_pkt")
# pkt.show2()
# ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

# pkt = ble_sul.get_packet("ll_length_req_pkt")
# pkt.show2()
# ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

# pkt = ble_sul.get_packet("ll_feature_rsp_pkt")
# pkt.show2()
# ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

# pkt = ble_sul.get_packet("ll_length_rsp_pkt")
# pkt.show2()
# ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

# pkt = ble_sul.get_packet("ll_version_ind_pkt")
# pkt.show2()
# ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

# pkt = ble_sul.get_packet("ll_pause_enc_req_pkt")
# pkt.show2()
# ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)
 
# pkt = ble_sul.get_packet("pairing_request_pkt")
# ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 100)
# # # pkt = ble_sul.get_packet("pairing_confirm_pkt")
# # # pkt.show2()
# # # ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 100)
# pkt = ble_sul.get_packet("pairing_public_key_pkt")

# ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 100)

# pkt = ble_sul.get_packet("pairing_random_pkt")
# pkt.show2()
# ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50) 

# pkt = ble_sul.get_packet("pairing_dhkey_check_pkt")
# pkt.show2()
# ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

# pkt = ble_sul.get_packet("ll_enc_req_pkt")

# pkt['BTLE_DATA'].LLID = 0x00
# pkt.show2()

# ble_sul.packet_send_received_fuzz(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

# pkt = ble_sul.get_packet("ll_start_enc_rsp_pkt")
# pkt.show2()
# ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)



# ble_sul.post()


# ble_sul.pre()
# ble_sul.post()
# # test end
# ble_sul.driver.save_pcap()
# ble_sul.packet_construction.save_key()



