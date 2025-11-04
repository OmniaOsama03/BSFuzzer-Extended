import resource
import os
import sys
import signal
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/libs/")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/libs/boofuzz/")



from BSFuzz.srcs.Send_Packet.Bluetooth_SUL import Bluetooth_SUL
from BSFuzz.libs.driver.NRF52_dongle import NRF52Dongle
from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Test_Seq_Generation.SemFuzz import Fuzz_Session
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from BSFuzz.srcs.Config_File.Esp32 import config

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

return_handle_layer = [Layers[i] for i in config.device["return_handle_layer"]]
send_handle_layer = [Layers[i] for i in config.device["send_handle_layer"]]
port_name = config.device["port_name"]
logs_pcap = config.device["logs_pcap"]
pairing_type = config.device["pairing_type"]
pcap_filename = config.fuzz["fuzz_pcap_filename"]
key_path = config.device["key_path"]
block_packet=config.fuzz["block_packet"]
block_packet_truncated=config.fuzz["block_packet_truncated"]
block_packet_add=config.fuzz["block_packet_add"]
output_file_path = config.fuzz["output_file_path"]
fuzz_config_path = "/home/yangting/Documents/BSFuzz/config/semfuzz_config.json"


ble_sul = Bluetooth_SUL(NRF52Dongle(port_name=port_name,logs_pcap=logs_pcap,pcap_filename=pcap_filename), advertiser_address,iat,rat, role,rx_len,tx_len ,logger_handle, key_path,test_layer, config_file, return_handle_layer=return_handle_layer,send_handle_layer=send_handle_layer)

ble_sul.data_processing()
signal.signal(signal.SIGTSTP, ble_sul.handle_sigtstp)
logger.info(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+"start fuzzing")
fuzz_session = Fuzz_Session(sul=ble_sul,logger_handle=logger_handle,config_file=fuzz_config_path,block_packet=block_packet,block_packet_truncated=block_packet_truncated,block_packet_add=block_packet_add,output_file_path=output_file_path,pairing_type=pairing_type)

fuzz_session.fuzz()
# fuzz_session.fuzz_connect()



    

