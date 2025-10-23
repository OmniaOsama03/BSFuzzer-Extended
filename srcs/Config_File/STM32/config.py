

# if master sul_type is 0, if slave sul_type is 1
# Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_pkts"} 
device = {
    "advertiser_address": "00:80:E1:27:B1:B2",
    "sul_type": 0,
    "iat": 1,
    "rat": 0,
    "role": 1,
    "rx_len": 251,
    "tx_len": 251,
    "packet_layer": 1,
    "config_file": "/home/yangting/Documents/Semantic/srcs/Config_File/STM32/esp_ble_security.ini",
    "learned_model_path": "/home/yangting/Documents/Semantic/result/dot_file/STM32/esp_ble_security_l2cap.dot",
    "model_path": "/home/yangting/Documents/Semantic/result/dot_file/STM32/pairing_sm_encryption.dot",
    "log_path": "/home/yangting/Documents/Semantic/result/log_file/STM32/test.log",
    "port_name": "/dev/ttyACM1",
    "logs_pcap": True,
    "pcap_filename": "/home/yangting/Documents/Semantic/result/log_file/STM32/test_smp_legency.pcap",
    "return_handle_layer": [1,3] ,
    "send_handle_layer":[1,3], # Uncomment and modify if needed
    "key_path": "/home/yangting/Documents/Semantic/result/log_file/STM32/key.txt",
    "pairing_type": "sc"
}

fuzz = {
    "fuzz_pcap_filename": "/home/yangting/Documents/Semantic/result/log_file/STM32/test_l2cap_fuzz.pcap",
    "output_file_path": "/home/yangting/Documents/Semantic/result/log_file/STM32/semfuzz_output.json",
    "untested_layer": ["BTLE",],
    "block_packet":[
        {
          "packet_name":"connect_req",
          "packet_layer":"BTLE_CONNECT_REQ",
          "field_name":"interval"
        },
                {
          "packet_name":"connect_req",
          "packet_layer":"BTLE_CONNECT_REQ",
          "field_name":"timeout"
        }
    ],
    "block_packet_truncated":[
        {
          "packet_name":"connect_req",
          "packet_layer":"33"
        }
    ],
    "block_packet_add":[]

}

