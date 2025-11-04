

# if master sul_type is 0, if slave sul_type is 1
# Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_legency_pkts",6:"test_sc_pkts",7:"test_all_pkts"}
device = {
    "advertiser_address": "e8:31:cd:73:f8:e2",
    "sul_type": 0,
    "iat": 1,
    "rat": 0,
    "role": 1,
    "rx_len": 251,
    "tx_len": 251,
    "packet_layer": 1,
    "config_file": "/home/yangting/Documents/BSFuzz/srcs/Config_File/Esp32/esp_ble_security.ini",
    "learned_model_path": "/home/yangting/Documents/BSFuzz/result/dot_file/Esp32/esp_ble_security_l2cap.dot",
    "log_path": "/home/yangting/Documents/BSFuzz/result/log_file/Esp32/test_log.log",
    "port_name": "/dev/ttyACM0",
    "logs_pcap": True,
    "pcap_filename": "/home/yangting/Documents/BSFuzz/result/log_file/Esp32/test_smp_legency_access_adress.pcap",
    "return_handle_layer": [1,3] ,
    "send_handle_layer":[1,3], # Uncomment and modify if needed
    "key_path": "/home/yangting/Documents/BSFuzz/result/log_file/Esp32/key.txt",
    "pairing_type": "sc"
}

fuzz = {
    "fuzz_pcap_filename": "/home/yangting/Documents/BSFuzz/result/log_file/Esp32/test_l2cap_fuzz.pcap",
    "output_file_path": "/home/yangting/Documents/BSFuzz/result/log_file/Esp32/semfuzz_output_test.json",
    "untested_layer": ["BTLE",],
    "block_packet":[
        {
          "packet_name":"connect_req",
          "packet_layer":"BTLE_CONNECT_REQ",
          "field_name":"AA"
        },
        {
          "packet_name":"connect_req",
          "packet_layer":"BTLE_CONNECT_REQ",
          "field_name":"win_offset"
        },
        {
          "packet_name":"connect_req",
          "packet_layer":"BTLE_CONNECT_REQ",
          "field_name":"interval"
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