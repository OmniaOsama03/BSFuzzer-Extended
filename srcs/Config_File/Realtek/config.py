

# if master sul_type is 0, if slave sul_type is 1
# Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_legency_pkts",6:"test_sc_pkts",7:"test_all_pkts"}
device = {
    "advertiser_address": "00:E0:12:34:56:78",
    "sul_type": 0,
    "iat": 1,
    "rat": 0,
    "role": 1,
    "rx_len": 251,
    "tx_len": 251,
    "packet_layer": 1,
    "config_file": "/home/yangting/Documents/Semantic/srcs/Config_File/Realtek/peripheral_07_30.ini",
    "learned_model_path": "/home/yangting/Documents/Semantic/result/dot_file/Realtek/peripheral_all_test.dot",
    "log_path": "/home/yangting/Documents/Semantic/result/log_file/Realtek/test.log",
    "port_name": "/dev/ttyACM0",
    "logs_pcap": True,
    "pcap_filename": "/home/yangting/Documents/Semantic/result/log_file/Realtek/test_all.pcap",
    "return_handle_layer": [ 1, 3],
    "send_handle_layer": [1, 3],
    "key_path": "/home/yangting/Documents/Semantic/result/log_file/Realtek/key.txt",
    "pairing_type": "sc"
}

fuzz = {
    "fuzz_pcap_filename": "/home/yangting/Documents/Semantic/result/log_file/Realtek/test_att_fuzz.pcap",
    "untested_layer": ["LL_TERMINATE_IND", "BTLE"],
    "output_file_path": "/home/yangting/Documents/Semantic/result/log_file/Realtek/semfuzz_output.json",
    # 对于测出问题的数据包，对于block_packet的定义，是一个二维数组，第一维是block_packet的类型，第二维是block_packet的内容
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