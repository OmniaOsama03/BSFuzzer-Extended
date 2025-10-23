

# if master sul_type is 0, if slave sul_type is 1
# Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_legency_pkts",6:"test_sc_pkts",7:"test_all_pkts"}
from re import T


device = {
    "advertiser_address": "9c:95:6e:40:0f:bb",
    "sul_type": 0,
    "iat": 1,
    "rat": 0,
    "role": 1,
    "rx_len": 5,
    "tx_len": 251,
    "packet_layer": 1,
    "config_file": "/home/yangting/Documents/Semantic/srcs/Config_File/Microchip/pairing_select_05_28.ini",
    "learned_model_path": "/home/yangting/Documents/Semantic/result/dot_file/Microchip/unpairing_ll.dot",
    "log_path": "/home/yangting/Documents/Semantic/result/log_file/Microchip/unpairing_ll.log",
    "port_name": "/dev/ttyACM1",
    "logs_pcap": True,
    "pcap_filename": "/home/yangting/Documents/Semantic/result/log_file/Microchip/unpairing_ll.pcap",
    "return_handle_layer": [1,3] ,
    "send_handle_layer":[1,3], # Uncomment and modify if needed
    "key_path": "/home/yangting/Documents/Semantic/result/log_file/Microchip/key.txt",
    "pairing_type": "sc"
}

fuzz = {
    "fuzz_pcap_filename": "/home/yangting/Documents/Semantic/result/log_file/Microchip/test_att_fuzz.pcap",
    
    "output_file_path": "/home/yangting/Documents/Semantic/result/log_file/Microchip/semfuzz_output.json",
    "untested_layer": ["BTLE",],
    "block_packet":[

        {
          "packet_name":"connect_req",
          "packet_layer":"BTLE_CONNECT_REQ",
          "field_name":"win_offset"
        },
        {
          "packet_name":"connect_req",
          "packet_layer":"BTLE_CONNECT_REQ",
          "field_name":"interval"
        },
        {
          "packet_name":"connect_req",
          "packet_layer":"BTLE_CONNECT_REQ",
          "field_name":"latency"
            
        },
        {
          "packet_name":"connect_req",
          "packet_layer":"BTLE_CONNECT_REQ",
          "field_name":"timeout"
            
        },
        {
          "packet_name":"connect_req",
          "packet_layer":"BTLE_CONNECT_REQ",
          "field_name":"win_size"
        },
        {
          "packet_name":"connect_req",
          "packet_layer":"BTLE_CONNECT_REQ",
          "field_name":"chM"
        },


    ],
    "block_packet_truncated":[
        {
          "packet_name":"connect_req",
          "packet_layer":"33"
        }
    ],
    "block_packet_add":[

    ]
}