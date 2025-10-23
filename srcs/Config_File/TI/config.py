


# if master sul_type is 0, if slave sul_type is 1
# Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_pkts"} 
device = {
    "advertiser_address": "74:D2:85:D3:6B:A4",
    "sul_type": 0,
    "iat": 1,
    "rat": 0,
    "role": 1,
    "rx_len": 251,
    "tx_len": 251,
    "packet_layer": 1,
    "config_file": "/home/yangting/Documents/Semantic/srcs/Config_File/TI/tlkapp_controller_selected_07_15.ini",
    "model_path": "/home/yangting/Documents/Semantic/result/dot_file/TI/pairing_legency_encryption.dot",
    "log_path": "/home/yangting/Documents/Semantic/result/log_file/TI/test_l2cap.log",
    "port_name": "/dev/ttyACM0",
    "logs_pcap":  False,
    "pcap_filename": "/home/yangting/Documents/Semantic/result/log_file/TI/test_smp_legency.pcap",
    "return_handle_layer": [1,3] ,
    "send_handle_layer":[1,3], # Uncomment and modify if needed
    "key_path": "/home/yangting/Documents/Semantic/result/log_file/TI/key.txt",
    "statepkt_dict": {"ll_base":['ll_feature_req_pkt','ll_length_req_pkt', 'll_version_ind_pkt',],"sm_legency":['pairing_request_pkt','pairing_confirm_pkt', 'pairing_random_pkt', ],"sm_sc":['pairing_request_pkt','pairing_public_key_pkt',"pairing_random_pkt","pairing_dhkey_check_pkt"]},
    "pairing_type": "sc"
}

fuzz = {
    "fuzz_pcap_filename": "/home/yangting/Documents/Semantic/result/log_file/TI/test_l2cap_fuzz.pcap",
    "untested_layer": ["BTLE", ],
    "output_file_path": "/home/yangting/Documents/Semantic/result/log_file/TI/semfuzz_output1.json",
    "block_packet":[
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
      "block_packet_add":[
      ]
}

