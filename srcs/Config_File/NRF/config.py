




# if master sul_type is 0, if slave sul_type is 1
# Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_pkts"} 



device = {
    "advertiser_address": "E0:9C:F0:D1:72:A4",
    "sul_type": 0,
    "iat": 1,
    "rat": 1,
    "role": 1,
    "rx_len": 251,
    "tx_len":251,
    "packet_layer":1,
    "config_file": "/home/yangting/Documents/Semantic/srcs/Config_File/NRF/peripheral_07_17_selected.ini",
    "model_path": "/home/yangting/Documents/Semantic/result/dot_file/NRF/pairing_legency_encryption.dot",
    "learned_model_path": "/home/yangting/Documents/Semantic/result/dot_file/NRF/ble_security_l2cap.dot",
    "log_path": "/home/yangting/Documents/Semantic/result/log_file/NRF/test_state.log",
    "port_name": "/dev/ttyACM0",
    "logs_pcap": False,
    "pcap_filename": "/home/yangting/Documents/Semantic/result/log_file/NRF/test_smp_legency.pcap",
    "return_handle_layer": [1,3] ,
    "send_handle_layer":[1,3], # Uncomment and modify if needed
    "key_path": "/home/yangting/Documents/Semantic/result/log_file/NRF/key.txt",
    "statepkt_dict": {"ll_base":['ll_feature_req_pkt','ll_length_req_pkt', 'll_version_ind_pkt',],"sm_legency":['pairing_request_pkt','pairing_confirm_pkt', 'pairing_random_pkt', ],"sm_sc":['pairing_request_pkt','pairing_public_key_pkt',"pairing_random_pkt","pairing_dhkey_check_pkt"]},
    "device_name": "Nordic_HIDS_mouse",
    "pairing_type": "legency"
}

fuzz = {
    "fuzz_pcap_filename": "/home/yangting/Documents/Semantic/result/log_file/NRF/test_l2cap_fuzz.pcap",
    "untested_layer": ["BTLE", ],
    "output_file_path": "/home/yangting/Documents/Semantic/result/log_file/NRF/semfuzz_output.json",
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


