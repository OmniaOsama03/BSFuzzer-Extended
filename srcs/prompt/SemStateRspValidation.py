from langchain_core.prompts import PromptTemplate

SemRspPrompt = PromptTemplate(
            input_variables=["INSEQ","OUTSEQ", "PACKET_NAME", "Precondition", "Valid_Response", "Invalid_Response"],
            template="""
    You are a Bluetooth Core Specification expert. Given a sequence of BLE packets: {INSEQ} and {OUTSEQ}, perform the following checks for {PACKET_NAME} packet in the path:
    1. Pre-State Verification
    For {PACKET_NAME} packet, determine whether the device was in a valid protocol state to legally receive and process this packet, based on the precondition: {Precondition}.
    If the send packet is expected in the current state, it should be treated as a state-valid packet.
    If the send packet is unexpected in the current state, it should be treated as a state-invalid packet.
    2. Device Response Compliance
    For response packet:
    If the pre-state was valid, verify whether the device replied with the expected {Valid_Response}.
    If the pre-state was invalid, verify whether the device replied with the expected {Invalid_Response}.
   
    ### Output Requirements
    - Final output MUST be a valid JSON object.
    - You MUST wrap the JSON with the prefix `Final Answer:` so the agent can recognize it.
    - Do NOT include any markdown formatting like ```json or extra explanation outside the JSON.
    - Only return this line: 
    ---
    ### Example Output: 
    Final Answer: {{
    "Packet": "The packet name",
    "Input": "The input sequence of packets", 
    "Output": "The output sequence of packets",
    "Analysis": "The analysis of the packet,only focus on the packet and the previous packet's context state, and the output sequence of packets, not the packet's parameters,",
    "Conclusion": "The conclusion of the packet"
    }}
    """
        )

def get_state_prompt(INSEQ, OUTSEQ, PACKET_NAME, Precondition, Valid_Response, Invalid_Response):
    return SemRspPrompt.format(INSEQ=INSEQ, OUTSEQ=OUTSEQ, PACKET_NAME=PACKET_NAME, Precondition=Precondition, Valid_Response=Valid_Response, Invalid_Response=Invalid_Response)

if __name__ == "__main__":
    print(get_state_prompt(INSEQ="(ll_feature_req_pkt),(ll_length_req_pkt),(ll_version_ind_pkt),(pairing_request_pkt),(pairing_public_key_pkt),(master_identification_pkt),(encryption_information_pkt),(encryption_information_pkt),(ll_enc_req_pkt),(ll_start_enc_rsp_pkt),(ll_pause_enc_req_pkt)", OUTSEQ="(ll_feature_rsp_pkt),(ll_length_rsp_pkt),(ll_version_ind_pkt),(pairing_response_pkt),(pairing_confirm_pkt,pairing_public_key_pkt),(pairing_failed_pkt),(empty),(empty),(ll_enc_rsp_pkt,ll_reject_ind_ext_pkt),(ll_connection_param_req_pkt),(empty)", PACKET_NAME="ll_pause_enc_req_pkt", Precondition="The device is in the pairing state", Valid_Response="The device should reply with the expected ", Invalid_Response="The device should reply with the expected"))




