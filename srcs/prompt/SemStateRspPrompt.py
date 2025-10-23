from langchain.prompts import PromptTemplate

SemRspPrompt = PromptTemplate(
            input_variables=["INSEQ","OUTSEQ", ],
            template="""
    You are a Bluetooth protocol expert. Please analyze the state mutation packet sequence {INSEQ} of the Bluetooth protocol and its corresponding output packet sequence {OUTSEQ}.

    ### Step
    1. Ignore the violation of input packet sequence, and check the state of the device base on the output packet sequence, and verify each input packet's response packet.
    2. Analyze if the input packet is correct, and what is the expected output packet, if the input packet sequence is incorrect, what is the expected output packet. And check if the input packet sequence is correct or not, explain the reason in <Analysis> tag, base on the analysis, you can give the correct output packet.

    ### Output Requirements

    - Final output MUST be a valid JSON object.
    - You MUST wrap the JSON with the prefix `Final Answer:` so the agent can recognize it.
    - Do NOT include any markdown formatting like ```json or extra explanation outside the JSON.
    - Only return this line: 
    ---
    ### Example Output: 
    Final Answer: {{
    "Input":
    "(ll_version_ind_pkt),(ll_feature_req_pkt),(ll_length_req_pkt),(pairing_request_pkt),(pairing_public_key_pkt),(pairing_random_pkt),(ll_enc_req_pkt),(ll_start_enc_rsp_pkt),(ll_pause_enc_req_pkt)", 
    "Output":
    "(ll_slave_feature_req_pkt),(ll_feature_rsp_pkt),(ll_length_rsp_pkt),(pairing_response_pkt),(pairing_confirm_pkt,pairing_public_key_pkt),(pairing_random_pkt),(ll_enc_rsp_pkt,ll_reject_ind_ext_pkt),(raw_pkt),(empty)"
    "Analysis":
    "The pairing process is missing pairing dhkey check pkt, so the pairing is incomplete and cannot enter the encrypted state. When the input ll_pause_enc_req_pkt device should reject it, but the reply is raw_pkt, please check if it is correct."
    }}
   
    """
        )

def get_state_prompt(INSEQ, OUTSEQ):
    return SemRspPrompt.format(INSEQ=INSEQ, OUTSEQ=OUTSEQ)

if __name__ == "__main__":
    print(get_state_prompt(INSEQ="(ll_feature_req_pkt),(ll_length_req_pkt),(ll_version_ind_pkt),(pairing_request_pkt),(pairing_public_key_pkt),(master_identification_pkt),(encryption_information_pkt),(encryption_information_pkt),(ll_enc_req_pkt),(ll_start_enc_rsp_pkt),(ll_pause_enc_req_pkt)", OUTSEQ="(ll_feature_rsp_pkt),(ll_length_rsp_pkt),(ll_version_ind_pkt),(pairing_response_pkt),(pairing_confirm_pkt,pairing_public_key_pkt),(pairing_failed_pkt),(empty),(empty),(ll_enc_rsp_pkt,ll_reject_ind_ext_pkt),(ll_connection_param_req_pkt),(empty)"))




