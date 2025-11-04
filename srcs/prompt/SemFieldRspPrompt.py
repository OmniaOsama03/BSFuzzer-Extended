from langchain_core.prompts import PromptTemplate

SemRspPrompt = PromptTemplate(
            input_variables=["INSEQ","OUTSEQ", "MUTINF"],
            template="""
    You are a Bluetooth protocol expert. Please analyze the input packet sequence {INSEQ} of the Bluetooth protocol and its corresponding output packet sequence {OUTSEQ}. The mutation information of the mutated input packet is {MUTINF}. The response packet to the mutated packet is {RSP}. Is the output correct?  "empty" means no response.

    ### Output Requirements  

    1. Conclude with `"Correct"` or `"Incorrect"` or `"Inconclusive"` in `<Judgment>`.  
    2. Explain reasoning in `<Explanation>`:  
    - If correct: Explain why.  
    - If incorrect: Explain why.  
    - If inconclusive: List missing protocol details.  


    Final output MUST be a valid JSON object.
    You MUST wrap the JSON with the prefix `Final Answer:` so the agent can recognize it.
    Do NOT include any markdown formatting like ```json or extra explanation outside the JSON.
    Only return this line:
    ---
    ### Example Output:
    Final Answer: {{
    "Mutation": "ll_pause_enc_req_pkt,BTLE_DATA,RFU,07",
    "RSP": "empty",
    "Judgment": "Incorrect",
    "Explanation": "The output packet sequence is incorrect because the mutation in the `ll_pause_enc_req_pkt` to `BTLE_DATA,RFU,07` should not result in an empty response. According to the Bluetooth Link Layer specification, the RFU field must be ignored by the receiver, and the packet should be processed as a valid request to pause encryption. A compliant receiver should respond appropriately, rather than providing no response."
    }}
  

    """
        )

def get_field_prompt(INSEQ, OUTSEQ, MUTINF, RSP):
    return SemRspPrompt.format(INSEQ=INSEQ, OUTSEQ=OUTSEQ, MUTINF=MUTINF, RSP=RSP)

if __name__ == "__main__":
    print(get_field_prompt(INSEQ="(ll_version_ind_pkt),(ll_feature_req_pkt),(ll_length_req_pkt),(pairing_request_pkt),(pairing_public_key_pkt),(pairing_random_pkt),(pairing_dhkey_check_pkt),(ll_enc_req_pkt),(ll_start_enc_rsp_pkt),(ll_pause_enc_req_pkt)", OUTSEQ="(ll_slave_feature_req_pkt),(ll_feature_rsp_pkt),(ll_length_rsp_pkt),(pairing_response_pkt),(pairing_confirm_pkt,pairing_public_key_pkt),(pairing_random_pkt),(pairing_dhkey_check_pkt),(ll_enc_rsp_pkt,ll_start_enc_req_pkt),(ll_start_enc_rsp_pkt,identity_address_information_pkt,identity_information_pkt),(empty)", MUTINF="ll_pause_enc_req_pkt,BTLE_DATA,RFU,01", RSP="empty"))


