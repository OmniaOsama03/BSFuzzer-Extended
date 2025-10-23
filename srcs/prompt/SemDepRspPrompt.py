from langchain.prompts import PromptTemplate

SemRspPrompt = PromptTemplate(
            input_variables=["INSEQ","OUTSEQ", "MUTINF"],
            template="""
    You are a Bluetooth protocol expert. Please analyze the input packet sequence {INSEQ} of the Bluetooth protocol and its corresponding output packet sequence {OUTSEQ}. The mutation information of the mutated input packet is {MUTINF}. The response packet to the mutated packet is {RSP}. Is the output correct? Analyze potential security vulnerabilities.  

    ### Output Requirements  

    1. Conclude with `"Correct"` or `"Incorrect"` or `"Inconclusive"` in `<Judgment>`.  
    2. Explain reasoning in `<Explanation>`:  
    - If correct: Explain why.  
    - If incorrect: Explain why.  
    - If inconclusive: List missing protocol details.  
    ---
    ### Example Output  
    ```xml
    <Judgment>Incorrect</Judgment>
    <Explanation>
    The output packet sequence does not match the expected behavior of the Bluetooth protocol. Specifically, the mutation in the input packet was not handled correctly, leading to an incorrect response. Additionally, the lack of proper validation for the `ediv` and `confirm` fields introduces potential security vulnerabilities, such as replay attacks or unauthorized pairing.
    </Explanation>
    ```  
    Final output MUST adhere to the XML-like tag structure above.
    """
        )

def get_prompt(INSEQ, OUTSEQ, MUTINF, RSP):
    return SemRspPrompt.format(INSEQ=INSEQ, OUTSEQ=OUTSEQ, MUTINF=MUTINF, RSP=RSP)

if __name__ == "__main__":
    print(get_prompt(INSEQ="(ll_version_ind_pkt),(ll_feature_req_pkt),(ll_length_req_pkt),(pairing_request_pkt),(pairing_public_key_pkt),(pairing_random_pkt),(pairing_dhkey_check_pkt),(ll_enc_req_pkt),(ll_start_enc_rsp_pkt),(ll_pause_enc_req_pkt)", OUTSEQ="(ll_slave_feature_req_pkt),(ll_feature_rsp_pkt),(ll_length_rsp_pkt),(pairing_response_pkt),(pairing_confirm_pkt,pairing_public_key_pkt),(pairing_random_pkt),(pairing_dhkey_check_pkt),(ll_enc_rsp_pkt,ll_start_enc_req_pkt),(ll_start_enc_rsp_pkt,identity_address_information_pkt,identity_information_pkt),(empty)", MUTINF="ll_pause_enc_req_pkt,BTLE_DATA,RFU,00", RSP="empty"))


