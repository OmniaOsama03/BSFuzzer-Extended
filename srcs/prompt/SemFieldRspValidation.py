from langchain_core.prompts import PromptTemplate

SemRspPrompt = PromptTemplate(
            input_variables=["MUTINF","ACTUAL_RESPONSE","SPECIFICATION_SECTION","EXPECTED_DEVICE_BEHAVIOR"],
            template="""
        You are an expert in the Bluetooth Core Specification. A single field in a BLE control packet has been mutated: {MUTINF},
        device's actual response is {ACTUAL_RESPONSE}, where ”empty” in actual response indicates a
        silently dropped packet. Perform the following steps:
        1. Field Validity Verification
        Determine whether the mutated field value is valid or invalid according
        to the {SPECIFICATION_SECTION}.
        2. Device Response Compliance
        If the field value is invalid, evaluate whether the device’s actual response
        aligns with the expected behavior {EXPECTED_DEVICE_BEHAVIOR}.

        Final output MUST be a valid JSON object.
        You MUST wrap the JSON with the prefix `Final Answer:` so the agent can recognize it.
        Do NOT include any markdown formatting like ```json or extra explanation outside the JSON.
        Only return this line:
        ---
        ### Example Output:
        Final Answer: {{
        "Mutation": "ll_pause_enc_req_pkt,BTLE_DATA,RFU,07",
        "actual_response": "empty",
        "Judgment": "Incorrect",
        "Explanation": "The output packet sequence is incorrect because the mutation in the `ll_pause_enc_req_pkt` to `BTLE_DATA,RFU,07` should not result in an empty response. According to the Bluetooth Link Layer specification, the RFU field must be ignored by the receiver, and the packet should be processed as a valid request to pause encryption. A compliant receiver should respond appropriately, rather than providing no response."
        }}

        """
        )

def get_field_prompt(MUTINF, ACTUAL_RESPONSE, SPECIFICATION_SECTION, EXPECTED_DEVICE_BEHAVIOR):
    return SemRspPrompt.format(MUTINF=MUTINF, ACTUAL_RESPONSE=ACTUAL_RESPONSE, SPECIFICATION_SECTION=SPECIFICATION_SECTION, EXPECTED_DEVICE_BEHAVIOR=EXPECTED_DEVICE_BEHAVIOR)

if __name__ == "__main__":
    print(get_field_prompt(MUTINF="ll_pause_enc_req_pkt,BTLE_DATA,RFU,01", ACTUAL_RESPONSE="empty", SPECIFICATION_SECTION="Vol 2 Part E §7.8.18", EXPECTED_DEVICE_BEHAVIOR="None — No specific error signaling mandated for field value errors at Link Layer"))


