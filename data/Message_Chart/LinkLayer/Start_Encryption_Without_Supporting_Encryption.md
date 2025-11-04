```mermaid
sequenceDiagram
    participant Client
    participant Peripheral

    Client->>Peripheral: LL_ENC_REQ
    Peripheral-->>Client: LL_REJECT_IND or LL_REJECT_EXT_IND