```mermaid
sequenceDiagram
    participant Client
    participant Peripheral

    Client->>Peripheral: LL_CONNECTION_PARAM_REQ
    Peripheral-->>Client: LL_REJECT_EXT_IND

