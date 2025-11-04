```mermaid
sequenceDiagram
    participant Client
    participant Peripheral

    Client->>Peripheral: LL_CONNECTION_PARAM_REQ
    Peripheral-->>Client: LL_CONNECTION_PARAM_RSP
    Client->>Peripheral: LL_CONNECTION_UPDATE_IND
