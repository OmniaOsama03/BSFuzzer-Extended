```mermaid
sequenceDiagram
    participant Client
    participant Peripheral

    Client->>Peripheral: LL_PHY_REQ
    Peripheral-->>Client: LL_PHY_RSP
    Client->>Peripheral: LL_PHY_UPDATE_IND
