```mermaid
sequenceDiagram
    participant Client
    participant Peripheral 

    Peripheral-->>Client: ADV_IND
    Client->>Peripheral: SCAN_REQ
    Peripheral-->>Client: SCAN_RSP