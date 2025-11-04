```mermaid
sequenceDiagram
    participant Client
    participant Peripheral 

    Client->>Peripheral: LL_PING_REQ
    Peripheral-->>Client: LL_PING_RSP