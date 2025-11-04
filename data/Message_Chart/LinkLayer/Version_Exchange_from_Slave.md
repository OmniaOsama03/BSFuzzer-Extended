```mermaid
sequenceDiagram
    participant Client
    participant Peripheral

    Peripheral-->>Client: LL_VERSION_IND
    Client->>Peripheral: LL_VERSION_IND
    