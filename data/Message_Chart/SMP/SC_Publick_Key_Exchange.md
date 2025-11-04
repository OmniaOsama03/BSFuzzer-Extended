```mermaid
sequenceDiagram
    participant Master
    participant Slave


    Master->>Slave: Pairing Public Key
    Slave-->>Master: Pairing Public Key
