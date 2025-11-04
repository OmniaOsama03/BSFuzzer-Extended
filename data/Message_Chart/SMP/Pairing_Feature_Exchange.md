```mermaid
sequenceDiagram
    participant Master
    participant Slave


    Master->>Slave: Pairing Request
    Slave-->>Master: Pairing Response
 
