```mermaid
sequenceDiagram
    participant Master
    participant Slave

    Master->>Slave: Pairing DHKey Check 
    Slave-->>Master: Pairing DHKey Check 
