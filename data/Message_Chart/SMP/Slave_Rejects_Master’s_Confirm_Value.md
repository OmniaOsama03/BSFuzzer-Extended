```mermaid
sequenceDiagram
    participant Master
    participant Slave



    Master->>Slave: PairingConfirm (Mconfirm)
    Slave-->>Master: PairingConfirm (Sconfirm)
    Master->>Slave: PairingRandom (Mrand)
    Slave-->>Master: Pairing Failed ("Confirm Value Failed")
