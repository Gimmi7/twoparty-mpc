# twoparty-mpc

**_twoparty-mpc_** is an open source library that provides the cryptographic foundation to protect blockchain signing
keys and seed secrets, it can also be used to protect traditional web2
assets.

## Bind a share with a third-party identity id

In order to provide a smooth experience for web3 users,we can bind a mpc share with a third-party
identity id. After binding, users can access web3 resources in a mnemonic-free and private-key-free
way. They just need to auth with their web2 social account.(e.g. google auth, apple id, twitter ...)

The rationale of binding:

**generate phase**

* for each identity id, mpc-server will generate an identity-secret for it
* mpc-client encrypt identity-secret & share with aws kms,
  then send (Enc(identity-secret), Enc(share)) to mpc-server.

**recovery phase**

* mpc-client first get the Enc(identity-secret) from mpc-server, then decrypt it with aws kms
* mpc-client generate a proof to convince mpc-server it has successfully decrypted the Enc(identity-secret)
* mpc-server send the Enc(share) to mpc-client
* mpc-client decrypt Enc(share) with aws kms