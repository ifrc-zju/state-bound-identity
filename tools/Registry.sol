// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Independent supplementary baseline. No production identities or funds.
contract Registry {
    struct Identity { address controller; bytes32 key; bool active; bool issuer; uint64 version; }
    struct Credential { bytes32 issuer; bytes32 subject; bytes32 digest; bool revoked; }
    address public immutable governor;
    mapping(bytes32 => Identity) public identities;
    mapping(bytes32 => Credential) public credentials;
    event IdentityChanged(bytes32 indexed did, address controller, bytes32 key, bool active, bool issuer, uint64 version);
    event CredentialChanged(bytes32 indexed cid, bytes32 issuer, bytes32 subject, bytes32 digest, bool revoked);
    constructor() { governor = msg.sender; }
    function register(bytes32 did, bytes32 key) external {
        require(identities[did].controller == address(0), "EXISTS");
        require(key != bytes32(0), "EMPTY_KEY");
        identities[did] = Identity(msg.sender,key,true,false,1); emitIdentity(did);
    }
    function authorizeIssuer(bytes32 did, bool allowed) external {
        require(msg.sender == governor, "GOVERNOR_ONLY");
        require(identities[did].active, "INACTIVE");
        identities[did].issuer=allowed; emitIdentity(did);
    }
    function rotate(bytes32 did, bytes32 key) external {
        Identity storage d=identities[did];
        require(msg.sender==d.controller, "CONTROLLER_ONLY");
        require(d.active && key!=bytes32(0), "INVALID");
        d.key=key; d.version++; emitIdentity(did);
    }
    function deactivate(bytes32 did) external {
        require(msg.sender==identities[did].controller, "CONTROLLER_ONLY");
        identities[did].active=false; emitIdentity(did);
    }
    function issue(bytes32 cid, bytes32 issuer, bytes32 subject, bytes32 digest) external {
        Identity memory d=identities[issuer];
        require(msg.sender==d.controller && d.active && d.issuer, "ISSUER_ONLY");
        require(identities[subject].active && digest!=bytes32(0), "INVALID");
        require(credentials[cid].digest==bytes32(0), "EXISTS");
        credentials[cid]=Credential(issuer,subject,digest,false); emitCredential(cid);
    }
    function revoke(bytes32 cid) external {
        Credential storage c=credentials[cid];
        require(c.digest!=bytes32(0) && msg.sender==identities[c.issuer].controller, "ISSUER_CONTROLLER_ONLY");
        c.revoked=true; emitCredential(cid);
    }
    function emitIdentity(bytes32 did) private {
        Identity memory d=identities[did];
        emit IdentityChanged(did,d.controller,d.key,d.active,d.issuer,d.version);
    }
    function emitCredential(bytes32 cid) private {
        Credential memory c=credentials[cid];
        emit CredentialChanged(cid,c.issuer,c.subject,c.digest,c.revoked);
    }
}
