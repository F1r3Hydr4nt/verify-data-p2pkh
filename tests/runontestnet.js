const path = require('path');
const { buildContractClass, lockScriptTx, unlockScriptTx, showError } = require('scrypttest');

// private key on testnet in WIF
const key = ''
if (!key) {
    throw new Error('You must provide a private key');
}

(async() => {
    try {
        // get locking script
        const Demo = buildContractClass(path.join(__dirname, '../contracts/demo.scrypt'));
        demo = new Demo(4, 7);
        const scriptPubKey = demo.getScriptPubKey()
        
        // lock fund to the script
        const lockingTxid = await lockScriptTx(scriptPubKey, key)
        console.log('locking txid:     ', lockingTxid)
        
        // unlock
        const scriptSig = 'OP_11'
        const unlockingTxid = await unlockScriptTx(scriptSig, lockingTxid, scriptPubKey)
        console.log('unlocking txid:   ', unlockingTxid)

        console.log('Succeeded on testnet')
    } catch (error) {
        console.log('Failed on testnet')
        showError(error)
    }
})()