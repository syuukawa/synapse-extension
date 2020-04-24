import { publicKeyToAddress } from "../wallet/address";

const CKB = require('@nervosnetwork/ckb-sdk-core').default
const nodeUrl = 'http://106.13.40.34:8114/'
const ckb = new CKB(nodeUrl)
                      
// privateKey =>  448ff179b923f0602a00f68f23cb8425d30198446a1b5aa2a016deea2762b1f8
// publicKey =>  0304d793194278a005407cd53e6fbd290d8e2a8e90154b4123dc5e0e06a8a19ecb
// Address=> ckt1qyqt9ed4emcxyfed77ed0dp7kcm3mxsn97ls38jxjw
const privateKey = '0x448ff179b923f0602a00f68f23cb8425d30198446a1b5aa2a016deea2762b1f8';
const toAddress  = "ckt1qyqdh85u4euqkjjhzcl8zdj24nx6msh0sptquvf32p";

const sendCapacity = BigInt(11100000000);
const sendFee = BigInt(1100000000);

describe('transaction test', () => {

  it('send simple transaction', async () => {

    console.log("0x6151c90c6735e505c64cda8ac37efcac55a5823c0037a38ad9ca90f4cce56b83".length)
    jest.setTimeout(100000)

    const secp256k1Dep = await ckb.loadSecp256k1Dep() // load the dependencies of secp256k1 algorithm which is used to verify the signature in transaction's witnesses.
    // console.log(" === secp256k1Dep === ",secp256k1Dep);
    // === secp256k1Dep ===  {
    //   hashType: 'type',
    //   codeHash: '0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8',
    //   outPoint: {
    //     txHash: '0x6495cede8d500e4309218ae50bbcadb8f722f24cc7572dd2274f5876cb603e4e',
    //     index: '0x0'
    //   }
    // }    
    const publicKey = ckb.utils.privateKeyToPublicKey(privateKey)
    /**
     * to see the public key
     */
    //0304d793194278a005407cd53e6fbd290d8e2a8e90154b4123dc5e0e06a8a19ecb
    // console.log(`Public key: ${publicKey}`)
    // console.log src/test/sendSimpleTransaction.test.ts:25
    // Public key: 0x03ec80924627d484afd9da7e701dbc7acbf612f573eb1098a1e0c813dbbdcc543c
    // console.log src/test/sendSimpleTransaction.test.ts:42
    // fromAddress => ckt1qyqwcnwg78e58tnsd4wqyq74yuxvls3076rqcmangd
  
    const publicKeyHash = `0x${ckb.utils.blake160(publicKey, 'hex')}`
    /**
     * to see the public key hash
     */
    // console.log(`Public key hash: ${publicKeyHash}`)
  
    const addresses = {
      testnetAddress: ckb.utils.pubkeyToAddress(publicKey, {
        prefix: 'ckt'
      })
    }
    //ckt1qyqrpkej44pkt0anq8g0qv8wzlyusjx082xs2c2ux4
    // console.log("fromAddress =>", addresses.testnetAddress);

    /**
     * to see the addresses
     */
    // console.log(JSON.stringify(addresses, null, 2))
  
    /**
     * calculate the lockHash by the address publicKeyHash
     * 1. the publicKeyHash of the address is required in the args field of lock script
     * 2. compose the lock script with the code hash(as a miner, we use blockAssemblerCodeHash here), and args
     * 3. calculate the hash of lock script via ckb.utils.scriptToHash method
     */
    // const lockScript = {
    //   hashType: "type",
    //   codeHash: blockAssemblerCodeHash,
    //   args: publicKeyHash,
    // }
    /**
     * to see the lock script
     */
    // console.log(JSON.stringify(lockScript, null, 2))
  
    // const lockHash = ckb.utils.scriptToHash(lockScript)
    const lockHash = ckb.generateLockHash(publicKeyHash, secp256k1Dep)

    /**
     * to see the lock hash
     */
    // console.log(lockHash)
  
    // method to fetch all unspent cells by lock hash
    const unspentCells = await ckb.loadCells({
      lockHash
    })
  
    /**
     * to see the unspent cells
     */
    // console.log("unspentCells => ",unspentCells)
  
    /**
     * send transaction
     */
    // const toAddress = ckb.utils.privateKeyToAddress(privateKey, {
    //   prefix: 'ckt'
    // })

    const rawTransaction = ckb.generateRawTransaction({
      fromAddress: addresses.testnetAddress,
      toAddress: toAddress,
      capacity: sendCapacity,
      fee: sendFee,
      safeMode: true,
      cells: unspentCells,
      deps: ckb.config.secp256k1Dep,
    })
    // console.log(" === rawTransaction === ",rawTransaction);
    // {
    //   version: '0x0',
    //   cellDeps: [ { outPoint: [Object], depType: 'depGroup' } ],
    //   headerDeps: [],
    //   inputs: [ { previousOutput: [Object], since: '0x0' } ],
    //   outputs: [
    //     { capacity: '0x2959c8f00', lock: [Object] },
    //     { capacity: '0x646b4df240', lock: [Object] }
    //   ],
    //   witnesses: [],
    //   outputsData: [ '0x', '0x' ]
    // }

    rawTransaction.witnesses = rawTransaction.inputs.map(() => '0x')
    rawTransaction.witnesses[0] = {
      lock: '',
      inputType: '',
      outputType: ''
    }
  
    // const signedTx = ckb.signTransaction(privateKey)(rawTransaction)
    // /**
    //  * to see the signed transaction
    //  */
    // console.log("signedTx =>", JSON.stringify(signedTx, null, 2))
  
    // const realTxHash = await ckb.rpc.sendTransaction(signedTx)
    // /**
    //  * to see the real transaction hash
    //  */
    // console.log(`The real transaction hash is: ${realTxHash}`)

    // expect(realTxHash).toHaveLength(66);
  });
});
    //add by river
    // console.log(masterKeychain
    //             .derivePath(`m/44'/309'/0'/0`)
    //             .deriveChild(0,false)
    //             .privateKey.toString('hex'))
    // console.log(masterKeychain
    //             .derivePath(`m/44'/309'/0'/0`)
    //             .deriveChild(0,false)
    //             .publicKey.toString('hex')) 