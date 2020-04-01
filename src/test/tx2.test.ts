const CKB = require('@nervosnetwork/ckb-sdk-core').default;
const CkbUtils = require("@nervosnetwork/ckb-sdk-utils");

const chain =  require("../utils/constants").Ckb

const testnetRPC = 'http://127.0.0.1:8114'
const ckb = new CKB(testnetRPC)

import Keychain from '../wallet/keychain';
import Keystore from '../wallet/keystore'
import { mnemonicToSeedSync } from '../wallet/mnemonic';
import Address, { AddressType, publicKeyToAddress, AddressPrefix } from '../wallet/address'
import { generateMnemonic, AccountExtendedPublicKey, ExtendedPrivateKey } from "../wallet/key";


describe("", () => {
  const mnemonic = "excuse speak boring lunar consider sea behave next fog arrow black sweet"
  const hdMainnetAddr = "ckb1qyqt9ed4emcxyfed77ed0dp7kcm3mxsn97lsvzve7j"
  const hdTestnetAddr = "ckt1qyqt9ed4emcxyfed77ed0dp7kcm3mxsn97ls38jxjw"
  const password = "123456"

  // it("send tx", async () => {

  //   jest.setTimeout(10000)

  //   const privateKey = "0xd40c79c4583b7d9eb5310649c5bd3d608ce24fffe5dd955e718439a1b40a5692"
  //   const publicKey = "0x027815a2decd1fb52f982dfe12304e6cf2ea5441d55f1a034c581d52f8cc2f416f"
  //   const blake160 = `0x${ckb.utils.blake160(publicKey, 'hex')}`

  //   const lockHash = ckb.utils.scriptToHash({
  //     hashType: "type",
  //     codeHash: chain.TestNetCodeHash,
  //     args: blake160
  //   })

  //   console.log("lockHash =>", lockHash);

  //   const cells = await ckb.rpc.getCellsByLockHash(lockHash, BigInt(41036), BigInt(41038))

  //   // console.log("cell =>", cells);

  //   const unspentCells = await ckb.loadCells({
  //     lockHash,
  //     start: BigInt(41036),
  //     end: BigInt(41038),
  //   })

  //   console.log("unspentCells =>", unspentCells);

  //   let sum = BigInt(0)
  //   for (const cell of cells) {
  //     sum += BigInt(cell.capacity)
  //   }

  //   console.log("sum ->", sum);

  //   const testnetAddr = CkbUtils.privateKeyToAddress(privateKey, {
  //     prefix: 'ckt',
  //   })
  //   console.log("addr =>", testnetAddr)

  //   const secp256k1Dep = await ckb.loadSecp256k1Dep();

  //   const rawTransaction = ckb.generateRawTransaction({
  //     fromAddress: testnetAddr,
  //     toAddress: hdTestnetAddr,
  //     capacity: BigInt(1000e8), // 1000CKB
  //     fee: BigInt(1000000),
  //     safeMode: true,
  //     cells: unspentCells, // 选填， unspentCells 与cells 不一样
  //     deps: ckb.config.secp256k1Dep,
  //   })


  //   console.log("rawTransaction =>", rawTransaction);

  //   // rawTransaction.witnesses = rawTransaction.inputs.map(() => '0x')
  //   rawTransaction.witnesses[0] = {
  //     lock: '',
  //     inputType: '',
  //     outputType: ''
  //   }

  //   const signedTx = ckb.signTransaction(privateKey)(rawTransaction)
  //   console.log("signedTx =>", JSON.stringify(signedTx, null, 2))

  //   const realTxHash = await ckb.rpc.sendTransaction(signedTx)
  //   console.log(`The real transaction hash is: ${realTxHash}`)
  // })


  it("HD wallet", async () => {

    const seed = mnemonicToSeedSync(mnemonic)
    const masterKeychain = Keychain.fromSeed(seed)
    masterKeychain.privateKey.toString("hex")

    const accountKeychain = masterKeychain.derivePath(AccountExtendedPublicKey.ckbAccountPath);

    const accountExtendedPublicKey = new AccountExtendedPublicKey(
      accountKeychain.publicKey.toString('hex'),
      accountKeychain.chainCode.toString('hex'),
    )

    const firstPath = AccountExtendedPublicKey.ckbAccountPath + "/0/0" // 第1个地址

    const hdPrivateKey = `0x${masterKeychain.derivePath(firstPath).privateKey.toString('hex')}`

    const testnetAddr1 = CkbUtils.privateKeyToAddress(hdPrivateKey, {
      prefix: 'ckt',
    })

    expect(testnetAddr1).toBe(hdTestnetAddr)

    const hdPublicKey = ckb.utils.privateKeyToPublicKey(hdPrivateKey)

    const blake160 = `0x${ckb.utils.blake160(hdPublicKey, 'hex')}`

    const lockHash = ckb.utils.scriptToHash({
      hashType: "type",
      codeHash: chain.TestNetCodeHash,
      args: blake160
    })

    console.log("lockHash =>", lockHash);

    const unspentCells = await ckb.loadCells({
      lockHash,
      start: BigInt(41730),
      end: BigInt(41805),
    })

    console.log("unspentCells size", unspentCells.length)

    // ckb.utils.pubkeyToAddress(hdPublicKey, {
    //   prefix: 'ckt',
    // })

    const secp256k1Dep = await ckb.loadSecp256k1Dep();

    const rawTransaction = ckb.generateRawTransaction({
      fromAddress: testnetAddr1,
      toAddress: "ckt1qyqqep5jcm5uvpawpe4v2wmsh6zjlv27vj5qw0k009",
      capacity: BigInt(3000e8), // 1000CKB
      fee: BigInt(1000000),
      safeMode: true,
      cells: unspentCells, // 选填， unspentCells 与cells 不一样
      deps: ckb.config.secp256k1Dep,
    })

    console.log("rawTransaction =>", rawTransaction);

    rawTransaction.witnesses[0] = {
      lock: '',
      inputType: '',
      outputType: '',
    }

    const signedTx = ckb.signTransaction(hdPrivateKey)(rawTransaction)
    console.log("signedTx =>", JSON.stringify(signedTx, null, 2))

    const realTxHash = await ckb.rpc.sendTransaction(signedTx)
    console.log(`The real transaction hash is: ${realTxHash}`)
    // 0x1b4a1e7590b25bee97f10e5477d00874eece13afcfa6e6eed9f89f48320f6d32
  })

})


