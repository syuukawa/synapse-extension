const CKB = require('@nervosnetwork/ckb-sdk-core').default;
const chain =  require("../utils/constants").Ckb

const testnetRPC = 'http://127.0.0.1:8114'
const ckb = new CKB(testnetRPC)

import Keychain from '../wallet/keychain';
import Keystore from '../wallet/keystore'
import { mnemonicToSeedSync } from '../wallet/mnemonic';
import Address, { AddressType, publicKeyToAddress, AddressPrefix } from '../wallet/address'
import { generateMnemonic, AccountExtendedPublicKey, ExtendedPrivateKey } from "../wallet/key";


describe("balance", () => {
  jest.setTimeout(10000)

  const mnemonic = "excuse speak boring lunar consider sea behave next fog arrow black sweet"
  const hdMainnetAddr = "ckb1qyqt9ed4emcxyfed77ed0dp7kcm3mxsn97lsvzve7j"
  const hdTestnetAddr = "ckt1qyqt9ed4emcxyfed77ed0dp7kcm3mxsn97ls38jxjw"
  const password = "123456"

  it("get addr", () => {
    const seed = mnemonicToSeedSync(mnemonic)
    const masterKeychain = Keychain.fromSeed(seed)
    masterKeychain.privateKey.toString("hex")
    masterKeychain.privateKey.toString("hex")

    // const extendedPrivateKey = new ExtendedPrivateKey(
    //     masterKeychain.privateKey.toString("hex"),
    //     masterKeychain.chainCode.toString("hex")
    // )

    // const keystore = Keystore.create(extendedPrivateKey, password);

    const accountKeychain = masterKeychain.derivePath(AccountExtendedPublicKey.ckbAccountPath);

    const accountExtendedPublicKey = new AccountExtendedPublicKey(
      accountKeychain.publicKey.toString('hex'),
      accountKeychain.chainCode.toString('hex'),
    )

    const testnetAddr = accountExtendedPublicKey.address(AddressType.Receiving, 0, AddressPrefix.Testnet);
    const mainnetAddr = accountExtendedPublicKey.address(AddressType.Receiving, 0, AddressPrefix.Mainnet);

    expect(mainnetAddr.address).toBe('ckb1qyqt9ed4emcxyfed77ed0dp7kcm3mxsn97lsvzve7j')
    expect(testnetAddr.address).toBe('ckt1qyqt9ed4emcxyfed77ed0dp7kcm3mxsn97ls38jxjw')
  })

  it("get codeHash", async () => {
    jest.setTimeout(100000)

    const privateKey = "0xd40c79c4583b7d9eb5310649c5bd3d608ce24fffe5dd955e718439a1b40a5692"
    const publicKey = "0x027815a2decd1fb52f982dfe12304e6cf2ea5441d55f1a034c581d52f8cc2f416f"
    const blake160 = `0x${ckb.utils.blake160(publicKey, 'hex')}`

    const secp256k1Dep = await ckb.loadSecp256k1Dep();

    const lockHash = ckb.generateLockHash(blake160, secp256k1Dep)

    console.log("lockHash =>", lockHash);

    const genesisBlock = await ckb.rpc.getBlockByNumber('0x0')

    const typeScript = genesisBlock?.transactions[0]?.outputs[1]?.type

    const secp256k1TypeHash = ckb.utils.scriptToHash(typeScript)
    const codeHash = secp256k1TypeHash
    console.log("codeHash =>", codeHash)

    expect(codeHash).toBe(chain.TestNetCodeHash)

  })

  it("get balance", async ()=>{
    const privateKey = "0xd40c79c4583b7d9eb5310649c5bd3d608ce24fffe5dd955e718439a1b40a5692"
    const publicKey = "0x027815a2decd1fb52f982dfe12304e6cf2ea5441d55f1a034c581d52f8cc2f416f"
    const blake160 = `0x${ckb.utils.blake160(publicKey, 'hex')}`

    const lockHash = ckb.utils.scriptToHash({
      hashType: "type",
      codeHash: chain.TestNetCodeHash,
      args: blake160
    })

    console.log("lockHash =>", lockHash);

    const cells = await ckb.rpc.getCellsByLockHash(lockHash, BigInt(41740), BigInt(41745))

    expect(cells.length).toBe(1)

    let sum = BigInt(0)
    for(const cell of cells){
      sum += BigInt(cell.capacity)
    }

    expect(sum).toBe(BigInt(5000e8)) // 5000 CKB

  })

})
