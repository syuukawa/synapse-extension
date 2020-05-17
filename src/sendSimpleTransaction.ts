import Address, { AddressType, publicKeyToAddress, AddressPrefix } from './wallet/address';
import { Ckb } from './utils/constants';

const CKB = require('@nervosnetwork/ckb-sdk-core').default;

const ckb = new CKB("http://101.200.147.143:8117/rpc")

export const sendSimpleTransaction = async (
  privateKey,
  fromAddress,
  toAddress,
  sendCapacity,
  sendFee,
) => {

  const secp256k1Dep = await ckb.loadSecp256k1Dep();

  // 19-21 可删掉，直接传入 lockHash 参数
  const publicKey = ckb.utils.privateKeyToPublicKey(privateKey);
  const publicKeyHash = `0x${ckb.utils.blake160(publicKey, 'hex')}`;
  const lockHash = ckb.generateLockHash(publicKeyHash, secp256k1Dep);

  const unspentCells = await ckb.loadCells({
    lockHash,
    start: BigInt(210000),
    STEP: '0x64'
  });

  const rawTransaction = ckb.generateRawTransaction({
    fromAddress: fromAddress,
    toAddress: toAddress,
    capacity: sendCapacity,
    fee: sendFee,
    safeMode: true,
    cells: unspentCells,
    deps: ckb.config.secp256k1Dep,
  });

  rawTransaction.witnesses = rawTransaction.inputs.map(() => '0x');
  rawTransaction.witnesses[0] = {
    lock: '',
    inputType: '',
    outputType: '',
  };

  const signedTx = ckb.signTransaction(privateKey)(rawTransaction);
  const realTxHash = await ckb.rpc.sendTransaction(signedTx);
  return realTxHash;
};
