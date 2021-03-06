// const numberToBN = require("number-to-bn");
// const utils = require("@nervosnetwork/ckb-sdk-utils/lib");
// const {
//   SignatureAlgorithm
// } = require("@keyper/specs/lib");

import * as numberToBN from 'number-to-bn';
import * as utils from '@nervosnetwork/ckb-sdk-utils/lib';
import { SignatureAlgorithm } from '@keyper/specs/lib';

class AnyPayLockScript {
  name = 'AnyPay';
  codeHash = '0x6a3982f9d018be7e7228f9e0b765f28ceff6d36e634490856d2b186acf78e79b';
  hashType = 'type';
  provider = null;

  deps() {
    return [
      {
        outPoint: {
          txHash: '0x9af66408df4703763acb10871365e4a21f2c3d3bdc06b0ae634a3ad9f18a6525',
          index: '0x0',
        },
        depType: 'depGroup',
      },
    ];
  }

  script(publicKey) {
    const args = utils.blake160(publicKey);
    return {
      codeHash: this.codeHash,
      hashType: this.hashType,
      args: `0x${Buffer.from(args).toString('hex')}`,
    };
  }

  signatureAlgorithm() {
    return SignatureAlgorithm.secp256k1;
  }

  async setProvider(provider) {
    this.provider = provider;
  }

  async sign(context, rawTx, config = { index: 0, length: -1 }) {
    const txHash = utils.rawTransactionToHash(rawTx);

    if (config.length === -1) {
      config.length = rawTx.witnesses.length;
    }

    if (config.length + config.index > rawTx.witnesses.length) {
      throw new Error('request config error');
    }
    if (typeof rawTx.witnesses[config.index] !== 'object') {
      throw new Error('first witness in the group should be type of WitnessArgs');
    }

    const emptyWitness = {
      // @ts-ignore
      ...rawTx.witnesses[config.index],
      lock: `0x${'0'.repeat(130)}`,
    };

    const serializedEmptyWitnessBytes = utils.hexToBytes(utils.serializeWitnessArgs(emptyWitness));
    const serialziedEmptyWitnessSize = serializedEmptyWitnessBytes.length;

    const s = utils.blake2b(32, null, null, utils.PERSONAL);
    s.update(utils.hexToBytes(txHash));
    s.update(
      utils.hexToBytes(
        utils.toHexInLittleEndian(`0x${numberToBN(serialziedEmptyWitnessSize).toString(16)}`, 8),
      ),
    );
    s.update(serializedEmptyWitnessBytes);

    for (let i = config.index + 1; i < config.index + config.length; i++) {
      const w = rawTx.witnesses[i];
      // @ts-ignore
      const bytes = utils.hexToBytes(typeof w === 'string' ? w : utils.serializeWitnessArgs(w));
      s.update(
        utils.hexToBytes(
          utils.toHexInLittleEndian(`0x${numberToBN(bytes.length).toString(16)}`, 8),
        ),
      );
      s.update(bytes);
    }

    const message = `0x${s.digest('hex')}`;
    const signd = await this.provider.sign(context, message);
    // @ts-ignore
    rawTx.witnesses[config.index].lock = signd;
    // @ts-ignore
    rawTx.witnesses[config.index] = utils.serializeWitnessArgs(rawTx.witnesses[config.index]);

    return rawTx;
  }
}

module.exports = AnyPayLockScript;
