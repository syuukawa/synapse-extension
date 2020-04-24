import { MESSAGE_TYPE, KEYSTORE_TYPE, Ckb } from './utils/constants'
import { mnemonicToSeedSync, validateMnemonic, mnemonicToEntropy, entropyToMnemonic } from './wallet/mnemonic';
import * as ckbUtils from '@nervosnetwork/ckb-sdk-utils'

import { generateMnemonic } from './wallet/key';
import * as Keystore from './wallet/pkeystore';
import Keychain from './wallet/keychain';

import { AccountExtendedPublicKey, ExtendedPrivateKey } from "./wallet/key";
import { AddressType, AddressPrefix } from './wallet/address';
import { getBalanceByPublicKey, getBalanceByLockHash } from './balance';
import { sendSimpleTransaction } from './sendSimpleTransaction';
import { getAmountByTxHash, getStatusByTxHash, getFeeByTxHash, getInputAddressByTxHash, getOutputAddressByTxHash, getOutputAddressByTxHashAndIndex } from './transaction';
import { getPrivateKeyByKeyStoreAndPassword } from './wallet/exportPrivateKey'
import Address from './wallet/address';
import { getBalanceByAddress } from './utils/address'

const KeyperWallet = require('../src/keyper/keyperwallet');

/**
 * Listen messages from popup
 */

//TODO ====
let wallets = []
let currWallet = {}
let addresses = []

chrome.runtime.onMessage.addListener(async (request, sender, sendResp) => {

  //IMPORT_MNEMONIC
  if (request.messageType === MESSAGE_TYPE.IMPORT_MNEMONIC) {
    console.time()

    const mnemonic = request.mnemonic.trim();
    const password = request.password.trim();

    //验证助记词
    const isValidateMnemonic = validateMnemonic(mnemonic);
    if (!isValidateMnemonic) {
      chrome.runtime.sendMessage(MESSAGE_TYPE.IS_NOT_VALIDATE_MNEMONIC);
      return;
    } else {
      chrome.runtime.sendMessage(MESSAGE_TYPE.VALIDATE_PASS)
    }

    // store the mnemonic entropy
    const entropy = mnemonicToEntropy(mnemonic);

    const seed = mnemonicToSeedSync(mnemonic)
    const masterKeychain = Keychain.fromSeed(seed)

    const extendedKey = new ExtendedPrivateKey(
      masterKeychain.privateKey.toString('hex'),
      masterKeychain.chainCode.toString('hex')
    )

    //没有0x的privateKey
    const privateKey = masterKeychain.derivePath(Address.pathForReceiving(0)).privateKey.toString('hex');

    const addressObj = Address.fromPrivateKey(privateKey);
    const address = addressObj.address;

    chrome.runtime.sendMessage({ // 生成地址后，快速向页面发送地址信息
      messageType: MESSAGE_TYPE.SEND_ADDR,
      address
    })

    console.timeEnd()

    // 以下为耗时操作
    // 验证导入的地址是否已存在
    console.time("Keystore")
    const isExistObj = addressIsExist(address, addresses);
    if (isExistObj["isExist"]) {
      const index = isExistObj["index"];
      currWallet = wallets[addresses[index].walletIndex];
    } else {

      setTimeout(async ()=> {
        const rootKeystore = Keystore.encrypt(Buffer.from(extendedKey.serialize(), "hex"), password)
        const entropyKeystore = Keystore.encrypt(Buffer.from(entropy, "hex"), password)
        privateKeyToKeystore(privateKey, password, entropyKeystore, rootKeystore)
        // Add Keyper to Synapse
        await AddKeyperWallet(privateKey, password)
      }, 0)

    }

    // 002-
    saveToStorage();

    console.timeEnd("Keystore")
  }

  //GEN_MNEMONIC
  if (request.messageType === MESSAGE_TYPE.GEN_MNEMONIC) {
    const newmnemonic = generateMnemonic()

    chrome.runtime.sendMessage({
      mnemonic: newmnemonic,
      messageType: MESSAGE_TYPE.RECE_MNEMONIC
    })
  }

  //SAVE_MNEMONIC
  if (request.messageType === MESSAGE_TYPE.SAVE_MNEMONIC) {
    const mnemonic = request.mnemonic.trim();
    const password = request.password.trim();
    const confirmPassword = request.confirmPassword.trim();

    //助记词有效性的验证
    const isValidateMnemonic = validateMnemonic(mnemonic);

    if (!isValidateMnemonic) {
      console.log('isValidateMnemonic: ', "Not a ValidateMnemonic");
      chrome.runtime.sendMessage(MESSAGE_TYPE.IS_NOT_VALIDATE_MNEMONIC);
      return;
    }

    //store the mnemonic entropy
    const entropy = mnemonicToEntropy(mnemonic);
    const entropyKeystore = Keystore.encrypt(Buffer.from(entropy, "hex"), password);

    const seed = mnemonicToSeedSync(mnemonic)
    const masterKeychain = Keychain.fromSeed(seed)

    const extendedKey = new ExtendedPrivateKey(
      masterKeychain.privateKey.toString('hex'),
      masterKeychain.chainCode.toString('hex')
    )
    const rootKeystore = Keystore.encrypt(Buffer.from(extendedKey.serialize(), "hex"), password);

    const privateKey = masterKeychain.derivePath(Address.pathForReceiving(0)).privateKey.toString('hex');
    const addressObject = Address.fromPrivateKey(privateKey);
    const address = addressObject.address;

    //验证导入的Keystore是否已经存在
    //000-addressIsExist
    const isExistObj = addressIsExist(address, addresses);
    if (isExistObj["isExist"]) {
      const index = isExistObj["index"];
      currWallet = wallets[addresses[index].walletIndex];
    } else {
      //001-privateKeyToKeystore
      privateKeyToKeystore(privateKey, password, entropyKeystore, rootKeystore);

      //Add Keyper to Synapse
      await AddKeyperWallet(privateKey,password);
    }

    //002-saveToStorage
    saveToStorage();

    chrome.runtime.sendMessage(MESSAGE_TYPE.VALIDATE_PASS);
  }

  // REQUEST_ADDRESS_INFO
  // if (request.messageType === MESSAGE_TYPE.REQUEST_ADDRESS_INFO) {
  //   chrome.storage.sync.get(['currWallet'], function (wallet) {
  //     const message: any = {
  //       messageType: MESSAGE_TYPE.ADDRESS_INFO
  //     }
  //     if (wallet) {
  //       message.address = wallet.currWallet.address
  //     }
  //     chrome.runtime.sendMessage(message)
  //   });
  // }

  if (request.messageType === MESSAGE_TYPE.REQUEST_BALANCE_BY_ADDRESS) {

    const address = request.address.trim()
    const balance = await getBalanceByAddress(address)

    chrome.runtime.sendMessage({
      balance,
      messageType: MESSAGE_TYPE.BALANCE_BY_ADDRESS
    })
  }

  //发送交易
  if (request.messageType === MESSAGE_TYPE.RESQUEST_SEND_TX) {

    chrome.storage.sync.get(['currWallet'], async function (result) {

      console.log("currWallet ===>", result);
      console.log("wallet.currWallet.keystore ===>", result.currWallet.keystore);

      const toAddress = request.address.trim();
      const amount = request.amount.trim();
      const fee = request.fee.trim();
      const password = request.password.trim();

      //缺少0x的privateKey
      const privateKey = Keystore.decrypt(result.currWallet.keystore, password);
      console.log("privateKey ===>", privateKey);

      //PrivateKey导入的情况还未解决
      const fromAddress = result.currWallet.address;

      const sendTxHash = await sendSimpleTransaction(
        '0x' + privateKey,
        fromAddress,
        toAddress,
        BigInt(amount),
        BigInt(fee));

      chrome.runtime.sendMessage({
        fromAddress: fromAddress,
        toAddress: toAddress,
        amount: amount.toString(),
        fee: fee.toString(),
        txHash: sendTxHash,
        messageType: MESSAGE_TYPE.TO_TX_DETAIL
      })
    });
  }

  //tx-detail
  if (request.messageType === MESSAGE_TYPE.REQUEST_TX_DETAIL) {
    // chrome.storage.sync.get(['wallet'], async function( {wallet} ) {

    const txHash = request.message.txHash;
    const amount = request.message.amount;
    const fee = request.message.fee;
    const inputs = request.message.fromAddress;
    const outputs = request.message.toAddress;
    const status = await getStatusByTxHash(txHash);

    chrome.runtime.sendMessage({
      status,
      tradeAmount: amount,
      fee,
      inputs,
      outputs,
      txHash,
      messageType: MESSAGE_TYPE.TX_DETAIL
    })
    // });
  }

  //export-private-key check
  if (request.messageType === MESSAGE_TYPE.EXPORT_PRIVATE_KEY_CHECK) {

    chrome.storage.sync.get(['currWallet'], function (wallet) {

      const password = request.password;
      const keystore = wallet.currWallet.keystore
      //TODO check the password
      const privateKey = Keystore.decrypt(keystore, password)

      //send the check result to the page
      if (!privateKey) {
        chrome.runtime.sendMessage({
          isValidatePassword: false,
          messageType: MESSAGE_TYPE.EXPORT_PRIVATE_KEY_CHECK_RESULT
        })
      }

      chrome.runtime.sendMessage({
        isValidatePassword: true,
        keystore,
        privateKey,
        messageType: MESSAGE_TYPE.EXPORT_PRIVATE_KEY_CHECK_RESULT
      })
    });
  }

  //export-private-key-second check
  if (request.messageType === MESSAGE_TYPE.EXPORT_PRIVATE_KEY_SECOND) {

    const privateKey = request.message.privateKey;
    const keystore = request.message.keystore;

    chrome.runtime.sendMessage({
      privateKey,
      keystore: JSON.stringify(keystore),
      messageType: MESSAGE_TYPE.EXPORT_PRIVATE_KEY_SECOND_RESULT
    })
  }

  //my addresses
  if (request.messageType === MESSAGE_TYPE.REQUEST_MY_ADDRESSES) {

    chrome.storage.sync.get(['accounts'], async function (result) {

      await new Promise(resolve => setTimeout(resolve, 500));

      const accounts = result.accounts;
      const addresses = [];
      for (let i = 0; i < accounts.length; i++) {
        const account = accounts[i];
        const capacity = await getBalanceByLockHash(account.lock);
        const address = {
          address: account.address,
          type: account.type,
          capacity: capacity.toString(),
          lock: account.lock
        }
        addresses.push(address);
      }
      console.log("addresses =>", addresses);
      chrome.runtime.sendMessage({
        addresses: addresses,
        messageType: MESSAGE_TYPE.RESULT_MY_ADDRESSES
      })
    });
  }

  //export-mneonic check
  if (request.messageType === MESSAGE_TYPE.EXPORT_MNEONIC_CHECK) {

    chrome.storage.sync.get(['currWallet'], function (wallet) {

      const password = request.password;
      console.log("wallet.currWallet ===>", wallet.currWallet)
      const entropyKeystore = wallet.currWallet.entropyKeystore
      //TODO check the password
      const entropy = Keystore.decrypt(entropyKeystore, password)

      console.log("entropy ===>", entropy);
      // //send the check result to the page
      if (entropy !== "") {
        chrome.runtime.sendMessage({
          isValidatePassword: false,
          messageType: MESSAGE_TYPE.EXPORT_PRIVATE_KEY_CHECK_RESULT
        })
      }

      chrome.runtime.sendMessage({
        isValidatePassword: true,
        password,
        entropyKeystore,
        messageType: MESSAGE_TYPE.EXPORT_MNEONIC_CHECK_RESULT
      })
    });
  }

  //export-mneonic-second check
  if (request.messageType === MESSAGE_TYPE.EXPORT_MNEONIC_SECOND) {

    const password = request.message.password;
    const entropyKeystore = request.message.entropyKeystore;

    const entropy = Keystore.decrypt(entropyKeystore, password);
    const mnemonic = entropyToMnemonic(entropy);

    chrome.runtime.sendMessage({
      // mnemonic: JSON.stringify(mnemonic),
      mnemonic,
      messageType: MESSAGE_TYPE.EXPORT_MNEONIC_SECOND_RESULT
    })
  }

  //onKeyper test
  // if (request.messageType === MESSAGE_TYPE.ON_KEYPER) {

  //   await KeyperWallet.init(); //初始化Container
  //   // console.log("Init ==== !!!!");
  //   const password = "123456";
  //   const privateKey = "";
  //   const publicKey = await KeyperWallet.generateKeyKeyper(password, privateKey, publicKey);
  //   console.log(publicKey);

  //   const accounts = await KeyperWallet.accounts();

  //   //Just For Test
  //   // console.log("accounts ===>: ", accounts);
  //   // for (let i = 0; i < accounts.length; i++) {
  //   //   const account = accounts[i];
  //   //   console.log("account.lock ===>",account.lock);
  //   //   // const result = await cache.findCells(
  //   //   //   JSON.stringify(
  //   //   //     QueryBuilder.create()
  //   //   //       .setLockHash(account.lock)
  //   //   //       .build()
  //   //   //   )
  //   //   // );
  //   // }
  //   const addresses = [];
  //   for (let i = 0; i < accounts.length; i++) {
  //     const account = accounts[i];
  //     // const capacity = await getBalanceByLockHash(account.lock);
  //     const capacity = 0;
  //     const address = {
  //       address: account.address,
  //       type: account.type,
  //       capacity: capacity,
  //       lock: account.lock
  //     }
  //     addresses.push(address);
  //   }

  //   chrome.runtime.sendMessage({
  //     addresses,
  //     messageType: MESSAGE_TYPE.RESULT_MY_ADDRESSES
  //   })
  // }


  // import private key
  if (request.messageType === MESSAGE_TYPE.IMPORT_PRIVATE_KEY) {

    //没有0x的privateKey
    const privateKey = request.privatekey.trim();
    const password = request.password.trim()

    //TODO 是否需要currWallet中的keystore的验证;
    const keystore = currWallet['keystore']
    if (keystore === undefined || keystore === "" || keystore === "undefined") {
      throw new Error('currWallet keystore is null')
    }
    if (!Keystore.checkPasswd(keystore, password)) {
      throw new Error('password incorrect')
    }

    const addressObj = Address.fromPrivateKey(privateKey);
    const address = addressObj.address;
    const isExistObj = addressIsExist(address, addresses);

    if (isExistObj["isExist"]) {
      const index = isExistObj["index"];
      currWallet = wallets[addresses[index].walletIndex];
    } else {
      //001-
      privateKeyToKeystore(privateKey, password, "", "");

      //Add Keyper to Synapse
      await AddKeyperWallet(privateKey, password);
    }

    //002-
    saveToStorage();

    chrome.runtime.sendMessage({
      messageType: MESSAGE_TYPE.IMPORT_PRIVATE_KEY_OK
    })
  }

});

//3- Type
//privateKey 没有0x前缀
function privateKeyToKeystore(privateKey, password, entropyKeystore, rootKeystore, prefix = AddressPrefix.Testnet) {

  const buff = Buffer.from(privateKey, 'hex')
  const newkeystore = Keystore.encrypt(buff, password)

  let _obj = {}
  _obj['id'] = newkeystore.id
  _obj['version'] = newkeystore.version
  _obj["crypto"] = newkeystore.crypto

  const addressObj = Address.fromPrivateKey(privateKey, prefix);
  const blake160 = addressObj.getBlake160(); //publicKeyHash

  const lockHash = ckbUtils.scriptToHash({
    hashType: "type",
    codeHash: Ckb.MainNetCodeHash,
    args: blake160,
  })

  const wallet = {
    "path": addressObj.path, //ckt 有问题
    "blake160": blake160,
    "address": addressObj.address,
    "lockHash": lockHash,
    "entropyKeystore": entropyKeystore, //助记词
    "rootKeystore": rootKeystore, //Root
    "keystore": _obj,
    "keystoreType": KEYSTORE_TYPE.PRIVATEKEY_TO_KEYSTORE
  }
  wallets.push(wallet)

  const _address = {
    "address": addressObj.address,
    "walletIndex": wallets.length - 1
  }
  addresses.push(_address);
  currWallet = wallets[_address.walletIndex];
}

function saveToStorage() {

  chrome.storage.sync.set({ wallets, }, () => {
    console.log('wallets is set to storage: ' + JSON.stringify(wallets));
  });

  chrome.storage.sync.set({ currWallet, }, () => {
    console.log('currWallet is set to storage: ' + JSON.stringify(currWallet));
  });

  chrome.storage.sync.set({ addresses, }, () => {
    console.log('addresses is set to storage: ' + JSON.stringify(addresses));
  });
}

function addressIsExist(address, addresses): {} {
  let isExist = false;
  let index = 99999;
  if (addresses.length === 0) {
    //不处理
  } else {
    for (let i = 0; i < addresses.length; i++) {
      if (address === addresses[i].address) {
        isExist = true;
        // currWallet = wallets[addresses[i].walletIndex];
        index = i;
        break;
      }
    }
  }
  const result = {
    isExist: isExist,
    index: index
  }
  return result;
}

async function AddKeyperWallet(privateKey, password) {

  await KeyperWallet.init();
  await KeyperWallet.generateKeyPrivateKey(password, privateKey);

  //Keyper accounts
  const accounts = await KeyperWallet.accounts()
  chrome.storage.sync.set({ accounts, }, () => {
    console.log('keyper accounts is set to storage: ' + JSON.stringify(accounts));
  });
}