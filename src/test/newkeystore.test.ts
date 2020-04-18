import Keystore from '../wallet/keystore';

describe('keystore ', () => {
  const passwd = "111111"
  const privKey = "889e4dc76349958f7ad481c178071ec57ed2b505b29cdadd15441e0abd798753"
  it('keystore lock recover', () => {
    const _keystore = Keystore.lock(privKey, passwd)
    const keystore = _keystore.toJson()

    console.log(keystore);

    const newkeystore = Keystore.fromJson(JSON.stringify(keystore))
    const content = newkeystore.recover(passwd)

    console.log("content =>", content);

    expect(content).toEqual(privKey)
  })
})