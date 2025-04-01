import { readFileSync } from 'fs'
import { join, resolve } from 'path'

import {
  createData,
  TorspecKeyblindSigner
} from "../../index";
import {
  torspecKeyblindPublicKeyFromExpandedKey
} from '../signing/chains/TorspecKeyblindSigner';

const EXAMPLE_MASTER_ID_PUBLIC_KEY = readFileSync(
  join(resolve(), './src/__tests__/test_keys/torspec_keyblind_master_id_public_key'
  )
)
const EXAMPLE_MASTER_ID_SECRET_KEY = readFileSync(
  join(
    resolve(),
    './src/__tests__/test_keys/torspec_keyblind_master_id_secret_key'
  )
)
const EXAMPLE_SIGNING_CERT = readFileSync(
  join(resolve(), './src/__tests__/test_keys/torspec_keyblind_signing_cert')
)
const EXAMPLE_SIGNING_SECRET_KEY = readFileSync(
  join(resolve(), './src/__tests__/test_keys/torspec_keyblind_signing_secret_key')
)

describe('TorspecKeyblindSigner', () => {
  it('signs & verifies stuff', async () => {
    const certified_key = EXAMPLE_SIGNING_CERT.subarray(39, 71)
    const extData = EXAMPLE_SIGNING_CERT.subarray(76, 108)
    const signature = EXAMPLE_SIGNING_CERT.subarray(108, 172)
    const digest = EXAMPLE_SIGNING_CERT.subarray(
      32,
      EXAMPLE_SIGNING_CERT.length - 64
    )
    const master_id_pk = EXAMPLE_MASTER_ID_PUBLIC_KEY.subarray(32)
    const master_id_sk = EXAMPLE_MASTER_ID_SECRET_KEY.subarray(32)
    const signing_sk = EXAMPLE_SIGNING_SECRET_KEY.subarray(32)
    const signing_pk = torspecKeyblindPublicKeyFromExpandedKey(
      signing_sk.subarray(0, 32)
    )

    const cert_verified = await TorspecKeyblindSigner.verify(extData, digest, signature)
    const signer = new TorspecKeyblindSigner(master_id_sk, master_id_pk)
    const tor_signer_signature = await signer.sign(digest)
    const tor_signer_verify = await TorspecKeyblindSigner.verify(
      master_id_pk,
      digest,
      signature
    )

    expect(cert_verified).toBe(true)
    expect(Buffer.from(signing_pk).toString('hex'))
      .toEqual(certified_key.toString('hex'))
    expect(Buffer.from(tor_signer_signature).toString('hex'))
      .toEqual(signature.toString('hex'))
    expect(tor_signer_verify).toBe(true)
  })

  it('creates data items', async () => {
    const certified_key = EXAMPLE_SIGNING_CERT.subarray(39, 71)
    const signing_sk = EXAMPLE_SIGNING_SECRET_KEY.subarray(32)
    const signing_pk = Buffer.from(
      torspecKeyblindPublicKeyFromExpandedKey(signing_sk.subarray(0, 32))
    )
    const signer = new TorspecKeyblindSigner(signing_sk, signing_pk)
    const obj = { hello: 'world' }
    const dataItem = createData(JSON.stringify(obj), signer)

    await dataItem.sign(signer)

    expect(
      Buffer.from(dataItem.owner, 'base64').toString('hex')
    ).toEqual(certified_key.toString('hex'))

    const isValid = await dataItem.isValid()
    expect(isValid).toBe(true)
  })
})
