/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const forge = require('node-forge');
const bitcoreMessage = require('bitcore-message');
const LinkedDataSignature2015 =
  require('jsonld-signatures/lib/suites/LinkedDataSignature2015');

module.exports = class EcdsaKoblitzSignature2016
  extends LinkedDataSignature2015 {
  constructor({
    privateKeyWif, publicKeyWif, creator, date, domain, nonce,
    useNativeCanonize} = {}) {
    super({
      type: 'EcdsaKoblitzSignature2016',
      creator, date, domain, nonce, useNativeCanonize});
    this.privateKeyWif = privateKeyWif;
    this.publicKeyWif = publicKeyWif;
  }

  async sign({verifyData, proof}) {
    if(typeof this.privateKeyWif !== 'string') {
      throw new TypeError('"privateKeyWif" must be a base58 formatted string.');
    }
    const bitcore = bitcoreMessage.Bitcore;
    const privateKey = bitcore.PrivateKey.fromWIF(this.privateKeyWif);
    const message = bitcoreMessage(forge.util.binary.raw.encode(verifyData));
    proof.signatureValue = message.sign(privateKey);

    return proof;
  }

  async verifySignature({verifyData, proof}) {
    const message = bitcoreMessage(forge.util.binary.raw.encode(verifyData));
    return message.verify(this.publicKeyWif, proof.signatureValue);
  }

  async getVerificationMethod({proof, documentLoader}) {
    const verificationMethod = await super.getVerificationMethod(
      {proof, documentLoader});
    if(typeof verificationMethod.publicKeyWif !== 'string') {
      throw new TypeError(
        'Unknown public key encoding. Public key encoding must be ' +
        '"publicKeyWif".');
    }
    if(!this.publicKeyWif) {
      this.publicKeyWif = verificationMethod.publicKeyWif;
    }
    return verificationMethod;
  }
};
