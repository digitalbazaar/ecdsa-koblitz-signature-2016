/*!
 * Copyright (c) 2014-2018 Digital Bazaar, Inc. All rights reserved.
 */
/* eslint-disable indent */
'use strict';

module.exports = async function({assert, constants, jsigs, mock, Suite}) {

const {
  PublicKeyProofPurpose} = jsigs.purposes;
const {NoOpProofPurpose} = mock;

// helper:
function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

const {testLoader} = mock;

// run tests
describe('JSON-LD Signatures', () => {
  const commonSuiteTests = [
    'EcdsaKoblitzSignature2016',
  ];

  for(const suiteName of commonSuiteTests) {
    const pseudorandom = ['EcdsaKoblitzSignature2016'];

    context(suiteName, () => {
      it('should sign a document w/security context', async () => {
        const suite = new Suite(mock.suites[suiteName].parameters.sign);
        const testDoc = clone(mock.securityContextTestDoc);
        const signed = await jsigs.sign(testDoc, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        let expected = mock.suites[suiteName].securityContextSigned;
        if(pseudorandom.includes(suiteName)) {
          expected = clone(expected);
          if(suite.legacy) {
            expected.signature.signatureValue = signed.signature.signatureValue;
          } else {
            expected.proof.jws = signed.proof.jws;
          }
        }
        assert.deepEqual(signed, expected);
      });

      it('should sign a document when `compactProof` is `false`', async () => {
        const suite = new Suite(mock.suites[suiteName].parameters.sign);
        const testDoc = clone(mock.securityContextTestDoc);
        const signed = await jsigs.sign(testDoc, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose(),
          compactProof: false
        });
        let expected = mock.suites[suiteName].securityContextSigned;
        if(pseudorandom.includes(suiteName)) {
          expected = clone(expected);
          if(suite.legacy) {
            expected.signature.signatureValue = signed.signature.signatureValue;
          } else {
            expected.proof.jws = signed.proof.jws;
          }
        }
        assert.deepEqual(signed, expected);
      });

      it('should sign a document w/o security context', async () => {
        const suite = new Suite(mock.suites[suiteName].parameters.sign);
        const testDoc = clone(mock.nonSecurityContextTestDoc);
        const signed = await jsigs.sign(testDoc, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        let expected = mock.suites[suiteName].nonSecurityContextSigned;
        if(pseudorandom.includes(suiteName)) {
          expected = clone(expected);
          if(suite.legacy) {
            expected[constants.SECURITY_SIGNATURE_URL]
              ['https://w3id.org/security#signatureValue'] =
              signed[constants.SECURITY_SIGNATURE_URL]
                ['https://w3id.org/security#signatureValue'];
          } else {
            expected[constants.SECURITY_PROOF_URL]['@graph']
              ['https://w3id.org/security#jws'] =
              signed[constants.SECURITY_PROOF_URL]['@graph']
                ['https://w3id.org/security#jws'];
          }
        }
        assert.deepEqual(signed, expected);
      });

      it('should verify a document w/security context', async () => {
        const suite = new Suite(mock.suites[suiteName].parameters.verify);
        const signed = mock.suites[suiteName].securityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: true,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...signed[property]
            },
            verified: true
          }]
        };
        assert.deepEqual(result, expected);
      });

      it('should verify a document when `compactProof` is `false`',
        async () => {
        const suite = new Suite(mock.suites[suiteName].parameters.verify);
        const signed = mock.suites[suiteName].securityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose(),
          compactProof: false
        });
        const property = suite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: true,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...signed[property]
            },
            verified: true
          }]
        };
        assert.deepEqual(result, expected);
      });

      it('should verify a document w/o security context', async () => {
        const suite = new Suite(mock.suites[suiteName].parameters.verify);
        const signed = mock.suites[suiteName].nonSecurityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: true,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...mock.suites[suiteName].securityContextSigned[property]
            },
            verified: true
          }]
        };
        assert.deepEqual(result, expected);
      });

      it('should fail to verify when `compactProof` is `false`', async () => {
        const suite = new Suite(mock.suites[suiteName].parameters.verify);
        const signed = mock.suites[suiteName].nonSecurityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose(),
          compactProof: false
        });
        assert.isObject(result);
        assert.equal(result.verified, false);
        assert.exists(result.error);
      });

      it('should verify a document w/security context w/passed key',
        async () => {
        const suite = new Suite(
          mock.suites[suiteName].parameters.verifyWithPassedKey);
        const signed = mock.suites[suiteName].securityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: true,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...signed[property]
            },
            verified: true
          }]
        };
        assert.deepEqual(result, expected);
      });

      it('should verify a document w/o security context w/passed key',
        async () => {
        const suite = new Suite(
          mock.suites[suiteName].parameters.verifyWithPassedKey);
        const signed = mock.suites[suiteName].nonSecurityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: true,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...mock.suites[suiteName].securityContextSigned[property]
            },
            verified: true
          }]
        };
        assert.deepEqual(result, expected);
      });

      it('should detect an invalid signature', async () => {
        const suite = new Suite(mock.suites[suiteName].parameters.verify);
        const signed = mock.suites[suiteName].securityContextInvalidSignature;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: false,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...signed[property]
            },
            verified: false
          }]
        };
        assert.isFalse(result.verified);
        assert.isArray(result.results);
        assert.equal(result.results.length, expected.results.length);
        assert.deepEqual(result.results[0].proof, expected.results[0].proof);
        assert.equal(result.results[0].verified, expected.results[0].verified);
        assert.equal(
          result.results[0].error.message,
          'Invalid signature.');
      });

      it('should sign a document with multiple signatures', async () => {
        const suite = new Suite(mock.suites[suiteName].parameters.sign);
        const testDoc = clone(mock.suites[suiteName].securityContextSigned);
        const signed = await jsigs.sign(testDoc, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        assert.isArray(signed[property]);
        assert.equal(signed[property].length, 2);
        const expected = clone(mock.suites[suiteName].securityContextSigned);
        expected[property] = [expected[property], clone(expected[property])];
        if(suite.legacy) {
          expected[property][1].signatureValue =
            signed[property][1].signatureValue;
        } else {
          expected[property][1].jws = signed[property][1].jws;
        }
        assert.deepEqual(signed, expected);
      });

      it('should verify a document with multiple set signatures', async () => {
        const suite = new Suite(mock.suites[suiteName].parameters.verify);
        const testDoc = clone(mock.suites[suiteName].securityContextSigned);
        const property = suite.legacy ? 'signature' : 'proof';
        testDoc[property] = [testDoc[property], clone(testDoc[property])];
        const result = await jsigs.verify(testDoc, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const expected = {
          verified: true,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...mock.suites[suiteName].securityContextSigned[property]
            },
            verified: true
          }, {
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...mock.suites[suiteName].securityContextSigned[property]
            },
            verified: true
          }]
        };
        assert.deepEqual(result, expected);
      });

      it('should sign and verify a document w/public key proof purpose',
        async () => {
        const signSuite = new Suite(mock.suites[suiteName].parameters.sign);
        const testDoc = clone(mock.securityContextTestDoc);
        const signed = await jsigs.sign(testDoc, {
          documentLoader: testLoader,
          suite: signSuite,
          purpose: new PublicKeyProofPurpose()
        });

        const verifySuite = new Suite(mock.suites[suiteName].parameters.verify);
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite: verifySuite,
          purpose: new PublicKeyProofPurpose()
        });
        const property = verifySuite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: true,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...signed[property]
            },
            verified: true
          }]
        };
        assert.deepEqual(result, expected);
      });
    });
  }

  const legacySuiteTests = [
    'EcdsaKoblitzSignature2016',
  ];

  for(const suiteName of legacySuiteTests) {
    context(`Legacy suite tests: ${suiteName}`, () => {
      it('should detect an expired date', async () => {
        const suite = new Suite({
          ...mock.suites[suiteName].parameters.verify
        });
        const signed = mock.suites[suiteName].securityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: new PublicKeyProofPurpose({
            date: new Date('01-01-1970'),
            maxTimestampDelta: 0
          })
        });
        const expected = {
          verified: false,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...signed.signature
            },
            verified: false
          }]
        };
        assert.isFalse(result.verified);
        assert.isArray(result.results);
        assert.equal(result.results.length, expected.results.length);
        assert.deepEqual(result.results[0].proof, expected.results[0].proof);
        assert.equal(result.results[0].verified, expected.results[0].verified);
        assert.equal(
          result.results[0].error.message,
          'The proof\'s created timestamp is out of range.');
      });

      it('should detect a non-matching domain', async () => {
        const suite = new Suite({
          ...mock.suites[suiteName].parameters.verify,
          date: new Date('01-01-1970'),
          domain: 'example.com'
        });
        const signed = mock.suites[suiteName].securityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: new PublicKeyProofPurpose()
        });
        const expected = {
          verified: false,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...signed.signature
            },
            verified: false
          }]
        };
        assert.isFalse(result.verified);
        assert.isArray(result.results);
        assert.equal(result.results.length, expected.results.length);
        assert.deepEqual(result.results[0].proof, expected.results[0].proof);
        assert.equal(result.results[0].verified, expected.results[0].verified);
        const expectedMessage = 'The domain is not as expected';
        assert.equal(
          result.results[0].error.message.substr(0, expectedMessage.length),
          expectedMessage);
      });
    });
  }
});

};
