var fs = require('fs');
const path = require('path');
const { expect } = require('chai');
const { buildContractClass, bsv } = require('scrypttest');
const { inputIndex, inputSatoshis, tx, getPreimage, toHex } = require('../testHelper');

/*const dataFilename = "../../contracts/CheckDataIntegrity.scrypt"
var fileData = fs.readFileSync(path.join(__dirname, dataFilename));
var sha256hash = bsv.crypto.Hash.sha256(fileData);*/

var sha256hash = bsv.crypto.Hash.sha256(Buffer.from("abc"));// Test case from here: https://www.di-mgt.com.au/sha_testvectors.html
//ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
if(sha256hash.toString('hex')!="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"){
  console.log("Shasum calculation INCORRECT");
}
console.log(toHex(sha256hash))

var fileData =  Buffer.from("abc")
console.log(toHex(fileData))

describe('Test sCrypt contract CheckDataIntegrity In Javascript', () => {
  let testContract
  before(() => {
    const CheckDataIntegrity = buildContractClass(path.join(__dirname, '../../contracts/CheckDataIntegrity.scrypt'));
    testContract = new CheckDataIntegrity(toHex(sha256hash)) // Either I am initialising the contract with the wrong data type !!
  });
  
  it('shasum check should succeed when correct data is provided', () => {
    expect(testContract.validateDataChecksum(toHex(fileData)).to.equal(true));// Or I am passing the wrong data type here !!
  });

  it('shasum check should fail when wrong data provided', () => {
    expect(testContract.validateDataChecksum("wrong data")).to.equal(false);
  });
});