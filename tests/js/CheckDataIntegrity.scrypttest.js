var fs = require('fs');
const path = require('path');
const { expect } = require('chai');
const { buildContractClass, bsv } = require('scrypttest');

const dataFilename = "../../contracts/CheckDataIntegrity.scrypt"
const fileData = fs.readFileSync(path.join(__dirname, dataFilename));
const sha256hash = bsv.crypto.Hash.sha256(fileData);

if(sha256hash.toString('hex')!="5b363fc8979a37d4d9c85d28ed9a8072d77844b32d72d4c3b265ecaddf8e6ae9"){
  console.log("Shasum calculation INCORRECT");
}

describe('Test sCrypt contract CheckDataIntegrity In Javascript', () => {
  let testContract

  before(() => {
    const CheckDataIntegrity = buildContractClass(path.join(__dirname, '../../contracts/CheckDataIntegrity.scrypt'));
    testContract = new CheckDataIntegrity(sha256hash)
  });

  it('shasum check should succeed when correct data is provided', () => {
    expect(testContract.validateDataChecksum(fileData)).to.equal(true);
  });

  it('shasum check should fail when wrong data provided', () => {
    expect(testContract.validateDataChecksum("wrong data")).to.equal(false);
  });
});