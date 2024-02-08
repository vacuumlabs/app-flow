## Generate merkle tree files from manifest files
```
nvm use 16.10.0
cd tree
yarn run generate
cd ..
cd tests
yarn run generate
cd ..
```

This produces
- `txMerkleTree.mjs` to be used in JS client. 
- `txMerkleTree.py` to be used in Python client.
- `testvectors/manifestPayloadCases.json`  to be used in manifest tests. Further files may be used for testing purposes in the future. They were used by hard to maintain unit tests in C++ before.

```
cp txMerkleTree.py ../tests/application_client/
cp testvectors/manifestPayloadCases.json ../tests/
```
