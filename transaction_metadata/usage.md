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
`txMerkleTree.mjs`
to be used in JS client and
`txMerkleTree.py`
to be used in Python  client

```
cp txMerkleTree.py ../tests/application_client txMerkleTree.py
```
