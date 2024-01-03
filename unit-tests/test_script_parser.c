#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <cmocka.h>

#include "script_parser.h"

bool PARSE_TEST(const char *script, size_t scriptSize, const char *template, size_t templateSize, bool expectedResult, 
                                     const char **expectedValues, size_t expectedValuesSize) {
    script_parsed_elements_t parsed;
    bool result = parseScript(&parsed, (const uint8_t *) script, scriptSize,
                            (const uint8_t *) template, templateSize);
    if (result != expectedResult) {        
        printf("Return value error: Result: %d, expected: %d\n", result, expectedResult);
        return false;
    }
    if (result) {
        if (parsed.elements_count != expectedValuesSize) {
            printf("Value size error: Result: %ld, expected: %ld\n", parsed.elements_count, expectedValuesSize);
            return false;
        }

        for(size_t i=0; i<expectedValuesSize; i++) {
            size_t len = strlen(expectedValues[i]);
            size_t parsedLen = parsed.elements[i].length;
            if (len != parsedLen || memcmp(parsed.elements[i].data, expectedValues[i], len) != 0) {
                if (len != parsedLen) {
                    printf("Return element %ld error, Length:%ld, Parsed length: %ld\n", i, len, parsedLen);
                }
                else {
                    printf("Strings: %s  .......  %s\n",parsed.elements[i].data, expectedValues[i]);
                    for(size_t j=0; j<len; j++) {
                        printf("Error in parsed strings %ld, %ld, Parsed:%c Expected:%c\n", i, j, parsed.elements[i].data[j], expectedValues[i][j]);
                    }
                }
                return false;
            }
        }
    }
    return true;
}

typedef bool (*NFTFunction)(script_parsed_elements_t *, const uint8_t *, size_t);

bool PARSE_NFT_TEST(NFTFunction parseNFTFunction, const char *script, size_t scriptSize, bool expectedResult, 
                                        const char ** expectedValues,
                                        size_t expectedValuesSize,
                                        script_parsed_type_t expectedScriptType) {
    script_parsed_elements_t parsed;
    bool result = parseNFTFunction(&parsed, (const uint8_t *) script, scriptSize);
    if (result != expectedResult) {
        printf("Return value error: Result: %d, expected: %d\n", result, expectedResult);
        return false;
    }
    if (result) {
        if (parsed.script_type != expectedScriptType) {
            printf("Value size error: Result: %ld, expected: %ld\n", parsed.elements_count, expectedValuesSize);
            return false;
        }

        if (parsed.elements_count != expectedValuesSize) {
            return false;
        }

        for(size_t i=0; i<expectedValuesSize; i++) {
            size_t len = strlen(expectedValues[i]);
            size_t parsedLen = parsed.elements[i].length;
            if (len != parsedLen || memcmp(parsed.elements[i].data, expectedValues[i], len) != 0) {
                if (len != parsedLen) {
                    printf("Return element %ld error, Length:%ld, Parsed length: %ld\n", i, len, parsedLen);
                }
                else {
                    printf("Strings: %s  .......  %s\n",parsed.elements[i].data, expectedValues[i]);
                    for(size_t j=0; j<len; j++) {
                        printf("Error in parsed strings %ld, %ld, Parsed:%c Expected:%c\n", i, j, parsed.elements[i].data[j], expectedValues[i][j]);
                    }
                }
                return false;
            }
        }
    }
    return true;
}

//templates 3-5 should always fail
const char TEMPLATE1[] = "abb\001 aa \001";
const char TEMPLATE2[] = "abb\001 aa\001 a";
const char TEMPLATE3[] = "\001 \001 \001 \001 \001 \001 \001 \001 \001 \001 \001 \001";
const char TEMPLATE4[] = "\001\001";
const char TEMPLATE5[] = "\001a";
const char TEMPLATE6[] = "\001 a";
const char TEMPLATE7[] = "a\001^\001";

static void test_parseTest(void **state) {
    {const char input[] = "abbxxy aa yy";
    const char *expected[2] = {"xxy", "yy"};
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE1, sizeof(TEMPLATE1)-1, true, expected, sizeof(expected)/sizeof(*expected)));}
    {const char input[] = "abbxxy aa y ";
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE1, sizeof(TEMPLATE1)-1, false, NULL, 0));}
    {const char input[] = "abbxxy aayy";
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE1, sizeof(TEMPLATE1)-1, false, NULL, 0));}
    {const char input[] = "abbxxy aa y;";
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE1, sizeof(TEMPLATE1)-1, false, NULL, 0));}
    {const char input[] = "abbxxy aa y?";
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE1, sizeof(TEMPLATE1)-1, false, NULL, 0));}
    {const char input[] = "abbxxy aa y a";
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE2, sizeof(TEMPLATE2)-1, false, NULL, 0));}
    {const char input[] = "abbxxy aay a";
    const char *expected[2] = {"xxy", "y"};
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE2, sizeof(TEMPLATE2)-1, true, expected, sizeof(expected)/sizeof(*expected)));}
    {const char input[] = "a a a a a a a a a a a a";
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE3, sizeof(TEMPLATE3)-1, false, NULL, 0));}
    {const char input[] = "aa";
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE4, sizeof(TEMPLATE4)-1, false, NULL, 0));}
    {const char input[] = "a a";
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE4, sizeof(TEMPLATE4)-1, false, NULL, 0));}
    {const char input[] = "ba";
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE5, sizeof(TEMPLATE5)-1, false, NULL, 0));}
    {const char input[] = "Abb_xy a";
    const char *expected[1] = {"Abb_xy"};
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE6, sizeof(TEMPLATE6)-1, true, expected, sizeof(expected)/sizeof(*expected)));}
    {const char input[] = "aa^__";
    const char *expected[2] = {"a", "__"};
    assert_true(PARSE_TEST(input, sizeof(input)-1, TEMPLATE7, sizeof(TEMPLATE7)-1, true, expected, sizeof(expected)/sizeof(*expected)));}
}

static void test_parseTestNFT1(void **state) {
    assert_true(PARSE_NFT_TEST(parseNFT1, "", 0, false, NULL, 0, SCRIPT_TYPE_UNKNOWN));

    const char script1[] = 
        "import NonFungibleToken from 0x631e88ae7f1d7c20\n"
        "import MetadataViews from 0x631e88ae7f1d7c20\n"
        "import aaa from bbb\n"
        "transaction {\n"
        "  prepare(acct: AuthAccount) {\n"
        "    let collectionType = acct.type(at: /storage/c)\n"
        "    // if there already is a collection stored, return\n"
        "    if (collectionType != nil) {\n"
        "      return\n"
        "    }\n"
        "    // create empty collection\n"
        "    let collection <- aaa.createEmptyCollection()\n"
        "    // put the new Collection in storage\n"
        "    acct.save(<-collection, to: /storage/c)\n"
        "    // create a public capability for the collection\n"
        "    acct.link<&{NonFungibleToken.CollectionPublic, NonFungibleToken.Receiver, x._, MetadataViews.ResolverCollection}>(\n"
        "      /public/zzzzzzZ,\n"
        "      target: /storage/c\n"
        "    )\n"
        "  }\n"
        "}\n";

    const char* expected1[11] = {"0x631e88ae7f1d7c20", "0x631e88ae7f1d7c20", "aaa", "bbb", "c", "aaa", "c", "x", "_", "zzzzzzZ", "c"};
    assert_true(PARSE_NFT_TEST(parseNFT1, script1, sizeof(script1)-1, true, expected1, sizeof(expected1)/sizeof(*expected1), 
                               SCRIPT_TYPE_NFT_SETUP_COLLECTION));

    const char script2[] = 
        "import NonFungibleToken from 0x631e88ae7f1d7c20\n"
        "import MetadataViews from 0x631e88ae7f1d7c20\n"
        "import aaa from bbb\n"
        "transaction {\n"
        "  prepare(acct: AuthAccount) {\n"
        "    let collectionType = acct.type(at: /storage/c)\n"
        "    // if there already is a collection stored, return\n"
        "    if (collectionType != nil) {\n"
        "      return\n"
        "    }\n"
        "    // create empty collection\n"
        "    let collection <- aaa.createEmptyCollection()\n"
        "    // put the new Collection in storage\n"
        "    acct.save(<-collection, to: /storage/cc)\n"
        "    // create a public capability for the collection\n"
        "    acct.link<&{NonFungibleToken.CollectionPublic, NonFungibleToken.Receiver, x._, MetadataViews.ResolverCollection}>(\n"
        "      /public/zzzzzzZ,\n"
        "      target: /storage/c\n"
        "    )\n"
        "  }\n"
        "}\n";

    assert_true(PARSE_NFT_TEST(parseNFT1, script2, sizeof(script2)-1, false, NULL, 0, SCRIPT_TYPE_UNKNOWN)); //storages do not match

    const char script3[] = 
        "import NonFungibleToken from 0x631e88ae7f1d7c20\n"
        "import MetadataViews from 0x631e88ae7f1d7c20\n"
        "import aaaa from bbb\n"
        "transaction {\n"
        "  prepare(acct: AuthAccount) {\n"
        "    let collectionType = acct.type(at: /storage/c)\n"
        "    // if there already is a collection stored, return\n"
        "    if (collectionType != nil) {\n"
        "      return\n"
        "    }\n"
        "    // create empty collection\n"
        "    let collection <- aaa.createEmptyCollection()\n"
        "    // put the new Collection in storage\n"
        "    acct.save(<-collection, to: /storage/c)\n"
        "    // create a public capability for the collection\n"
        "    acct.link<&{NonFungibleToken.CollectionPublic, NonFungibleToken.Receiver, x._, MetadataViews.ResolverCollection}>(\n"
        "      /public/zzzzzzZ,\n"
        "      target: /storage/c\n"
        "    )\n"
        "  }\n"
        "}\n";

    assert_true(PARSE_NFT_TEST(parseNFT1, script3, sizeof(script3)-1, false, NULL, 0, SCRIPT_TYPE_UNKNOWN)); //contract names do not match
}

static void test_parseTestNFT2(void **state) {
    assert_true(PARSE_NFT_TEST(parseNFT2, "", 0, false, NULL, 0, SCRIPT_TYPE_UNKNOWN));

    const char script1[] = 
        "import NonFungibleToken from 0x1d7e57aa55817448\n"
        "import aaaa from bbb\n"
        "transaction(recipient: Address, withdrawID: UInt64) {\n"
        "  // local variable for storing the transferred nft\n"
        "  let transferToken: @NonFungibleToken.NFT\n"
        "  prepare(owner: AuthAccount) {\n"
        "      // check if collection exists\n"
        "      if (owner.type(at: /storage/ststst) != Type<@aaaa.Collection>()) {\n"
        "        panic(\"Could not borrow a reference to the stored collection\")\n"
        "      }\n"
        "      // borrow a reference to the collection\n"
        "      let collectionRef = owner\n"
        "        .borrow<&aaaa.Collection>(from: /storage/ststst)!\n"
        "      // withdraw the NFT\n"
        "      self.transferToken <- collectionRef.withdraw(withdrawID: withdrawID)\n"
        "  }\n"
        "  execute {\n"
        "      // get the recipient's public account object\n"
        "      let recipient = getAccount(recipient)\n"
        "      // get receivers capability\n"
        "      let nonFungibleTokenCapability = recipient\n"
        "        .getCapability<&{NonFungibleToken.CollectionPublic}>(/public/publicPath)\n"
        "      // check the recipient has a NonFungibleToken public capability\n"
        "      if (!nonFungibleTokenCapability.check()) {\n"
        "        panic(\"Could not borrow a reference to the receiver's collection\")\n"
        "      }\n"
        "      // deposit nft to recipients collection\n"
        "      nonFungibleTokenCapability\n"
        "        .borrow()!\n"
        "        .deposit(token: <-self.transferToken)\n"
        "  }\n"
        "}\n";

    const char* expected1[8] = {"0x1d7e57aa55817448", "aaaa", "bbb", "ststst", "aaaa", "aaaa", "ststst", "publicPath"};
    assert_true(PARSE_NFT_TEST(parseNFT2, script1, sizeof(script1)-1, true, expected1, sizeof(expected1)/sizeof(*expected1),
                               SCRIPT_TYPE_NFT_TRANSFER));

    const char script2[] = 
        "import NonFungibleToken from 0x1d7e57aa55817448\n"
        "import aaaa from bbb\n"
        "transaction(recipient: Address, withdrawID: UInt64) {\n"
        "  // local variable for storing the transferred nft\n"
        "  let transferToken: @NonFungibleToken.NFT\n"
        "  prepare(owner: AuthAccount) {\n"
        "      // check if collection exists\n"
        "      if (owner.type(at: /storage/ststst) != Type<@aaaa.Collection>()) {\n"
        "        panic(\"Could not borrow a reference to the stored collection\")\n"
        "      }\n"
        "      // borrow a reference to the collection\n"
        "      let collectionRef = owner\n"
        "        .borrow<&aaaaa.Collection>(from: /storage/ststst)!\n"
        "      // withdraw the NFT\n"
        "      self.transferToken <- collectionRef.withdraw(withdrawID: withdrawID)\n"
        "  }\n"
        "  execute {\n"
        "      // get the recipient's public account object\n"
        "      let recipient = getAccount(recipient)\n"
        "      // get receivers capability\n"
        "      let nonFungibleTokenCapability = recipient\n"
        "        .getCapability<&{NonFungibleToken.CollectionPublic}>(/public/publicPath)\n"
        "      // check the recipient has a NonFungibleToken public capability\n"
        "      if (!nonFungibleTokenCapability.check()) {\n"
        "        panic(\"Could not borrow a reference to the receiver's collection\")\n"
        "      }\n"
        "      // deposit nft to recipients collection\n"
        "      nonFungibleTokenCapability\n"
        "        .borrow()!\n"
        "        .deposit(token: <-self.transferToken)\n"
        "  }\n"
        "}\n";

    assert_true(PARSE_NFT_TEST(parseNFT2, script2, sizeof(script2)-1, false, NULL, 0, SCRIPT_TYPE_UNKNOWN)); //contractName mismatch

    const char script3[] = 
        "import NonFungibleToken from 0x1d7e57aa55817448\n"
        "import aaaa from bbb\n"
        "transaction(recipient: Address, withdrawID: UInt64) {\n"
        "  // local variable for storing the transferred nft\n"
        "  let transferToken: @NonFungibleToken.NFT\n"
        "  prepare(owner: AuthAccount) {\n"
        "      // check if collection exists\n"
        "      if (owner.type(at: /storage/stst) != Type<@aaaa.Collection>()) {\n"
        "        panic(\"Could not borrow a reference to the stored collection\")\n"
        "      }\n"
        "      // borrow a reference to the collection\n"
        "      let collectionRef = owner\n"
        "        .borrow<&aaaa.Collection>(from: /storage/ststst)!\n"
        "      // withdraw the NFT\n"
        "      self.transferToken <- collectionRef.withdraw(withdrawID: withdrawID)\n"
        "  }\n"
        "  execute {\n"
        "      // get the recipient's public account object\n"
        "      let recipient = getAccount(recipient)\n"
        "      // get receivers capability\n"
        "      let nonFungibleTokenCapability = recipient\n"
        "        .getCapability<&{NonFungibleToken.CollectionPublic}>(/public/publicPath)\n"
        "      // check the recipient has a NonFungibleToken public capability\n"
        "      if (!nonFungibleTokenCapability.check()) {\n"
        "        panic(\"Could not borrow a reference to the receiver's collection\")\n"
        "      }\n"
        "      // deposit nft to recipients collection\n"
        "      nonFungibleTokenCapability\n"
        "        .borrow()!\n"
        "        .deposit(token: <-self.transferToken)\n"
        "  }\n"
        "}\n";

    assert_true(PARSE_NFT_TEST(parseNFT2, script3, sizeof(script3)-1, false, NULL, 0, SCRIPT_TYPE_UNKNOWN)); // storage mismatch
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_parseTest), cmocka_unit_test(test_parseTestNFT1), cmocka_unit_test(test_parseTestNFT2)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
