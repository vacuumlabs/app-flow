#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "rlp.h"

struct RLPValueTestCase {
    const char *data;
    parser_error_t expectedError;
    uint8_t expectedKind;
    uint64_t expectedLen;
    uint64_t expectedDataOffset;
    uint64_t expectedConsumed;
};

struct RLPValueTestCase testCases[] = { 
    {"00", PARSER_OK, RLP_KIND_STRING, 1, 0, 1}, // Byte string (00)
    {"01", PARSER_OK, RLP_KIND_STRING, 1, 0, 1}, // Byte string (01)
    {"7F", PARSER_OK, RLP_KIND_STRING, 1, 0, 1}, // Byte string (7F)

    {"80", PARSER_OK, RLP_KIND_STRING, 0, 1, 1},       // Empty string ("")
    {"83646F67", PARSER_OK, RLP_KIND_STRING, 3, 1, 4}, // Short string ("dog")

    {"B7"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000",
        PARSER_OK, RLP_KIND_STRING, 55, 1, 56},
    {"B90400"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000",
        PARSER_OK, RLP_KIND_STRING, 1024, 3, 1027},
    {"C0", PARSER_OK, RLP_KIND_LIST, 0, 1, 1},
    {"C80000000000000000", PARSER_OK, RLP_KIND_LIST, 8, 1, 9},
    {"F7"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000",
        PARSER_OK, RLP_KIND_LIST, 55, 1, 56},
    {"F90400"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000",
        PARSER_OK, RLP_KIND_LIST, 1024, 3, 1027},
    // Varios invalid RLP data examples
    {"", PARSER_UNEXPECTED_BUFFER_END, RLP_KIND_UNKNOWN, 0, 0, 0},

    {"BB", PARSER_UNEXPECTED_BUFFER_END, RLP_KIND_STRING, 0, 0, 0},

    {"B800", PARSER_OK, RLP_KIND_STRING, 0, 2, 2},

    {"B900", PARSER_UNEXPECTED_BUFFER_END, RLP_KIND_STRING, 0, 0, 0},
    {"B90000", PARSER_OK, RLP_KIND_STRING, 0, 3, 3},
    {"B9000100", PARSER_OK, RLP_KIND_STRING, 1, 3, 4},

    {"BA000000", PARSER_RLP_ERROR_INVALID_VALUE_LEN, RLP_KIND_STRING, 0, 0, 0},
    {"BB01000000", PARSER_RLP_ERROR_INVALID_VALUE_LEN, RLP_KIND_STRING, 0, 0, 0}
};

static void test_rlp(void **state) {
    (void) state;

    const size_t numberOfTests = (sizeof(testCases) / sizeof(*testCases));
    for(int i=0; i<numberOfTests; i++) {
        struct RLPValueTestCase *testCase = &(testCases[i]);

        uint8_t data[2000];
        const size_t dataSize = parseHexString(data, sizeof(data), testCase->data);
        parser_context_t ctx_in;
        parser_context_t ctx_out;

        ctx_in.buffer = data;
        ctx_in.bufferLen = dataSize;
        ctx_in.offset = 0;

        rlp_kind_e kind;
        uint32_t bytesConsumed;

        parser_error_t err = rlp_decode(&ctx_in, &ctx_out, &kind, &bytesConsumed);

        assert_int_equal(err, testCase->expectedError);
        assert_int_equal(kind, testCase->expectedKind);
        assert_int_equal(ctx_out.bufferLen, testCase->expectedLen);
        assert_int_equal(ctx_out.buffer - ctx_in.buffer, testCase->expectedDataOffset);
        assert_int_equal(bytesConsumed, testCase->expectedConsumed);
    }
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_rlp)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
