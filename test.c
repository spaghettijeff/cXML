#include "cxml.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>


char *load_file(const char *filename) {
    char *buffer = NULL;
    size_t length;
    FILE *f = fopen(filename, "r");
    if (f) {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);
        buffer = malloc(sizeof(*buffer) * (length + 1));
        fread(buffer, 1, length, f);
        fclose(f);
    }
    buffer[length] = '\0';
    return buffer;
}

void test_xml_rw_1() {
    char *test = load_file("test_1.xml");
    xml_doc doc = cxml_parse_str(test);
    cxml_write_doc(doc, "test_1_out.xml");
    cxml_free_node(doc.root);
    free(test);
}

void test_str_sanatize() {
    char *test1_in = "________________";
    char *test1_out = cxml_str_sanitize(test1_in);
    assert(strcmp(test1_in, test1_out) == 0);
    free(test1_out);

    char *test2_in = "& test'str";
    char *test2_out = cxml_str_sanitize(test2_in);
    assert(strcmp("&amp; test&apos;str", test2_out) == 0);
    free(test2_out);
}

void test_str_desanitize() {
    char *test1_out = cxml_str_desanitize("&amp; test&apos;str");
    assert(strcmp("& test'str", test1_out));
}


int main() {
    test_xml_rw_1();
    test_str_sanatize();
    test_str_desanitize();
    return 1;
}
