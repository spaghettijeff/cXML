#ifndef CXML_H
#define CXML_H

#include <stdlib.h>

struct xml_node {
    const char *title;
    const char *text;
    const char **attrs;             // array of strings stored {attr_name, attr_val, ...}
    size_t attr_count;
    size_t attr_buf_size;
    struct xml_node **children;     // array to pointers of children with unique titles
    size_t children_count;
    size_t children_buf_size;
    struct xml_node *sibling;       // pointer to next node with same title
    struct xml_node *parent;
};
typedef struct xml_node* xml_t;

typedef struct {
    const char *version;
    const char *encoding;
    const char *standalone;
    xml_t root;
} xml_doc;


enum token_type {
    tag_open,       // <tag
    tag_close,      // </tag
    tag_end,        // >
    xml_decl,       // <?xml ... ?>
    tag_close_end,  // />
    attr_name,      // name
    attr_val,       // "value"
    equal,          // =
    cdata,          // <![CDATA[ text ]]>
    text,        // text
    comment,        // <!-- comment -->
    eof,            // \0
    error           //
};


struct xml_token {
    enum token_type type;
    const char *str;
};

struct lexer;

struct lexer {
    char *str;
    char *pos;
    struct xml_token (*state_func) (struct lexer*);
    char working_char;
};


struct lexer lexer_init(char *str);

struct xml_token lexer_next_token(struct lexer *lex);

void print_token(const struct xml_token *t);

xml_doc cxml_parse_str(char *str);

// DOM tree interface functions -------------------------------------------------------

// cxml_create_node(title) creates an empty node with title.
// the new node must be freed with cxml_free_node(node)
xml_t cxml_node_new(const char *title);

// cxml_free_node(node) frees memory of node, and all it's children
void cxml_free_node(xml_t node);

// cxml_get_attribute_value(node, attr_name) returns the value associated with attr_name, NULL if no attr_name exists
const char *cxml_get_attr(xml_t node, const char *attr_name);

// cxml_set_attribute(node, attr_name, attr_value) adds the attrivte name, value pair to node
int cxml_set_attr(xml_t node, const char *attr_name, const char *attr_val);

// cxml_find_chid(node, child_title) returns the child of node with title child title. NULL if no child exists
xml_t cxml_child(xml_t node, const char *child_title);

// cxml_insert_child(parent, child) adds child as a child to parent
int cxml_insert(xml_t parent, xml_t child);

// cxml_print_doc(doc) prints doc as xml to stdout
int cxml_write_doc(xml_doc doc, const char *filename);

//cxml_str_sanatize(str) returns a copy of str where special characters are escaped
char* cxml_str_sanitize(const char *str);

// cxml_str_desanitize(str) returns a copy of str where escaped characteres are unescaped
char* cxml_str_desanitize(const char *str);


#endif
