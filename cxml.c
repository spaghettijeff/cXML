#include "cxml.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Helper functions -----------------------------------------

// skip whitespace(lex) modifies lex by advancing the position
// pointer (lex->pos) past any combiniation of whitesace (space, tab, newline, return)
static void skip_whitespace(struct lexer *lex) {
    while(1) {
        switch (lex->working_char) {
            case ' ':
            case '\t':
            case '\n':
            case '\r':
                lex->working_char = *(++lex->pos);
                break;
            default :
                return;
        }
    }
}

// begins_with(str, sub_str) returns 1 if str begins with sub_str
// and 0 otherwixe
static int begins_with(const char *str, const char *sub_str) {
    while (*sub_str != '\0') {
        if (*sub_str != *str) {
            return 0;
        }
        sub_str++;
        str++;
    }
    return 1;
}


static struct xml_token token_create(enum token_type type, char *str) {
    struct xml_token new_token = {type, str};
    return new_token;
}


static void lexer_step(struct lexer *lex, unsigned int step) {
    lex->pos += step;
    lex->working_char = *(lex->pos);
}


// lexer state functions --------------------------------------------------

struct xml_token lex_state_root(struct lexer *lex);
struct xml_token lex_state_tag(struct lexer *lex);


// get_next_token(lex) returns the next token for lex->str and advances lex
struct xml_token get_next_token(struct lexer *lex) {
    skip_whitespace(lex);
    return (lex->state_func)(lex);
}

// lex_state_root(lex) internal function does lexing when inside the main body of an xml file.
// used for flow control and lexer state. Returns a token advances the lexer and may modify lexer state_func
struct xml_token lex_state_root(struct lexer *lex) {
    char *start;
    switch (lex->working_char) {
        case '\0':
            return token_create(eof, NULL);
            break;
        case '<':
            if (*(lex->pos + 1) == '/') {
                // tag_end
                lex->pos += 2;
                lex->working_char = *(lex->pos);
                skip_whitespace(lex);
                start = lex->pos;
                while (!(*(lex->pos + 1) == ' '  || *(lex->pos + 1) == '>')) {
                    lex->pos++;
                }
                lex->state_func = lex_state_tag;
                lex->working_char = *(++lex->pos);
                *lex->pos = '\0';
                return token_create(tag_end, start);
            }
            else if (begins_with(lex->pos + 1, "?xml")) {
                lex->pos += 5;
                start = lex->pos;
                while (!begins_with(lex->pos, "?>")) {
                    lex->pos++;
                }
                *lex->pos = '\0';
                lex->pos += 2;
                lex->working_char = *lex->pos;
                return token_create(xml_decl, start);
            }
            else if (begins_with(lex->pos + 1, "!--")) {
                // comments
                lex->pos += 4;
                while (!begins_with(lex->pos, "-->")) {
                    lex->pos++;
                }
                lex->pos += 3;
                lex->working_char = *(lex->pos);
                return token_create(comment, NULL);
            }
            else if (begins_with(lex->pos + 1, "![CDATA[")) {
                lex->pos += 9;
                start = lex->pos;
                while (!begins_with(lex->pos + 1, "]]>")) {
                    lex->pos++;
                }
                *(lex->pos + 1) = '\0';
                lex->pos += 4;
                lex->working_char = *(lex->pos);
                return token_create(cdata, start);
            }
            else {
                // tag_open
                lex->working_char = *(++lex->pos);
                skip_whitespace(lex);
                start = lex->pos;
                while (!(*(lex->pos + 1) == ' '  || *(lex->pos + 1) == '>' || *(lex->pos + 1) == '/')) {
                    lex->pos++;
                }
                lex->state_func = lex_state_tag;
                lex->working_char = *(++lex->pos);
                *(lex->pos) = '\0';
                return token_create(tag_open, start);
            }
            break;
        default:
            // text
            skip_whitespace(lex);
            start = lex->pos;
            while (*(lex->pos + 1) != '<') {
                lex->pos++;
            }
            lex->working_char = *(++lex->pos);
            *(lex->pos) = '\0';
            return token_create(text, start);
    } 
}

// lex_state_tag(lex) internal function does lexing when inside the tags of an xml file.
// used for flow control and lexer state. emits a token, advances the lexer and may modifes lexer state_func
struct xml_token lex_state_tag(struct lexer *lex) {
    char *start;
    switch (lex->working_char) {
        case '\0':
            return token_create(eof, NULL);
        case '>':
            // tag_close
            lex->working_char = *(++lex->pos);
            lex->state_func = lex_state_root;
            return token_create(tag_close, NULL);
        case '/':
            if (*(lex->pos + 1) == '>') {
            // tag_colse_end
                lex->pos += 2;
                lex->working_char = *(lex->pos);
                lex->state_func = lex_state_root;
                return token_create(tag_close_end, NULL);
            }
            else {
                lex->working_char = *(++lex->pos);
                return token_create(error, "unexpected '/' within tag");
            }
        case '=':
            lex->working_char = *(++lex->pos);
            return token_create(equal, NULL);
        case '"':
            start = lex->pos + 1;
            while (*(lex->pos + 1) != '"') {
                lex->pos++;
            }
            lex->pos += 2;
            lex->working_char = *(lex->pos);
            *(lex->pos - 1) = '\0';
            return token_create(attr_val, start);
        case '\'':
            start = lex->pos + 1;
            while (*(lex->pos + 1) != '\'') {
                lex->pos++;
            }
            lex->pos += 2;
            lex->working_char = *(lex->pos);
            *(lex->pos - 1) = '\0';
            return token_create(attr_val, start);
        default:
            start = lex->pos;
            while (1) {
                switch (*(lex->pos + 1)) {
                    case ' ':
                    case '/':
                    case '>':
                    case '=':
                    case '"':
                        lex->working_char = *(++lex->pos);
                        *(lex->pos) = '\0';
                        return token_create(attr_name, start);
                    default:
                        lex->pos++;
                }
            }
    }
}


// HEADER FILE DEFINITIONS -------------------------------------------------

void print_token(const struct xml_token *t) {
    char *str_lit;
    switch (t->type) {
        case (tag_open):
            str_lit = "token(tag_open: %s)\n";
            break;
        case (tag_close):
            str_lit = "token(tag_close: NULL)\n";
            break;
        case (tag_end):
            str_lit = "token(tag_end: %s)\n";
            break;
        case (tag_close_end):
            str_lit = "token(tag_close_end: NULL)\n";
            break;
        case (attr_name):
            str_lit = "token(attr_name: %s)\n";
            break;
        case (attr_val):
            str_lit = "token(attr_val: %s)\n";
            break;
        case (equal):
            str_lit = "token(equal: NULL)\n";
            break;
        case (cdata):
            str_lit = "token(cdata: %s)\n";
            break;
        case (text):
            str_lit = "token(text: %s)\n";
            break;
        case (eof):
            str_lit = "token(eof: NULL)\n";
            break;
        case (error):
            str_lit = "token(error: %s)\n";
            break;
        default:
            str_lit = "token(unrecognized)\n";
            break;
    }
    printf(str_lit, t->str);
}


struct lexer lexer_init(char *str) {
    struct lexer new_lex = {.str=str, .pos=str, .state_func=lex_state_root, .working_char=*str};
    return new_lex;
}


// Parsing DOM tree ---------------------------------------------------------



struct xml_parser {
    xml_doc doc;
    xml_t working_node;
    const char *attr_name;
    void (*parser_state_func) (struct xml_parser*, struct xml_token);
};


static void parser_state_init(struct xml_parser* parser, struct xml_token token);
static void parser_state_root(struct xml_parser* parser, struct xml_token token);
static void parser_state_tag_open(struct xml_parser* parser, struct xml_token token);
static void parser_state_attr_name(struct xml_parser* parser, struct xml_token token);
static void parser_state_assign(struct xml_parser* parser, struct xml_token token);
static void parser_state_tag_end(struct xml_parser* parser, struct xml_token token);


xml_doc cxml_parse_str(char *str) {
    struct lexer l = lexer_init(str);
    struct xml_parser p = { {NULL, NULL, NULL, NULL}, NULL, NULL, parser_state_init};
    struct xml_token token = get_next_token(&l);
    while (p.parser_state_func) {
        p.parser_state_func(&p, token);
        token = get_next_token(&l);
    }
    return p.doc;
}


static void parser_state_init(struct xml_parser* parser, struct xml_token token) {
    if (parser->doc.root) {
        printf("Parser error: looking for document root when DOM root is already initialized\n");
        parser->parser_state_func = NULL;
        cxml_free_node(parser->doc.root);
        parser->doc.root=NULL;
        return;
    }
    switch (token.type) {
        case xml_decl:
            parser->doc.encoding = token.str;
            break;
        case tag_open:
            parser->doc.root = cxml_node_new(token.str);
            parser->working_node = parser->doc.root;
            parser->parser_state_func = parser_state_tag_open;
            break;
        case comment:
            break;
        default:
            printf("Parser error: XML document root node not found\n");
            parser->parser_state_func = NULL;
            cxml_free_node(parser->doc.root);
            parser->doc.root=NULL;
            break;
    }
}


static void parser_state_root(struct xml_parser* parser, struct xml_token token) {
    xml_t new_node;
    switch (token.type) {
        case tag_open:
            new_node = cxml_node_new(token.str);
            cxml_insert(parser->working_node, new_node);
            parser->working_node = new_node;
            parser->parser_state_func = parser_state_tag_open;
            break;
        case cdata:
        case text:
            parser->working_node->text = token.str;
            break;
        case tag_end:
            if (strcmp(token.str, parser->working_node->title) == 0) {
                parser->working_node = parser->working_node->parent;
                parser->parser_state_func = parser_state_tag_end;
            }
            else {
                printf("Parser error: mismatched open and end tags\n");
                parser->parser_state_func = NULL;
                cxml_free_node(parser->doc.root);
                parser->doc.root=NULL;
            }
            break;
        case eof:
            parser->parser_state_func = NULL;
            break;
        case comment:
            break;
        default:
            parser->parser_state_func = NULL;
            break;
    }
}


static void parser_state_tag_open(struct xml_parser* parser, struct xml_token token) {
    switch (token.type) {
        case tag_close:
            parser->parser_state_func = parser_state_root;
            break;
        case tag_close_end:
            parser->working_node = parser->working_node->parent;
            parser->parser_state_func = parser_state_root;
            break;
        case attr_name:
            parser->parser_state_func = parser_state_attr_name;
            parser->attr_name = token.str;
            break;
        case comment:
            return;
            break;
        case eof:
            parser->parser_state_func = NULL;
            return;
            break;
        default:
            parser->parser_state_func = NULL;
            cxml_free_node(parser->doc.root);
            parser->doc.root=NULL;
            return;
            break;
    }
}


static void parser_state_attr_name(struct xml_parser* parser, struct xml_token token) {
    switch (token.type) {
        case equal:
            parser->parser_state_func = parser_state_assign;
            return;
        case comment:
            return;
            break;
        case eof:
            parser->parser_state_func = NULL;
            return;
            break;
        default:
            parser->parser_state_func = NULL;
            cxml_free_node(parser->doc.root);
            parser->doc.root=NULL;
            return;
            break;
    }
}


static void parser_state_assign(struct xml_parser* parser, struct xml_token token) {
    switch (token.type) {
        case attr_val:
            cxml_set_attr(parser->working_node, parser->attr_name, token.str);
            parser->parser_state_func = parser_state_tag_open;
            return;
        case comment:
            return;
            break;
        case eof:
            parser->parser_state_func = NULL;
            return;
            break;
        default:
            parser->parser_state_func = NULL;
            cxml_free_node(parser->doc.root);
            parser->doc.root=NULL;
            return;
            break;
    }
}


static void parser_state_tag_end(struct xml_parser* parser, struct xml_token token) {
    switch (token.type) {
        case tag_close:
            parser->parser_state_func = parser_state_root;
            break;
        default:
            printf("Parser error: missing closing brace of end tag\n");
            parser->parser_state_func = NULL;
            cxml_free_node(parser->doc.root);
            parser->doc.root=NULL;
    }
}

// DOM tree interface functions -------------------------------------------------------

xml_t cxml_node_new(const char *title) {
    xml_t new_node = malloc(sizeof (*new_node));
    new_node->title = title;
    new_node->text = NULL;
    new_node->attrs = NULL;
    new_node->attr_count = 0;
    new_node->attr_buf_size = 0;
    new_node->children = NULL;
    new_node->children_count = 0;
    new_node->children_buf_size = 0;
    new_node->sibling = NULL;
    new_node->parent = NULL;
    return new_node;
}

void cxml_free_node(xml_t node) {
    for (unsigned int i = 0; i < node->children_count; i++) {
        xml_t next_node = node->children[i];
        while (next_node) {
            xml_t swap = next_node->sibling;
            cxml_free_node(next_node);
            next_node = swap;
        }
    }
    free(node->attrs);
    free(node->children);
    free(node);
}


xml_t cxml_find_child(xml_t node, const char *child_title) {
    if (!node || !child_title) {
        return NULL;
    }
    for (size_t i = 0; i < node->children_count; i++) {
        if (strcmp(node->children[i]->title, child_title) == 0) {
            return node->children[i];
        }
    }
    return NULL;
}


const char *cxml_get_attribute_value(xml_t node, const char *attr_name) {
    if (attr_name) {
        for (unsigned int i=0; i < node->attr_count; i++) {
            if (strcmp(node->attrs[i*2], attr_name) == 0) {
                return node->attrs[(i*2) + 1];
            }
        }
    }
    return NULL;
}


int cxml_set_attr(xml_t node, const char *attr_name, const char *attr_val) {
    if (!node || !attr_name || !attr_val) {
        return 1;
    }
    for (unsigned int i = 0; i < node->attr_count; i++) {
        if (strcmp(node->attrs[i*2], attr_name) == 0) {
            node->attrs[(i*2) + 1] = attr_val;
            return 0;
        }
    }
    if (node->attr_buf_size <= node->attr_count) {
        node->attr_buf_size += 8;
        node->attrs = realloc(node->attrs, sizeof(char*) * node->attr_buf_size * 2);
    }
    node->attrs[node->attr_count * 2] = attr_name;
    node->attrs[(node->attr_count * 2) + 1] = attr_val;
    node->attr_count++;
    return 0;
}

int cxml_insert(xml_t parent, xml_t child) {
    if ((!parent) || (!child)) {
        return 1;
    }
    child->parent = parent;
    xml_t sib = cxml_find_child(parent, child->title);
    if (sib) {
        while (sib->sibling) {
            sib = sib->sibling;
        }
        sib->sibling = child;
    }
    else {
        if (parent->children_buf_size <= parent->children_count) {
            parent->children_buf_size += 8;
            parent->children = realloc(parent->children, sizeof(xml_t) * parent->children_buf_size);
        }
        parent->children[parent->children_count] = child;
        parent->children_count++;
    }
    return 0;
}


static void cxml_write_dom(xml_t root, FILE *f, unsigned int depth) {
    for (unsigned int i=0; i < depth; i++) fprintf(f, "\t");
    fprintf(f, "<%s", root->title);
    for (unsigned int i=0; i < root->attr_count; i++) {
        fprintf(f, " %s = \"%s\"", root->attrs[2*i], root->attrs[(2*i)+1]);
    }
    fprintf(f, ">");
    if (root->text) {
        fprintf(f, "%s", root->text);
    }

    //print children
    for (unsigned int i = 0; i < root->children_count; i++) {
        xml_t child = root->children[i];
        while (child) {
            fprintf(f, "\n");
            cxml_write_dom(child, f, depth + 1);
            child = child->sibling;
        }
    }
    if (root->children_count) {
        fprintf(f, "\n");
        for (unsigned int i=0; i < depth; i++) fprintf(f, "\t");
    }
    fprintf(f, "</%s>", root->title);
}

int cxml_write_doc(xml_doc doc, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        return 0;
    }
    if (doc.encoding) {
        fprintf(f, "<?xml%s?>\n", doc.encoding);
    }
    cxml_write_dom(doc.root, f, 0);
    fclose(f);
    return 1;
}


char *cxml_str_sanitize(const char *str) {
    size_t buf_size = 0;
    size_t str_len = 0;
    char *new_str = NULL;
    while (*str != '\0') {
        const char *str_lit = NULL;
        switch (*str) {
            case '"':
                str_lit = "&quot;";
                break;
            case '\'':
                str_lit = "&apos;";
                break;
            case '<':
                str_lit = "&lt;";
                break;
            case '>':
                str_lit = "&gt;";
                break;
            case '&':
                str_lit = "&amp;";
                break;
            default:
                if (buf_size <= str_len + 1) {
                    buf_size += 16;
                    new_str = realloc(new_str, buf_size);
                }
                *(new_str + str_len) = *str;
                str_len++;
                str++;
                continue;
        }
        if (buf_size <= str_len + strlen(str_lit) + 1) {
            buf_size += 16;
            new_str = realloc(new_str, buf_size);
        }
        strcpy(new_str + str_len, str_lit);
        str_len += strlen(str_lit);
        str++;
    }
    *(new_str + str_len) = '\0';
    return new_str;
}

char *cxml_str_desanitize(const char *str) {
    size_t buf_size = 0;
    size_t str_len = 0;
    char *new_str = NULL;
    char sub = '\0';
    while (*str != '\0') {
        if (buf_size <= str_len + 1) {
            buf_size +=16;
            new_str = realloc(new_str, sizeof(char) * str_len);
        }
        switch (*str) {
            case '&':
                if (begins_with(str, "&quot;")) {
                    sub = '"';
                    str += strlen("&quot;");
                }
                else if (begins_with(str, "&apos;")) {
                    sub = '\'';
                    str += strlen("&apos;");
                }
                else if (begins_with(str, "&lt;")) {
                    sub = '<';
                    str += strlen("&lt;");
                }
                else if (begins_with(str, "&gt;")) {
                    sub = '>';
                    str += strlen("&gt;");
                }
                else if (begins_with(str, "&amp;")) {
                    sub = '&';
                    str += strlen("&amp;");
                }
                else {
                    sub = *str;
                    str++;
                }
                *(new_str + str_len) = sub;
                str_len++;
                break;
            default:
                *(new_str + str_len) = *str;
                str++;
                str_len++;
                break;
        }
    }
    return new_str;
}
