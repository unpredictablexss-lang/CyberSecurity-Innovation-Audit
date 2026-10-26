struct Node { struct Node *child; int value; };
struct Node *seek_indexed(struct Node **index, int key) { return index[key]; }
int compare_indexed(struct Node *a, struct Node *b, struct Node **index) {
    if (!a || !b) return a == b;
    for (struct Node *p = a->child; p; p = p->child) {
        struct Node *match = seek_indexed(index, p->value);
        if (!match || !compare_indexed(p, match, index)) return 0;
    }
    return 1;
}
void visit(struct Node *node) { if (node) visit(node->child); }
