struct Node { struct Node *child; int value; };
struct Node *bounded_copy(struct Node *source, unsigned depth) {
    if (!source || depth >= 24) return 0;
    struct Node *copy = (struct Node *)malloc(sizeof(struct Node));
    copy->value = source->value;
    copy->child = bounded_copy(source->child, depth + 1);
    return copy;
}
void erase_iteratively(struct Node *node) {
    while (node) { struct Node *next = node->child; free(node); node = next; }
}
void build_one(struct Node *root) { struct Node *result = bounded_copy(root, 0); erase_iteratively(result); }
