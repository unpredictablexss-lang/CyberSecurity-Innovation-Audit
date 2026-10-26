struct Node { struct Node *child; struct Node *next; int value; };
struct Node *duplicate(struct Node *source) {
    if (!source) return 0;
    struct Node *copy = (struct Node *)malloc(sizeof(struct Node));
    copy->value = source->value;
    copy->child = duplicate(source->child);
    return copy;
}
void erase(struct Node *node) {
    if (!node) return;
    erase(node->child);
    free(node);
}
void apply_many(struct Node *root, struct Node **items, int count) {
    for (int i = 0; i < count; ++i) items[i] = duplicate(root);
}
