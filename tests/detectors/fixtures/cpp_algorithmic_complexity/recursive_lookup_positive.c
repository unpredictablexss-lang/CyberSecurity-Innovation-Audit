struct Branch { int key; struct Branch *next; struct Branch *left; struct Branch *right; };
struct Branch *seek(struct Branch *list, int key) {
    for (struct Branch *p = list; p; p = p->next) if (p->key == key) return p;
    return 0;
}
int compare(struct Branch *a, struct Branch *b) {
    if (!a || !b) return a == b;
    for (struct Branch *child = a->left; child; child = child->next) {
        struct Branch *match = seek(b->right, child->key);
        if (!match || !compare(child, match)) return 0;
    }
    return 1;
}
