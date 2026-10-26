struct Node { struct Node *child; int value; };
int recursive_only(struct Node *n) { return n ? recursive_only(n->child) : 0; }
void loops_only(struct Node *n) { for (int i = 0; i < n->value; ++i) for (int j = 0; j < i; ++j) n->value += j; }
