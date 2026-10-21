typedef struct Node Node;
typedef struct Patch Patch;
struct Node { Node *child; };
struct Patch { Node *value; Patch *next; };
extern Node *deep_copy(Node *source, int recursive);
extern void add_node(Node *root, Node *value);
extern void release_tree(Node *node);

static int mutate_tree(Node *root, Patch *patch)
{
    Node *copy = deep_copy(patch->value, 1);
    if (copy == NULL)
        return 1;
    add_node(root, copy);
    if (invalid_patch(patch)) {
        release_tree(copy);
        return 1;
    }
    return 0;
}

static int apply_all(Node *root, Patch *patches)
{
    Patch *current = patches->next;
    while (current != NULL) {
        mutate_tree(root, current);
        current = current->next;
    }
    return 0;
}
