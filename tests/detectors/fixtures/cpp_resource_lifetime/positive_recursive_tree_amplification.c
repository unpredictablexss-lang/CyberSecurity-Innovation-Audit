typedef struct Node Node;
typedef struct Patch Patch;
struct Node { Node *child; Node *next; };
struct Patch { Node *value; Patch *next; };

static void destroy_tree(Node *node)
{
    while (node != NULL) {
        Node *next = node->next;
        if (node->child != NULL)
            destroy_tree(node->child);
        free(node);
        node = next;
    }
}

static Node *deep_copy(Node *source, int recursive)
{
    return recursive ? clone_node(source) : NULL;
}

static void add_node(Node *root, Node *value)
{
    root->child = value;
}

static int mutate_tree(Node *root, Patch *patch)
{
    Node *copy = deep_copy(patch->value, 1);
    if (copy == NULL)
        return 1;
    add_node(root, copy);
    if (invalid_patch(patch)) {
        destroy_tree(copy);
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
