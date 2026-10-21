typedef struct Node Node;
struct Node { Node *child; Node *next; };

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

static void consume_without_copy(Node *root, Node *input)
{
    if (input != NULL)
        root->child = input;
}
