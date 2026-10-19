typedef struct Node Node;
struct Node { Node *child; Node *next; };

static void release_tree(Node *node)
{
    while (node != NULL) {
        Node *next = node->next;
        if (node->child != NULL)
            release_tree(node->child);
        free(node);
        node = next;
    }
}
