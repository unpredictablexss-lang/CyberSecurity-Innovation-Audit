typedef struct Node Node;
struct Node {
    Node *child;
};

static void destroy_tree(Node *root)
{
    while (root->child) {
        Node *part = root->child;
        root->child = part->child;
        destroy_tree(part);
        free(part);
    }
    free(root);
}
