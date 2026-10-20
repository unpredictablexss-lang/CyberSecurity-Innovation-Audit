typedef struct Node Node;
struct Node {
    Node *child;
    void (*callback)(void *);
    void *arg;
};

static void destroy_tree(Node *root);

static void destroy_child(void *arg)
{
    destroy_tree((Node *)arg);
}

static void cleanup_part(Node *part)
{
    if (part->callback)
        part->callback(part->arg);
    free(part);
}

static void destroy_tree(Node *root)
{
    while (root->child) {
        Node *part = root->child;
        root->child = part->child;
        part->callback = NULL;
        cleanup_part(part);
    }
    free(root);
}

static void attach_owned_child(Node *part, Node *child)
{
    part->callback = destroy_child;
    part->arg = child;
}
