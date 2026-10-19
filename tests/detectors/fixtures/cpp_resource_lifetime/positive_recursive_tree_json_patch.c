typedef struct Node Node;
typedef struct Patch Patch;
struct Node { Node *child; Node *next; };
struct Patch { Node *value; Patch *next; };
extern Node *deep_copy(Node *source, int recursive);
extern void add_node(Node *root, Node *value);
extern void release_tree(Node *node);

static void destroy_tree(Node *node)
{
    while (node != NULL) {
        if (node->child != NULL) destroy_tree(node->child);
        free(node);
        node = node->next;
    }
}

static int apply_patch(Node *root, Patch *patch, int root_path, int is_copy)
{
    Node *value = NULL;
    if (root_path) {
        value = deep_copy(patch->value, 1);
        if (value == NULL) goto cleanup;
        overwrite_root(root, value);
        value = NULL;
        goto cleanup;
    }
    if (is_copy) {
        value = deep_copy(patch->value, 1);
    } else {
        value = deep_copy(patch->value, 1);
    }
    if (value == NULL) goto cleanup;
    add_node(root, value);
    value = NULL;
cleanup:
    if (value != NULL) destroy_tree(value);
    return 0;
}

static int apply_patches(Node *root, Patch *patches)
{
    Patch *current = patches->next;
    while (current != NULL) {
        apply_patch(root, current, 0, 0);
        current = current->next;
    }
    return 0;
}
